import asyncio
import threading
import inspect
import requests
from PySide6.QtCore import QThread, Signal
import websockets
import json
import re
from app.client_api import api, _small_response_json, validate_server_url
from app.delivery import SYNC_PAGE_SIZE, bounded_json_response


MAX_PENDING_WS_EVENTS = 16
MAX_PENDING_WS_SENDS = 32
MAX_OUTGOING_WS_BYTES = 128 * 1024
_SAFE_ENTITY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _bounded_or_mock_json(response, limit: int = 2 * 1024 * 1024):
    if hasattr(response, "iter_content"):
        return _small_response_json(response, limit)
    return response.json()


def _close_response(response) -> None:
    close_fn = getattr(response, "close", None)
    if callable(close_fn):
        close_fn()

# ============================================================
# AUTH WORKERS
# ============================================================

class HistoryPageWorker(QThread):
    """One cancellable history scan.

    Callers retain the worker until its native finished signal and must reject
    stale account/chat/revision results before displaying or marking read.
    """
    def __init__(self, owner, chat, offset=0, page_size=25, query=None, *, load_fn=None):
        super().__init__()
        self.owner, self.chat = owner, chat
        self.offset, self.page_size, self.query = offset, page_size, query
        self._cancelled = threading.Event()
        self._load_fn = load_fn
        self.result = None

    def cancel(self):
        self._cancelled.set()

    def run(self):
        from app.history_paging import HistoryCancelled, check_cancel
        try:
            check_cancel(self._cancelled.is_set)
            if self._load_fn is None:
                from app.secure_storage import storage
                load = storage.load_history_page
            else:
                load = self._load_fn
            page = load(self.owner, self.chat, self.offset, page_size=self.page_size,
                        query=self.query, cancel=self._cancelled.is_set)
            check_cancel(self._cancelled.is_set)
            self.result = ("ok", page)
        except HistoryCancelled:
            self.result = ("cancelled", None)
        except Exception as exc:
            # Avoid retaining exceptions/tracebacks that may reference plaintext.
            self.result = ("error", type(exc).__name__)


class RegisterWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, payload: dict):
        super().__init__()
        self.server_url = server_url
        self.payload = payload

    def run(self):
        success, response_data = api.register(self.server_url, self.payload)
        self.finished.emit(success, response_data)


class LoginWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, payload: dict):
        super().__init__()
        self.server_url = server_url
        self.payload = payload

    def run(self):
        success, response_data = api.login(self.server_url, self.payload)
        self.finished.emit(success, response_data)


class FindUserWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, target_username: str):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.target_username = target_username

    def run(self):
        try:
            success, data = api.find_user(self.server_url, self.token, self.target_username)
        finally:
            self.token = ""
        self.finished.emit(success, data)


class ListOwnDevicesWorker(QThread):
    finished = Signal(bool, object)

    def __init__(
        self,
        server_url: str,
        token: str,
        expected_device_id: str = None,
        expected_public_key: str = None,
    ):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.expected_device_id = expected_device_id
        self.expected_public_key = expected_public_key
        self.account_context = None

    def run(self):
        try:
            success, data = api.list_own_devices(
                self.server_url,
                self.token,
                expected_device_id=self.expected_device_id,
                expected_public_key=self.expected_public_key,
            )
        except Exception as exc:
            success, data = False, f"Ошибка загрузки устройств: {type(exc).__name__}"
        finally:
            self.token = ""
        self.finished.emit(success, data)


class RevokeDeviceWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, target_device_id: str):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.target_device_id = target_device_id
        self.account_context = None

    def run(self):
        try:
            success, data = api.revoke_own_device(
                self.server_url, self.token, self.target_device_id
            )
        except Exception as exc:
            success, data = False, f"Ошибка отзыва устройства: {type(exc).__name__}"
        finally:
            self.token = ""
        self.finished.emit(success, data)


class ChangePasswordWorker(QThread):
    finished = Signal(bool, object)

    def __init__(
        self,
        server_url: str,
        token: str,
        current_password: str,
        new_password: str,
        revoke_other_devices: bool = False,
    ):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.current_password = current_password
        self.new_password = new_password
        self.revoke_other_devices = bool(revoke_other_devices)
        self.account_context = None

    def run(self):
        try:
            success, data = api.change_password(
                self.server_url,
                self.token,
                self.current_password,
                self.new_password,
                revoke_other_devices=self.revoke_other_devices,
            )
        except Exception as exc:
            success, data = False, f"Ошибка смены пароля: {type(exc).__name__}"
        finally:
            self.token = ""
            self.current_password = ""
            self.new_password = ""
        self.finished.emit(success, data)


class CancelUploadReservationWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, file_id: str):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.file_id = file_id

    def run(self):
        try:
            success, data = api.cancel_upload_reservation(
                self.server_url, self.token, self.file_id
            )
        except Exception as exc:
            success, data = False, f"Ошибка отмены брони: {type(exc).__name__}"
        finally:
            self.token = ""
        self.finished.emit(success, data)


class LogoutSessionWorker(QThread):
    finished = Signal(bool, object)

    def __init__(
        self,
        server_url: str,
        token: str,
        *,
        include_other_devices: bool = False,
        only_other_devices: bool = False,
    ):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.include_other_devices = bool(include_other_devices)
        self.only_other_devices = bool(only_other_devices)
        self.account_context = None

    def run(self):
        try:
            success, data = api.logout(
                self.server_url,
                self.token,
                include_other_devices=self.include_other_devices,
                only_other_devices=self.only_other_devices,
            )
        except Exception as exc:
            success, data = False, f"Ошибка завершения сессии: {type(exc).__name__}"
        finally:
            self.token = ""
        self.finished.emit(success, data)


class SendMessageWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, payload: dict):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.payload = payload

    def run(self):
        try:
            success, data = api.send_message(self.server_url, self.token, self.payload)
        except Exception as exc:
            success, data = False, f"Ошибка отправки: {type(exc).__name__}"
        finally:
            self.token = ""
        self.finished.emit(success, data)


class ReliableSendWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, payload: dict):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.payload = payload
        self.expected_sender_device_id = None

    def run(self):
        try:
            if not self.expected_sender_device_id:
                raise ValueError("Missing sender device identity")
            success, data = api.send_reliable_message(self.server_url, self.token, self.payload,
                                                      self.expected_sender_device_id)
        except Exception as exc:
            success, data = False, f"Ошибка обработки ответа: {type(exc).__name__}"
        finally:
            self.token = ""
        self.finished.emit(success, data)


class UploadFileWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, file_data: bytes):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.file_data = file_data

    def run(self):
        try:
            success, data = api.upload_file(self.server_url, self.token, self.file_data)
        finally:
            self.token = ""
        self.finished.emit(success, data)


class ReliableUploadFileWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url, token, file_id, path, size=None, checksum=None, file_key=None):
        super().__init__()
        self.server_url, self.token, self.file_id, self.path = server_url, token, file_id, path
        self.size, self.checksum, self.file_key = size, checksum, file_key

    def run(self):
        try:
            from app.attachment_outbox import authenticated_snapshot, MAX_AUTHENTICATED_UPLOAD_BYTES
            import nacl.exceptions
            if type(self.size) is int and self.size > MAX_AUTHENTICATED_UPLOAD_BYTES:
                success, data = False, "ATTACHMENT_TOO_LARGE"
            else:
                try:
                    snapshot = authenticated_snapshot(self.path, self.size, self.checksum, self.file_key)
                except (ValueError, OSError, nacl.exceptions.CryptoError):
                    success, data = False, "ATTACHMENT_INVALID"
                else:
                    success, data = api.upload_file_reliable(self.server_url, self.token, self.file_id, snapshot)
        except Exception as exc:
            success, data = False, f"Ошибка загрузки: {type(exc).__name__}"
        finally:
            self.token = ""
            self.file_key = None  # Drop the reference; Python cannot guarantee secure erasure.
        self.finished.emit(success, data)


class GrantFileAccessWorker(QThread):
    """Asynchronously grant a specific device access to an uploaded file."""
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, file_id: str, recipient_device_id: str):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.file_id = file_id
        self.recipient_device_id = recipient_device_id

    def run(self):
        try:
            success, data = api.grant_file_access(
                self.server_url, self.token,
                self.file_id, self.recipient_device_id
            )
        except Exception as exc:
            success, data = False, f"Ошибка выдачи доступа: {type(exc).__name__}"
        finally:
            self.token = ""
        self.finished.emit(success, data)


class DownloadFileWorker(QThread):
    def __init__(self, server_url: str, token: str, file_id: str):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.file_id = file_id

    def run(self):
        try:
            self.result = api.download_file(self.server_url, self.token, self.file_id)
        except Exception:
            self.result = (False, b"")
        finally:
            self.token = ""


# ============================================================
# WEBSOCKET WORKER
# ============================================================

class WebSocketWorker(QThread):
    new_message_received  = Signal(dict)
    ws_error              = Signal(str)
    connection_status     = Signal(str)

    # ── Групповые события ───────────────────────────────────
    group_message_received = Signal(dict)
    group_created_received = Signal(dict)
    group_invited_received = Signal(dict)
    group_member_joined    = Signal(dict)
    group_member_left      = Signal(dict)
    group_deleted_received = Signal(dict)
    group_sender_key_updated = Signal(dict)

    # ── WebRTC сигналинг ────────────────────────────────────────────
    webrtc_signal_received = Signal(dict)   # зашифрованный E2EE сигнал
    call_offer_received    = Signal(dict)   # входящий вызов
    call_accept_received   = Signal(dict)   # собеседник принял
    call_ended_received    = Signal(dict)   # звонок завершён
    group_voice_state_received  = Signal(dict)  # участники голосовой комнаты группы
    group_voice_signal_received = Signal(dict)  # E2EE SDP/ICE внутри голосовой комнаты

    # Legacy screen relay is disabled; signals retained for UI compatibility.
    screen_frame_received  = Signal(dict)   # входящий кадр демки
    screen_control_received = Signal(dict)  # start/stop демки от пира

    def __init__(self, server_url: str, token: str, device_id: str):
        super().__init__()
        url_ok, url_err = validate_server_url(server_url)
        if not url_ok:
            raise ValueError(url_err)
        if not isinstance(device_id, str) or not _SAFE_ENTITY_ID_RE.fullmatch(device_id):
            raise ValueError("Invalid WebSocket device_id")
        self.device_id = device_id
        base_ws = server_url.rstrip("/").replace("http://", "ws://", 1).replace("https://", "wss://", 1)
        self.ws_url = f"{base_ws}/messages/ws/{device_id}"
        self._token = token
        self._is_running = True
        self._ws = None          # ссылка на активный websocket
        self._loop = None        # ссылка на event loop
        self._connect_task = None
        self._event_slots = threading.BoundedSemaphore(MAX_PENDING_WS_EVENTS)
        self._send_slots = threading.BoundedSemaphore(MAX_PENDING_WS_SENDS)

    # ── Отправка сообщения через WS (thread-safe) ───────────
    def send_signal(self, payload: dict):
        if not isinstance(payload, dict) or payload.get("type") in {"screen_frame", "screen_control"}:
            return False
        loop, ws = self._loop, self._ws
        if not loop or not ws or not loop.is_running():
            return False
        try:
            serialized = json.dumps(payload, separators=(",", ":"))
        except (TypeError, ValueError, RecursionError):
            return False
        if len(serialized.encode("utf-8")) > MAX_OUTGOING_WS_BYTES or not self._send_slots.acquire(blocking=False):
            return False
        coroutine = self._send_raw(ws, serialized)
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, loop)
        except RuntimeError:
            coroutine.close()
            self._send_slots.release()
            return False
        future.add_done_callback(lambda _: self._send_slots.release())
        return True  # Scheduled, not a delivery acknowledgement.

    async def _send_raw(self, ws, serialized):
        try:
            # A signal prepared for a previous connection must not be sent on
            # a replacement socket after reconnect.
            if self._ws is ws:
                await ws.send(serialized)
        except Exception as e:
            print(f"[WS] Ошибка отправки: {type(e).__name__}")

    def release_event(self):
        """Called exactly once by the GUI after handling a queued WS event."""
        self._event_slots.release()

    def run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._connect_task = self._loop.create_task(self._connect_loop())
            self._loop.run_until_complete(self._connect_task)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.ws_error.emit(f"WS FATAL: {type(e).__name__}")
        finally:
            self._token = ""
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self._connect_task = None
            self._loop.close()

    async def _connect_loop(self):
        backoff = 1.0
        max_backoff = 30.0

        while self._is_running:
            auth_suspect = False
            try:
                self.connection_status.emit("reconnecting")
                # websockets renamed extra_headers in v14. Both variants put
                # the credential in the handshake header, never the URL.
                header_arg = ("additional_headers" if "additional_headers" in
                              inspect.signature(websockets.connect).parameters else "extra_headers")
                from app.tls_pinning import build_pinned_ssl_context

                ws_extra_kwargs = {header_arg: {"Authorization": f"Bearer {self._token}"}}
                pinned_ssl = build_pinned_ssl_context(self.ws_url)
                if pinned_ssl is not None:
                    ws_extra_kwargs["ssl"] = pinned_ssl
                async with websockets.connect(
                    self.ws_url,
                    ping_interval=20,
                    ping_timeout=10,
                    close_timeout=2,
                    max_size=2 * 1024 * 1024,
                    max_queue=8,
                    **ws_extra_kwargs,
                ) as ws:
                    self._ws = ws
                    backoff = 1.0
                    self.connection_status.emit("connected")
                    print("[WS] ✅ Подключено")  # Never log the token-bearing URL.

                    event_signals = {
                        "new_message": self.new_message_received,
                        "group_message": self.group_message_received,
                        "group_created": self.group_created_received,
                        "group_invited": self.group_invited_received,
                        "group_member_joined": self.group_member_joined,
                        "group_member_left": self.group_member_left,
                        "group_deleted": self.group_deleted_received,
                        "group_sender_key_updated": self.group_sender_key_updated,
                        "webrtc_signal": self.webrtc_signal_received,
                        "call_offer": self.call_offer_received,
                        "call_accept": self.call_accept_received,
                        "call_ended": self.call_ended_received,
                        "group_voice_state": self.group_voice_state_received,
                        "group_voice_signal": self.group_voice_signal_received,
                    }
                    while self._is_running:
                        if not self._event_slots.acquire(blocking=False):
                            # Stop reading until the GUI consumes an event; the
                            # WebSocket library and TCP apply backpressure.
                            await asyncio.sleep(0.02)
                            continue
                        emitted = False
                        try:
                            message = await ws.recv()
                            if isinstance(message, bytes):
                                continue  # Legacy screen relay is disabled.
                            data = json.loads(message)
                            if not isinstance(data, dict):
                                continue
                            msg_type = data.get("type")
                            if not isinstance(msg_type, str):
                                continue
                            signal = event_signals.get(msg_type)
                            if signal is not None:
                                signal.emit(data)
                                emitted = True  # GUI callback returns the slot.
                        finally:
                            if not emitted:
                                self._event_slots.release()


            except websockets.exceptions.ConnectionClosed as e:
                rcvd = getattr(e, "rcvd", None)
                code = getattr(rcvd, "code", None) if rcvd is not None else getattr(e, "code", None)
                if code == 1008:
                    auth_suspect = True
                # Close reasons are peer-controlled and may contain secrets.
                print(f"[WS] Соединение закрыто: code={code} class={type(e).__name__}")
            except Exception as e:
                status_code = getattr(e, "status_code", None)
                if status_code is None:
                    status_code = getattr(getattr(e, "response", None), "status_code", None)
                if status_code in (401, 403):
                    auth_suspect = True
                # Exception strings/tracebacks can contain URLs or headers.
                print(f"[WS] Ошибка: {type(e).__name__}")
            finally:
                self._ws = None

            if not self._is_running:
                break

            self.connection_status.emit("disconnected")
            if auth_suspect:
                self.connection_status.emit("auth_check")
                backoff = max(backoff, 5.0)
            print(f"[WS] Реконнект через {backoff:.1f}s...")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)

    def stop(self):
        self._is_running = False
        self._token = ""
        loop, task = self._loop, self._connect_task
        if loop and task and loop.is_running():
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass


# ============================================================
# SYNC WORKERS
# ============================================================

class SyncMessagesWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, after: str = None):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.after = after

    def run(self):
        url = f"{self.server_url.rstrip('/')}/messages/sync-safe"
        headers = {"Authorization": f"Bearer {self.token}"}
        params = {"limit": SYNC_PAGE_SIZE}
        if self.after:
            params["after"] = self.after
        try:
            response = requests.get(url, headers=headers, params=params, timeout=15.0, stream=True, allow_redirects=False)
            try:
                if response.status_code == 200:
                    data = bounded_json_response(response)
                    if not isinstance(data, list) or len(data) > SYNC_PAGE_SIZE:
                        raise ValueError("Invalid sync response")
                    result = (True, data)
                else:
                    # Do not buffer or display an unbounded error body.
                    result = (False, f"HTTP {response.status_code}: sync failed")
            finally:
                response.close()
        except Exception as e:
            result = (False, f"Ошибка синхронизации: {type(e).__name__}")
        finally:
            self.token = ""
        self.finished.emit(*result)


class AcknowledgeMessagesWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, message_ids: list):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.message_ids = message_ids

    def run(self):
        try:
            if (not isinstance(self.message_ids, list) or not 1 <= len(self.message_ids) <= SYNC_PAGE_SIZE
                    or any(not isinstance(mid, str) or not 0 < len(mid) <= 64 for mid in self.message_ids)
                    or len(set(self.message_ids)) != len(self.message_ids)):
                raise ValueError("Invalid delivery acknowledgement IDs")
            response = requests.post(
                f"{self.server_url.rstrip('/')}/messages/ack",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"message_ids": self.message_ids}, timeout=15.0,
                stream=True, allow_redirects=False,
            )
            try:
                if response.status_code == 200:
                    data = _small_response_json(response)
                    result = ((True, response.status_code) if isinstance(data, dict) and data.get('status') == 'ok'
                              else (False, 'Invalid ACK confirmation'))
                else:
                    # Avoid consuming or logging untrusted error bodies.
                    result = (False, response.status_code)
            finally:
                response.close()
        except Exception as e:
            result = (False, type(e).__name__)
        finally:
            self.token = ""
        self.finished.emit(*result)


class SyncGroupMessagesWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, after: str | None = None):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.after = after

    def run(self):
        url = f"{self.server_url.rstrip('/')}/groups/sync-safe"
        params = {"limit": 100}
        if self.after:
            params["after"] = self.after
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=15.0,
                stream=True,
                allow_redirects=False,
            )
            try:
                if response.status_code == 200:
                    data = _bounded_or_mock_json(response, 4 * 1024 * 1024)
                    messages = data if isinstance(data, list) else []
                    result = (True, messages)
                else:
                    result = (False, f"HTTP {response.status_code}")
            finally:
                _close_response(response)
        except Exception as e:
            result = (False, f"Ошибка sync групп: {type(e).__name__}")
        finally:
            self.token = ""
        self.finished.emit(*result)


# ============================================================
# GROUP WORKERS (Protected E2EE v2)
# ============================================================

class CreateGroupWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, payload: dict):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.payload = payload

    def run(self):
        url = f"{self.server_url.rstrip('/')}/groups/v2/create"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.post(
                url,
                json=self.payload,
                headers=headers,
                timeout=15.0,
                stream=True,
                allow_redirects=False,
            )
            try:
                if response.status_code == 200:
                    result = (True, _bounded_or_mock_json(response, 256 * 1024))
                else:
                    result = (False, f"HTTP {response.status_code}")
            finally:
                _close_response(response)
        except Exception as e:
            result = (False, f"Ошибка создания группы: {type(e).__name__}")
        finally:
            self.token = ""
        self.finished.emit(*result)


class SendGroupMessageWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, payload: dict):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.payload = payload

    def run(self):
        url = f"{self.server_url.rstrip('/')}/groups/v2/send"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.post(
                url,
                json=self.payload,
                headers=headers,
                timeout=15.0,
                stream=True,
                allow_redirects=False,
            )
            try:
                if response.status_code == 200:
                    result = (True, _bounded_or_mock_json(response, 2 * 1024 * 1024))
                else:
                    result = (False, f"HTTP {response.status_code}")
            finally:
                _close_response(response)
        except Exception as e:
            result = (False, f"Ошибка отправки группового сообщения: {type(e).__name__}")
        finally:
            self.token = ""
        self.finished.emit(*result)


class DistributeGroupSenderKeyWorker(QThread):
    finished = Signal(bool, object, str)

    def __init__(self, server_url: str, token: str, group_id: str, payload: dict):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.group_id = group_id
        self.payload = payload

    def run(self):
        try:
            if not isinstance(self.group_id, str) or not _SAFE_ENTITY_ID_RE.fullmatch(self.group_id):
                raise ValueError("Invalid group_id")
            url = f"{self.server_url.rstrip('/')}/groups/v2/{self.group_id}/distribute-key"
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.post(
                url,
                json=self.payload,
                headers=headers,
                timeout=15.0,
                stream=True,
                allow_redirects=False,
            )
            try:
                if response.status_code == 200:
                    result = (True, _bounded_or_mock_json(response, 64 * 1024))
                else:
                    result = (False, f"HTTP {response.status_code}")
            finally:
                _close_response(response)
            self.finished.emit(*result, self.group_id)
        except Exception as e:
            self.finished.emit(False, f"Ошибка распределения ключа: {type(e).__name__}", self.group_id)
        finally:
            self.token = ""


class InviteGroupMemberWorker(QThread):
    finished = Signal(bool, object, str)

    def __init__(self, server_url: str, token: str, payload: dict):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.payload = payload
        self.group_id = str(payload.get("group_id", ""))

    def run(self):
        try:
            if not _SAFE_ENTITY_ID_RE.fullmatch(self.group_id):
                raise ValueError("Invalid group_id")
            url = f"{self.server_url.rstrip('/')}/groups/v2/invite"
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.post(
                url,
                json=self.payload,
                headers=headers,
                timeout=15.0,
                stream=True,
                allow_redirects=False,
            )
            try:
                if response.status_code == 200:
                    result = (True, _bounded_or_mock_json(response, 64 * 1024))
                else:
                    result = (False, f"HTTP {response.status_code}")
            finally:
                _close_response(response)
            self.finished.emit(*result, self.group_id)
        except Exception as e:
            self.finished.emit(False, f"Ошибка приглашения в группу: {type(e).__name__}", self.group_id)
        finally:
            self.token = ""


class AcknowledgeGroupMessagesWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, message_ids: list):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.message_ids = list(message_ids)[:500]

    def run(self):
        if not self.message_ids:
            self.token = ""
            self.finished.emit(True, {"status": "ok"})
            return
        url = f"{self.server_url.rstrip('/')}/groups/ack"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.post(
                url,
                json={"message_ids": self.message_ids},
                headers=headers,
                timeout=15.0,
                stream=True,
                allow_redirects=False,
            )
            try:
                if response.status_code == 200:
                    result = (True, _bounded_or_mock_json(response, 16 * 1024))
                else:
                    result = (False, f"HTTP {response.status_code}")
            finally:
                _close_response(response)
        except Exception as e:
            result = (False, f"Ошибка подтверждения групповых сообщений: {type(e).__name__}")
        finally:
            self.token = ""
        self.finished.emit(*result)


class FetchGroupMembersWorker(QThread):
    finished = Signal(bool, object, str)

    def __init__(self, server_url: str, token: str, group_id: str):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.group_id = group_id

    def run(self):
        try:
            if not isinstance(self.group_id, str) or not _SAFE_ENTITY_ID_RE.fullmatch(self.group_id):
                raise ValueError("Invalid group_id")
            url = f"{self.server_url.rstrip('/')}/groups/{self.group_id}/members"
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(url, headers=headers, timeout=15.0, stream=True, allow_redirects=False)
            try:
                if response.status_code == 200:
                    result = (True, _bounded_or_mock_json(response, 512 * 1024))
                else:
                    result = (False, f"HTTP {response.status_code}")
            finally:
                _close_response(response)
            self.finished.emit(*result, self.group_id)
        except Exception as e:
            self.finished.emit(False, f"Ошибка загрузки участников группы: {type(e).__name__}", self.group_id)
        finally:
            self.token = ""


class FetchGroupsWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str):
        super().__init__()
        self.server_url = server_url
        self.token = token

    def run(self):
        url = f"{self.server_url.rstrip('/')}/groups/list"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.get(url, headers=headers, timeout=15.0, stream=True, allow_redirects=False)
            try:
                if response.status_code != 200:
                    result = (False, f"HTTP {response.status_code}")
                else:
                    result = None
                if result is None:
                    groups = _small_response_json(response, 4 * 1024 * 1024)
                    if not isinstance(groups, list) or len(groups) > 1000:
                        raise ValueError("Invalid group list")
                    ids = set()
                    for group in groups:
                        if not isinstance(group, dict):
                            raise ValueError("Invalid group")
                        group_id, name, members = group.get("id"), group.get("name"), group.get("members")
                        if (not isinstance(group_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", group_id)
                                or group_id in ids or not isinstance(name, str) or not 1 <= len(name) <= 100
                                or not isinstance(members, list) or len(members) > 1000
                                or any(not isinstance(member, dict) for member in members)):
                            raise ValueError("Invalid group")
                        ids.add(group_id)
                    result = (True, groups)
            finally:
                response.close()
            self.finished.emit(*result)
        except Exception as e:
            self.finished.emit(False, f"Ошибка загрузки групп: {type(e).__name__}")
        finally:
            self.token = ""


class FetchGroupSenderKeysWorker(QThread):
    finished = Signal(bool, object, str)

    def __init__(self, server_url: str, token: str, group_id: str):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.group_id = group_id

    def run(self):
        try:
            if not isinstance(self.group_id, str) or not _SAFE_ENTITY_ID_RE.fullmatch(self.group_id):
                raise ValueError("Invalid group_id")
            url = f"{self.server_url.rstrip('/')}/groups/{self.group_id}/sender_keys"
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(url, headers=headers, timeout=15.0, stream=True, allow_redirects=False)
            try:
                if response.status_code == 200:
                    result = (True, _bounded_or_mock_json(response, 1024 * 1024))
                else:
                    result = (False, f"HTTP {response.status_code}")
            finally:
                _close_response(response)
            self.finished.emit(*result, self.group_id)
        except Exception as e:
            self.finished.emit(False, f"Ошибка загрузки ключей: {type(e).__name__}", self.group_id)
        finally:
            self.token = ""


class LeaveGroupWorker(QThread):
    finished = Signal(bool, object, str)

    def __init__(self, server_url: str, token: str, group_id: str):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.group_id = group_id

    def run(self):
        try:
            if not isinstance(self.group_id, str) or not _SAFE_ENTITY_ID_RE.fullmatch(self.group_id):
                raise ValueError("Invalid group_id")
            url = f"{self.server_url.rstrip('/')}/groups/{self.group_id}/leave"
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.post(url, headers=headers, timeout=15.0, stream=True, allow_redirects=False)
            try:
                if response.status_code == 200:
                    result = (True, _bounded_or_mock_json(response, 16 * 1024))
                else:
                    result = (False, f"HTTP {response.status_code}")
            finally:
                _close_response(response)
            self.finished.emit(*result, self.group_id)
        except Exception as e:
            self.finished.emit(False, f"Ошибка выхода из группы: {type(e).__name__}", self.group_id)
        finally:
            self.token = ""


class DeleteGroupWorker(QThread):
    finished = Signal(bool, object, str)

    def __init__(self, server_url: str, token: str, group_id: str):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.group_id = group_id

    def run(self):
        try:
            if not isinstance(self.group_id, str) or not _SAFE_ENTITY_ID_RE.fullmatch(self.group_id):
                raise ValueError("Invalid group_id")
            url = f"{self.server_url.rstrip('/')}/groups/{self.group_id}"
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.delete(url, headers=headers, timeout=15.0, stream=True, allow_redirects=False)
            try:
                if response.status_code == 200:
                    result = (True, _bounded_or_mock_json(response, 16 * 1024))
                else:
                    result = (False, f"HTTP {response.status_code}")
            finally:
                _close_response(response)
            self.finished.emit(*result, self.group_id)
        except Exception as e:
            self.finished.emit(False, f"Ошибка удаления группы: {type(e).__name__}", self.group_id)
        finally:
            self.token = ""


# ============================================================
# X3DH PREKEY WORKERS (Production /prekeys)
# ============================================================

class PreKeyStatusWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str):
        super().__init__()
        self.server_url = server_url
        self.token = token

    def run(self):
        url = f"{self.server_url.rstrip('/')}/prekeys/status"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.get(url, headers=headers, timeout=15.0, stream=True, allow_redirects=False)
            try:
                if response.status_code == 200:
                    result = (True, _bounded_or_mock_json(response, 16 * 1024))
                else:
                    result = (False, f"HTTP {response.status_code}")
            finally:
                _close_response(response)
        except Exception as e:
            result = (False, f"Ошибка статуса prekey: {type(e).__name__}")
        finally:
            self.token = ""
        self.finished.emit(*result)


class PublishPreKeyBundleWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, bundle_payload: dict):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.bundle_payload = bundle_payload

    def run(self):
        url = f"{self.server_url.rstrip('/')}/prekeys/bundle"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.put(
                url,
                json=self.bundle_payload,
                headers=headers,
                timeout=15.0,
                stream=True,
                allow_redirects=False,
            )
            try:
                if response.status_code == 200:
                    result = (True, _bounded_or_mock_json(response, 32 * 1024))
                else:
                    result = (False, f"HTTP {response.status_code}")
            finally:
                _close_response(response)
        except Exception as e:
            result = (False, f"Ошибка публикации prekey: {type(e).__name__}")
        finally:
            self.token = ""
        self.finished.emit(*result)


class ClaimPreKeyBundleWorker(QThread):
    finished = Signal(bool, object, str)

    def __init__(self, server_url: str, token: str, target_device_id: str, request_id: str | None = None):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.target_device_id = target_device_id
        self.request_id = request_id or str(__import__("uuid").uuid4())

    def run(self):
        try:
            if not isinstance(self.target_device_id, str) or not _SAFE_ENTITY_ID_RE.fullmatch(self.target_device_id):
                raise ValueError("Invalid target_device_id")
            url = f"{self.server_url.rstrip('/')}/prekeys/{self.target_device_id}/claim"
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.post(
                url,
                json={"request_id": self.request_id},
                headers=headers,
                timeout=15.0,
                stream=True,
                allow_redirects=False,
            )
            try:
                if response.status_code == 200:
                    result = (True, _bounded_or_mock_json(response, 32 * 1024))
                else:
                    result = (False, f"HTTP {response.status_code}")
            finally:
                _close_response(response)
            self.finished.emit(*result, self.target_device_id)
        except Exception as e:
            self.finished.emit(False, f"Ошибка получения prekey: {type(e).__name__}", self.target_device_id)
        finally:
            self.token = ""


# ============================================================
# PACKAGE IV: ICE/TURN CONFIG + GROUP VOICE ROOM WORKERS
# ============================================================

class FetchIceConfigWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str):
        super().__init__()
        self.server_url = server_url
        self.token = token

    def run(self):
        url = f"{self.server_url.rstrip('/')}/calls/ice-config"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=10.0,
                stream=True,
                allow_redirects=False,
            )
            try:
                if response.status_code == 200:
                    payload = _bounded_or_mock_json(response, 32 * 1024)
                    from app.ice_config import set_runtime_ice_config
                    set_runtime_ice_config(payload)
                    result = (True, payload)
                else:
                    result = (False, f"HTTP {response.status_code}")
            finally:
                _close_response(response)
        except Exception as e:
            result = (False, f"Ошибка загрузки ICE конфигурации: {type(e).__name__}")
        finally:
            self.token = ""
        self.finished.emit(*result)


class GroupVoiceRoomActionWorker(QThread):
    finished = Signal(bool, object, str, str)

    def __init__(
        self,
        server_url: str,
        token: str,
        group_id: str,
        action: str,
        payload: dict | None = None,
    ):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.group_id = group_id
        self.action = action
        self.payload = payload or {}

    def run(self):
        try:
            if not isinstance(self.group_id, str) or not _SAFE_ENTITY_ID_RE.fullmatch(self.group_id):
                raise ValueError("Invalid group_id")
            base = f"{self.server_url.rstrip('/')}/calls/groups/{self.group_id}/voice"
            headers = {"Authorization": f"Bearer {self.token}"}

            if self.action == "fetch_state":
                response = requests.get(
                    f"{base}/state",
                    headers=headers,
                    timeout=10.0,
                    stream=True,
                    allow_redirects=False,
                )
            elif self.action in ("join", "leave", "state", "signal"):
                response = requests.post(
                    f"{base}/{self.action}",
                    json=self.payload,
                    headers=headers,
                    timeout=10.0,
                    stream=True,
                    allow_redirects=False,
                )
            else:
                raise ValueError("Unsupported voice room action")

            try:
                if response.status_code == 200:
                    result = (True, _bounded_or_mock_json(response, 64 * 1024))
                else:
                    detail = f"HTTP {response.status_code}"
                    try:
                        err_json = _bounded_or_mock_json(response, 8 * 1024)
                        if isinstance(err_json, dict) and isinstance(err_json.get("detail"), str):
                            detail = err_json["detail"]
                    except Exception:
                        pass
                    result = (False, detail)
            finally:
                _close_response(response)
            self.finished.emit(*result, self.group_id, self.action)
        except Exception as e:
            self.finished.emit(False, f"Ошибка голосовой комнаты: {type(e).__name__}", self.group_id, self.action)
        finally:
            self.token = ""


class UploadAndGrantGroupAttachmentWorker(QThread):
    """Upload an already E2EE-encrypted blob and grant download access to all active group devices."""
    finished = Signal(bool, object)

    def __init__(
        self,
        server_url: str,
        token: str,
        file_id: str,
        encrypted_blob: bytes,
        member_device_ids: list[str],
    ):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.file_id = file_id
        self.encrypted_blob = encrypted_blob
        self.member_device_ids = list(dict.fromkeys(member_device_ids))

    def run(self):
        try:
            from app.attachment_outbox import MAX_AUTHENTICATED_UPLOAD_BYTES
            if not self.encrypted_blob or len(self.encrypted_blob) > MAX_AUTHENTICATED_UPLOAD_BYTES:
                self.finished.emit(False, "ATTACHMENT_TOO_LARGE")
                return

            ok_up, data_up = api.upload_file_reliable(
                self.server_url, self.token, self.file_id, self.encrypted_blob
            )
            if not ok_up:
                self.finished.emit(False, data_up)
                return

            for dev_id in self.member_device_ids:
                if not isinstance(dev_id, str) or not _SAFE_ENTITY_ID_RE.fullmatch(dev_id):
                    continue
                ok_g, data_g = api.grant_file_access(self.server_url, self.token, self.file_id, dev_id)
                if not ok_g:
                    self.finished.emit(False, data_g)
                    return

            self.finished.emit(True, {"file_id": self.file_id, "granted": len(self.member_device_ids)})
        except Exception as exc:
            self.finished.emit(False, f"Ошибка группового вложения: {type(exc).__name__}")
        finally:
            self.token = ""
            self.encrypted_blob = b""

