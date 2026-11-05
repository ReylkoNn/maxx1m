import asyncio
import base64
import requests
from PySide6.QtCore import QThread, Signal
import websockets
import json
from app.client_api import api


# ============================================================
# AUTH WORKERS
# ============================================================

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
        success, data = api.find_user(self.server_url, self.token, self.target_username)
        self.finished.emit(success, data)


class SendMessageWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, payload: dict):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.payload = payload

    def run(self):
        success, data = api.send_message(self.server_url, self.token, self.payload)
        self.finished.emit(success, data)


class UploadFileWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, file_data: bytes):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.file_data = file_data

    def run(self):
        success, data = api.upload_file(self.server_url, self.token, self.file_data)
        self.finished.emit(success, data)


class GrantFileAccessWorker(QThread):
    """
    Выдаёт получателю право скачивать файл (см. /files/{file_id}/grant на бэкенде).

    Запускается в фоне после upload, чтобы не морозить UI-поток синхронным
    requests.post. Сам по себе грант не блокирует отправку сообщения —
    если он не дойдёт, получатель просто не сможет скачать картинку сразу
    (а сообщение с текстом дойдёт в любом случае).
    """
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, file_id: str, recipient_device_id: str):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.file_id = file_id
        self.recipient_device_id = recipient_device_id

    def run(self):
        success, data = api.grant_file_access(
            self.server_url, self.token,
            self.file_id, self.recipient_device_id
        )
        self.finished.emit(success, data)


class DownloadFileWorker(QThread):
    finished = Signal(bool, object, str)

    def __init__(self, server_url: str, token: str, file_id: str):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.file_id = file_id

    def run(self):
        success, data = api.download_file(self.server_url, self.token, self.file_id)
        self.finished.emit(success, data, self.file_id)


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

    # ── WebRTC сигналинг ────────────────────────────────────────────
    webrtc_signal_received = Signal(dict)   # зашифрованный E2EE сигнал
    call_offer_received    = Signal(dict)   # входящий вызов
    call_accept_received   = Signal(dict)   # собеседник принял
    call_ended_received    = Signal(dict)   # звонок завершён

    # ── Демонстрация экрана ─────────────────────────────────────────
    # Кадры идут потоком (10-15 fps), каждый — base64-JPEG в data["frame"].
    # Раньше эти типы вообще не обрабатывались — сервер их ретрансил,
    # а клиент молча выбрасывал, поэтому демка "не работала".
    screen_frame_received  = Signal(dict)   # входящий кадр демки
    screen_control_received = Signal(dict)  # start/stop демки от пира

    def __init__(self, server_url: str, token: str, device_id: str):
        super().__init__()
        self.device_id = device_id
        base_ws = server_url.replace("http://", "ws://").replace("https://", "wss://")
        self.ws_url = f"{base_ws}/messages/ws/{device_id}?token={token}"
        self._is_running = True
        self._ws = None          # ссылка на активный websocket
        self._loop = None        # ссылка на event loop

    # ── Отправка сообщения через WS (thread-safe) ───────────
    def send_signal(self, payload: dict):
        if self._loop and self._ws:
            if payload.get("type") == "screen_frame" and isinstance(payload.get("frame"), bytes):
                asyncio.run_coroutine_threadsafe(
                    self._send_binary_frame(payload), self._loop
                )
            else:
                asyncio.run_coroutine_threadsafe(
                    self._send_raw(payload), self._loop
                )
        else:
            if payload.get("type") != "screen_frame":
                print(f"[WS] ⚠️ send_signal: loop/ws не готовы: {payload.get('type')}")

    async def _send_binary_frame(self, payload: dict):
        try:
            if self._ws:
                header = json.dumps({
                    "type": "screen_frame",
                    "to_device_id": payload.get("to_device_id", ""),
                }).encode("utf-8")
                jpeg_data = payload["frame"]
                header_len = len(header).to_bytes(2, "big")
                await self._ws.send(header_len + header + jpeg_data)
        except Exception as e:
            print(f"[WS] ❌ Binary frame error: {e}")

    async def _send_raw(self, payload: dict):
        try:
            if self._ws:
                await self._ws.send(json.dumps(payload))
                msg_type = payload.get("type")
                if msg_type != "screen_frame":
                    print(f"[WS] 📤 Отправлено: {msg_type}")
        except Exception as e:
            print(f"[WS] ❌ Ошибка отправки: {e}")

    def _handle_binary_frame(self, raw_data: bytes):
        try:
            header_len = int.from_bytes(raw_data[:2], "big")
            header_json = raw_data[2:2 + header_len].decode("utf-8")
            header = json.loads(header_json)
            jpeg_data = raw_data[2 + header_len:]

            if header.get("type") == "screen_frame":
                self.screen_frame_received.emit({
                    "type": "screen_frame",
                    "frame": base64.b64encode(jpeg_data).decode("ascii"),
                })
        except Exception as e:
            print(f"[WS] ❌ Binary parse error: {e}")

    def run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._connect_loop())
        except Exception as e:
            self.ws_error.emit(f"WS FATAL: {type(e).__name__} - {e}")
        finally:
            self._loop.close()

    async def _connect_loop(self):
        backoff = 1.0
        max_backoff = 30.0

        while self._is_running:
            try:
                self.connection_status.emit("reconnecting")
                async with websockets.connect(
                    self.ws_url,
                    ping_interval=20,
                    ping_timeout=10
                ) as ws:
                    self._ws = ws
                    backoff = 1.0
                    self.connection_status.emit("connected")
                    print(f"[WS] ✅ Подключено: {self.ws_url}")

                    while self._is_running:
                        message = await ws.recv()

                        if isinstance(message, bytes):
                            self._handle_binary_frame(message)
                            continue

                        data = json.loads(message)
                        msg_type = data.get("type")

                        # ── Личные сообщения ───────────────
                        if msg_type == "new_message":
                            self.new_message_received.emit(data)

                        # ── Групповые события ──────────────
                        elif msg_type == "group_message":
                            self.group_message_received.emit(data)
                        elif msg_type == "group_created":
                            self.group_created_received.emit(data)
                        elif msg_type == "group_invited":
                            self.group_invited_received.emit(data)
                        elif msg_type == "group_member_joined":
                            self.group_member_joined.emit(data)
                        elif msg_type == "group_member_left":
                            self.group_member_left.emit(data)
                        elif msg_type == "group_deleted":
                            self.group_deleted_received.emit(data)

                        # ── WebRTC сигналинг ───────────────────────
                        elif msg_type == "webrtc_signal":
                            print(f"[WS] 🔒 webrtc_signal от {data.get('from_device_id')}")
                            self.webrtc_signal_received.emit(data)

                        elif msg_type == "call_offer":
                            print(f"[WS] 📞 call_offer от {data.get('from_device_id')}")
                            self.call_offer_received.emit(data)

                        elif msg_type == "call_accept":
                            print(f"[WS] ✅ call_accept от {data.get('from_device_id')}")
                            self.call_accept_received.emit(data)

                        elif msg_type == "call_ended":
                            print(f"[WS] 📴 call_ended от {data.get('from_device_id')}")
                            self.call_ended_received.emit(data)

                        elif msg_type == "screen_frame":
                            self.screen_frame_received.emit(data)

                        elif msg_type == "screen_control":
                            print(f"[WS] 🖥️ screen_control от {data.get('from_device_id')}: {data.get('action')}")
                            self.screen_control_received.emit(data)



            except websockets.exceptions.ConnectionClosed as e:
                print(
                    f"[WS] Соединение закрыто: "
                    f"code={getattr(e, 'code', None)} "
                    f"reason={getattr(e, 'reason', None)} "
                    f"class={type(e).__name__}"
                )
            except Exception as e:
                print(f"[WS] Ошибка: {type(e).__name__}: {e}")
                import traceback
                traceback.print_exc()
            finally:
                self._ws = None

            if not self._is_running:
                break

            self.connection_status.emit("disconnected")
            print(f"[WS] Реконнект через {backoff:.1f}s...")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)

    def stop(self):
        self._is_running = False


# ============================================================
# SYNC WORKERS
# ============================================================

class SyncMessagesWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str):
        super().__init__()
        self.server_url = server_url
        self.token = token

    def run(self):
        url = f"{self.server_url.rstrip('/')}/messages/sync"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.get(url, headers=headers, timeout=15.0)
            if response.status_code == 200:
                data = response.json()
                messages = data if isinstance(data, list) else data.get("messages", [])
                self.finished.emit(True, messages)
            else:
                self.finished.emit(False, f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.finished.emit(False, f"Ошибка синхронизации: {type(e).__name__}")


class SyncGroupMessagesWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str):
        super().__init__()
        self.server_url = server_url
        self.token = token

    def run(self):
        url = f"{self.server_url.rstrip('/')}/groups/sync"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.get(url, headers=headers, timeout=15.0)
            if response.status_code == 200:
                data = response.json()
                messages = data if isinstance(data, list) else []
                self.finished.emit(True, messages)
            else:
                self.finished.emit(False, f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.finished.emit(False, f"Ошибка sync групп: {type(e).__name__}")


# ============================================================
# GROUP WORKERS
# ============================================================

class CreateGroupWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, payload: dict):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.payload = payload

    def run(self):
        url = f"{self.server_url.rstrip('/')}/groups/create"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.post(url, json=self.payload, headers=headers, timeout=15.0)
            if response.status_code == 200:
                self.finished.emit(True, response.json())
            else:
                self.finished.emit(False, f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.finished.emit(False, f"Ошибка создания группы: {type(e).__name__}")


class SendGroupMessageWorker(QThread):
    finished = Signal(bool, object)

    def __init__(self, server_url: str, token: str, payload: dict):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.payload = payload

    def run(self):
        url = f"{self.server_url.rstrip('/')}/groups/send"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.post(url, json=self.payload, headers=headers, timeout=15.0)
            if response.status_code == 200:
                self.finished.emit(True, response.json())
            else:
                self.finished.emit(False, f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.finished.emit(False, f"Ошибка отправки группового сообщения: {type(e).__name__}")


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
            response = requests.get(url, headers=headers, timeout=15.0)
            if response.status_code == 200:
                self.finished.emit(True, response.json())
            else:
                self.finished.emit(False, f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.finished.emit(False, f"Ошибка загрузки групп: {type(e).__name__}")


class FetchGroupSenderKeysWorker(QThread):
    finished = Signal(bool, object, str)

    def __init__(self, server_url: str, token: str, group_id: str):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.group_id = group_id

    def run(self):
        url = f"{self.server_url.rstrip('/')}/groups/{self.group_id}/sender_keys"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.get(url, headers=headers, timeout=15.0)
            if response.status_code == 200:
                self.finished.emit(True, response.json(), self.group_id)
            else:
                self.finished.emit(False, f"HTTP {response.status_code}", self.group_id)
        except Exception as e:
            self.finished.emit(False, f"Ошибка загрузки ключей: {type(e).__name__}", self.group_id)


class LeaveGroupWorker(QThread):
    finished = Signal(bool, object, str)

    def __init__(self, server_url: str, token: str, group_id: str):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.group_id = group_id

    def run(self):
        url = f"{self.server_url.rstrip('/')}/groups/{self.group_id}/leave"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.post(url, headers=headers, timeout=15.0)
            if response.status_code == 200:
                self.finished.emit(True, response.json(), self.group_id)
            else:
                self.finished.emit(False, f"HTTP {response.status_code}: {response.text}", self.group_id)
        except Exception as e:
            self.finished.emit(False, f"Ошибка выхода из группы: {type(e).__name__}", self.group_id)


class DeleteGroupWorker(QThread):
    finished = Signal(bool, object, str)

    def __init__(self, server_url: str, token: str, group_id: str):
        super().__init__()
        self.server_url = server_url
        self.token = token
        self.group_id = group_id

    def run(self):
        url = f"{self.server_url.rstrip('/')}/groups/{self.group_id}"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.delete(url, headers=headers, timeout=15.0)
            if response.status_code == 200:
                self.finished.emit(True, response.json(), self.group_id)
            else:
                self.finished.emit(False, f"HTTP {response.status_code}: {response.text}", self.group_id)
        except Exception as e:
            self.finished.emit(False, f"Ошибка удаления группы: {type(e).__name__}", self.group_id)