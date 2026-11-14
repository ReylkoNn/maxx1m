import base64
import hashlib
import os
import urllib.parse
import requests
import json
import re
from typing import Tuple, Any
from app.media_identity import valid_file_id

MAX_SEND_RESPONSE_BYTES = 2 * 1024 * 1024  # Older servers echo the full ciphertext.
MAX_DOWNLOAD_BYTES = 21 * 1024 * 1024  # Supports a 20 MiB image plus encryption overhead.
_SAFE_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _safe_local_fingerprint(public_key_b64: str, fallback: str = "—") -> Tuple[str, bool]:
    """Compute SHA-256 colon-hex fingerprint locally when public_key_b64 is a canonical 32-byte key."""
    if not isinstance(public_key_b64, str):
        return fallback, False
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != public_key_b64:
            return fallback, False
        digest = hashlib.sha256(raw).hexdigest().upper()
        return ":".join(digest[i:i + 4] for i in range(0, 32, 4)), True
    except Exception:
        return fallback, False


def validate_server_url(server_url: str) -> Tuple[bool, str]:
    """Ensure server_url uses HTTPS (or loopback HTTP for local tunnels/dev) without credentials or query strings."""
    if not isinstance(server_url, str) or not server_url.strip():
        return False, "Укажи корректный адрес сервера"
    raw = server_url.strip()
    if any(ch.isspace() or ord(ch) < 0x20 for ch in raw):
        return False, "Адрес сервера содержит недопустимые символы"
    parsed = urllib.parse.urlsplit(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("https", "http"):
        return False, "Адрес сервера должен начинаться с https:// (или http:// только для localhost)"
    if parsed.username is not None or parsed.password is not None:
        return False, "Учётные данные в URL сервера запрещены"
    if parsed.query or parsed.fragment:
        return False, "Параметры запроса и фрагменты в адресе сервера не допускаются"
    host = (parsed.hostname or "").lower()
    if not host:
        return False, "Не указан хост сервера"
    try:
        port = parsed.port
    except ValueError:
        return False, "Некорректный порт в адресе сервера"
    if port is not None and not (1 <= port <= 65535):
        return False, "Некорректный порт в адресе сервера"
    if scheme == "http":
        is_loopback = host in ("localhost", "127.0.0.1", "::1")
        if not is_loopback and os.environ.get("MAX1M_ALLOW_INSECURE_HTTP") != "1":
            return (
                False,
                "Передача паролей и токенов по незашифрованному HTTP запрещена для удалённых узлов. Используйте https://.",
            )
    elif scheme == "https":
        try:
            from app.tls_pinning import install_urllib3_spki_enforcement

            install_urllib3_spki_enforcement()
        except ImportError:
            pass
    return True, ""

def _small_response_json(response, limit=16 * 1024):
    data = bytearray()
    for chunk in response.iter_content(4096):
        if not isinstance(chunk, bytes) or len(data) + len(chunk) > limit:
            raise ValueError("Server response too large")
        data.extend(chunk)
    return json.loads(data)


class APIClient:
    def _get_error(self, response: requests.Response) -> str:
        try:
            data = response.json()
            detail = data.get("detail", "Неизвестная ошибка сервера")
            if isinstance(detail, list):
                return str(detail[0].get("msg", "Ошибка валидации"))
            return str(detail)
        except:
            return response.text

    def _auth_request(self, server_url: str, endpoint: str, payload: dict, expected_status: int) -> Tuple[bool, Any]:
        url_ok, url_err = validate_server_url(server_url)
        if not url_ok:
            return False, url_err
        url = f"{server_url.rstrip('/')}/auth/{endpoint}"
        try:
            # Never forward passwords or invitation codes through redirects.
            response = requests.post(url, json=payload, timeout=10.0, stream=True, allow_redirects=False)
            try:
                try:
                    data = _small_response_json(response, 64 * 1024)
                except (ValueError, TypeError):
                    return False, f"HTTP {response.status_code}: недопустимый ответ сервера"
                if response.status_code == expected_status and isinstance(data, dict):
                    return True, data
                detail = data.get("detail") if isinstance(data, dict) else None
                if isinstance(detail, list):
                    detail = detail[0].get("msg") if detail and isinstance(detail[0], dict) else None
                if not isinstance(detail, str):
                    detail = "Ошибка сервера"
                return False, f"HTTP {response.status_code}: {detail[:512]}"
            finally:
                response.close()
        except (requests.exceptions.RequestException, OSError, ValueError, TypeError) as e:
            return False, f"Ошибка сети или ответа: {type(e).__name__}"

    def register(self, server_url: str, payload: dict) -> Tuple[bool, Any]:
        return self._auth_request(server_url, "register", payload, 201)

    def login(self, server_url: str, payload: dict) -> Tuple[bool, Any]:
        return self._auth_request(server_url, "login", payload, 200)

    def logout(
        self,
        server_url: str,
        token: str,
        *,
        include_other_devices: bool = False,
        only_other_devices: bool = False,
        timeout: float = 4.0,
    ) -> Tuple[bool, Any]:
        if not isinstance(server_url, str) or not server_url or not isinstance(token, str) or not token:
            return False, "Отсутствуют параметры сессии."
        url_ok, url_err = validate_server_url(server_url)
        if not url_ok:
            return False, url_err
        if include_other_devices and only_other_devices:
            return False, "Взаимоисключающие параметры выхода."
        url = f"{server_url.rstrip('/')}/auth/logout"
        headers = {"Authorization": f"Bearer {token}"}
        payload = {
            "include_other_devices": bool(include_other_devices),
            "only_other_devices": bool(only_other_devices),
        }
        try:
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=timeout,
                stream=True,
                allow_redirects=False,
            )
            try:
                try:
                    data = _small_response_json(response, 16 * 1024)
                except (ValueError, TypeError):
                    return False, f"HTTP {response.status_code}: недопустимый ответ сервера"
                if response.status_code != 200:
                    detail = data.get("detail") if isinstance(data, dict) else None
                    if not isinstance(detail, str):
                        detail = "выход из сессии не подтверждён"
                    return False, f"HTTP {response.status_code}: {detail[:256]}"
                inv_count = data.get("invalidated_devices_count") if isinstance(data, dict) else None
                if (not isinstance(data, dict)
                        or data.get("status") != "ok"
                        or isinstance(inv_count, bool)
                        or not isinstance(inv_count, int)
                        or inv_count < 0):
                    raise ValueError("Invalid logout response")
                return True, {"status": "ok", "invalidated_devices_count": inv_count}
            finally:
                response.close()
        except (requests.exceptions.RequestException, OSError, ValueError, TypeError, RecursionError) as e:
            return False, f"Ошибка сети или ответа: {type(e).__name__}"

    def change_password(
        self,
        server_url: str,
        token: str,
        current_password: str,
        new_password: str,
        revoke_other_devices: bool = False,
    ) -> Tuple[bool, Any]:
        if (not isinstance(current_password, str) or not 1 <= len(current_password) <= 1024
                or not isinstance(new_password, str) or not 8 <= len(new_password) <= 1024):
            return False, "Некорректная длина пароля (минимум 8 символов)."
        if current_password == new_password:
            return False, "Новый пароль должен отличаться от текущего."
        url_ok, url_err = validate_server_url(server_url)
        if not url_ok:
            return False, url_err
        url = f"{server_url.rstrip('/')}/auth/change-password"
        headers = {"Authorization": f"Bearer {token}"}
        payload = {
            "current_password": current_password,
            "new_password": new_password,
            "revoke_other_devices": bool(revoke_other_devices),
        }
        try:
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=15.0,
                stream=True,
                allow_redirects=False,
            )
            try:
                try:
                    data = _small_response_json(response, 32 * 1024)
                except (ValueError, TypeError):
                    return False, f"HTTP {response.status_code}: недопустимый ответ сервера"
                if response.status_code != 200:
                    detail = data.get("detail") if isinstance(data, dict) else None
                    if not isinstance(detail, str):
                        detail = "смена пароля не подтверждена"
                    return False, f"HTTP {response.status_code}: {detail[:256]}"
                revoked_count = data.get("revoked_devices_count") if isinstance(data, dict) else None
                if (not isinstance(data, dict)
                        or data.get("status") != "ok"
                        or isinstance(revoked_count, bool)
                        or not isinstance(revoked_count, int)
                        or revoked_count < 0):
                    raise ValueError("Invalid change-password response")
                return True, {"status": "ok", "revoked_devices_count": revoked_count}
            finally:
                response.close()
        except (requests.exceptions.RequestException, OSError, ValueError, TypeError, RecursionError) as e:
            return False, f"Ошибка сети или ответа: {type(e).__name__}"

    def cancel_upload_reservation(self, server_url: str, token: str, file_id: str) -> Tuple[bool, Any]:
        url_ok, url_err = validate_server_url(server_url)
        if not url_ok:
            return False, url_err
        if not valid_file_id(file_id):
            return False, "Некорректный идентификатор загрузки"
        url = f"{server_url.rstrip('/')}/files/upload-reliable/{file_id}"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.delete(url, headers=headers, timeout=10.0, stream=True, allow_redirects=False)
            try:
                try:
                    data = _small_response_json(response, 16 * 1024)
                except (ValueError, TypeError):
                    return False, f"HTTP {response.status_code}: недопустимый ответ сервера"
                if response.status_code != 200:
                    detail = data.get("detail") if isinstance(data, dict) else None
                    if not isinstance(detail, str):
                        detail = "отмена брони не подтверждена"
                    return False, f"HTTP {response.status_code}: {detail[:256]}"
                if not isinstance(data, dict) or data.get("status") != "cancelled" or data.get("file_id") != file_id:
                    raise ValueError("Invalid cancel reservation response")
                return True, data
            finally:
                response.close()
        except (requests.exceptions.RequestException, OSError, ValueError, TypeError, RecursionError) as e:
            return False, f"Ошибка сети или ответа: {type(e).__name__}"

    def find_user(self, server_url: str, token: str, target_username: str) -> Tuple[bool, Any]:
        url_ok, url_err = validate_server_url(server_url)
        if not url_ok:
            return False, url_err
        clean = target_username.lstrip("@") if isinstance(target_username, str) else ""
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", clean):
            return False, "Некорректное имя контакта"
        url = f"{server_url.rstrip('/')}/auth/find/{clean}"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.get(url, headers=headers, timeout=10.0, stream=True, allow_redirects=False)
            try:
                if response.status_code == 404:
                    return False, "Союзник не найден."
                if response.status_code != 200:
                    return False, f"Ошибка сервера: {response.status_code}"
                data = _small_response_json(response, 1024 * 1024)
                if not isinstance(data, dict) or data.get("username") != clean:
                    raise ValueError("Invalid contact response")
                user_id, devices = data.get("user_id"), data.get("devices")
                if (not isinstance(user_id, str) or not 1 <= len(user_id) <= 64
                        or not isinstance(devices, list) or not 1 <= len(devices) <= 256):
                    raise ValueError("Invalid contact response")
                cleaned, ids = [], set()
                for device in devices:
                    if not isinstance(device, dict):
                        raise ValueError("Invalid contact device")
                    fields = {}
                    for field, maximum in (("device_id", 64), ("device_name", 100),
                                           ("public_key", 500), ("fingerprint", 100)):
                        value = device.get(field)
                        if not isinstance(value, str) or not 1 <= len(value) <= maximum:
                            raise ValueError("Invalid contact device")
                        fields[field] = value
                    if fields["device_id"] in ids:
                        raise ValueError("Duplicate contact device")
                    ids.add(fields["device_id"])
                    cleaned.append(fields)
                # A server's additional fields must never grant local trust.
                return True, {"user_id": user_id, "username": clean, "devices": cleaned}
            finally:
                response.close()
        except (requests.exceptions.RequestException, OSError, ValueError, TypeError, RecursionError) as e:
            return False, f"Ошибка сети или ответа: {type(e).__name__}"

    def list_own_devices(
        self,
        server_url: str,
        token: str,
        expected_device_id: str = None,
        expected_public_key: str = None,
    ) -> Tuple[bool, Any]:
        url_ok, url_err = validate_server_url(server_url)
        if not url_ok:
            return False, url_err
        url = f"{server_url.rstrip('/')}/auth/devices"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.get(url, headers=headers, timeout=10.0, stream=True, allow_redirects=False)
            try:
                if response.status_code != 200:
                    return False, f"HTTP {response.status_code}: не удалось получить список устройств"
                data = _small_response_json(response, 1024 * 1024)
                if not isinstance(data, list) or not 1 <= len(data) <= 256:
                    raise ValueError("Invalid own devices response")
                cleaned, ids, current_entries = [], set(), []
                for device in data:
                    if not isinstance(device, dict):
                        raise ValueError("Invalid own device entry")
                    dev_id = device.get("id")
                    if not isinstance(dev_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", dev_id):
                        raise ValueError("Invalid own device id")
                    if dev_id in ids:
                        raise ValueError("Duplicate own device id")
                    ids.add(dev_id)
                    entry = {"id": dev_id}
                    for field, maximum in (("device_name", 100), ("public_key", 500), ("fingerprint", 100)):
                        val = device.get(field)
                        if not isinstance(val, str) or not 1 <= len(val) <= maximum:
                            raise ValueError(f"Invalid {field}")
                        entry[field] = val
                    claimed_fp = entry["fingerprint"]
                    computed_fp, is_canonical_key = _safe_local_fingerprint(entry["public_key"], fallback=claimed_fp)
                    if is_canonical_key:
                        entry["fingerprint"] = computed_fp
                        if claimed_fp != computed_fp:
                            entry["server_fingerprint_mismatch"] = True
                    for flag in ("is_revoked", "is_current"):
                        val = device.get(flag)
                        if type(val) is not bool:
                            raise ValueError(f"Invalid {flag}")
                        entry[flag] = val
                    for ts_field in ("created_at", "last_seen"):
                        ts_val = device.get(ts_field)
                        if ts_val is not None:
                            if not isinstance(ts_val, str) or not 1 <= len(ts_val) <= 64:
                                raise ValueError(f"Invalid {ts_field}")
                            entry[ts_field] = ts_val
                    if entry["is_current"]:
                        current_entries.append(entry)
                        if entry["is_revoked"]:
                            raise ValueError("Current device reported as revoked")
                    cleaned.append(entry)
                if len(current_entries) != 1:
                    raise ValueError("Ambiguous current device")
                if expected_device_id is not None and current_entries[0]["id"] != expected_device_id:
                    raise ValueError("Current device mismatch")
                if expected_public_key is not None and current_entries[0]["public_key"] != expected_public_key:
                    raise ValueError("Current device public key mismatch")
                return True, cleaned
            finally:
                response.close()
        except (requests.exceptions.RequestException, OSError, ValueError, TypeError, RecursionError) as e:
            return False, f"Ошибка сети или ответа: {type(e).__name__}"

    def revoke_own_device(self, server_url: str, token: str, target_device_id: str) -> Tuple[bool, Any]:
        url_ok, url_err = validate_server_url(server_url)
        if not url_ok:
            return False, url_err
        if not isinstance(target_device_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", target_device_id):
            return False, "Некорректный идентификатор устройства"
        url = f"{server_url.rstrip('/')}/auth/devices/{target_device_id}/revoke"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.post(url, headers=headers, timeout=10.0, stream=True, allow_redirects=False)
            try:
                try:
                    data = _small_response_json(response, 16 * 1024)
                except (ValueError, TypeError):
                    if response.status_code != 200:
                        return False, f"HTTP {response.status_code}: отзыв не подтверждён"
                    raise
                if response.status_code != 200:
                    detail = data.get("detail") if isinstance(data, dict) else None
                    if not isinstance(detail, str):
                        detail = "отзыв не подтверждён"
                    return False, f"HTTP {response.status_code}: {detail[:256]}"
                if (not isinstance(data, dict)
                        or data.get("status") != "ok"
                        or data.get("device_id") != target_device_id
                        or data.get("is_revoked") is not True):
                    raise ValueError("Invalid revoke response")
                return True, data
            finally:
                response.close()
        except (requests.exceptions.RequestException, OSError, ValueError, TypeError, RecursionError) as e:
            return False, f"Ошибка сети или ответа: {type(e).__name__}"

    def send_message(self, server_url: str, token: str, payload: dict) -> Tuple[bool, Any]:
        url_ok, url_err = validate_server_url(server_url)
        if not url_ok:
            return False, url_err
        url = f"{server_url.rstrip('/')}/messages/send"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=10.0,
                                     stream=True, allow_redirects=False)
            try:
                if response.status_code != 200:
                    return False, f"HTTP {response.status_code}: отправка не подтверждена"
                data = _small_response_json(response, MAX_SEND_RESPONSE_BYTES)
                if not isinstance(data, dict):
                    raise ValueError("Invalid send response")
                return True, data
            finally:
                response.close()
        except (requests.exceptions.RequestException, ValueError, OSError, TypeError, RecursionError) as e:
            return False, f"Ошибка сети или ответа: {type(e).__name__}"

    def send_reliable_message(self, server_url: str, token: str, payload: dict,
                              expected_sender_device_id: str = None) -> Tuple[bool, Any]:
        url_ok, url_err = validate_server_url(server_url)
        if not url_ok:
            return False, url_err
        url = f"{server_url.rstrip('/')}/messages/send-reliable"
        try:
            response = requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"}, timeout=10.0, stream=True, allow_redirects=False)
            try:
                if response.status_code != 200:
                    label = "Not Found" if response.status_code == 404 else "отправка не подтверждена"
                    return False, f"HTTP {response.status_code}: {label}"
                data = _small_response_json(response, MAX_SEND_RESPONSE_BYTES)
                # A matching UUID alone does not establish that the relay
                # accepted the queued envelope. Retain it on malformed or
                # conflicting echoes so a retry never silently drops data.
                fields = ("encrypted_blob", "signature")
                if (isinstance(data, dict) and isinstance(payload, dict)
                        and isinstance(payload.get("client_message_id"), str)
                        and payload["client_message_id"]
                        and data.get("id") == payload["client_message_id"]
                        and all(isinstance(payload.get(key), str) and payload[key]
                                and data.get(key) == payload[key] for key in fields)
                        # Updated relays echo the destination. Missing is
                        # accepted for compatibility with older relays; a
                        # present but conflicting value must never be ignored.
                        and ('receiver_device_id' not in data or
                             (isinstance(payload.get('receiver_device_id'), str)
                              and payload['receiver_device_id']
                              and data['receiver_device_id'] == payload['receiver_device_id']))
                        and (expected_sender_device_id is None or
                             (isinstance(expected_sender_device_id, str) and expected_sender_device_id
                              and data.get("sender_device_id") == expected_sender_device_id))):
                    return True, data
                return False, "Сервер вернул неверное подтверждение сообщения"
            finally:
                response.close()
        except (requests.exceptions.RequestException, ValueError, OSError, TypeError) as e:
            return False, f"Ошибка сети или ответа: {type(e).__name__}"

    def upload_file(self, server_url: str, token: str, file_data: bytes) -> Tuple[bool, Any]:
        url_ok, url_err = validate_server_url(server_url)
        if not url_ok:
            return False, url_err
        if not isinstance(file_data, (bytes, bytearray)) or not 1 <= len(file_data) <= MAX_DOWNLOAD_BYTES:
            return False, "Недопустимый размер вложения"
        url = f"{server_url.rstrip('/')}/files/upload"
        headers = {"Authorization": f"Bearer {token}"}
        files = {"file": ("encrypted_blob.enc", bytes(file_data), "application/octet-stream")}
        try:
            response = requests.post(
                url,
                headers=headers,
                files=files,
                timeout=60.0,
                stream=True,
                allow_redirects=False,
            )
            try:
                if response.status_code == 200:
                    data = (
                        _small_response_json(response, 32 * 1024)
                        if hasattr(response, "iter_content")
                        else response.json()
                    )
                    if isinstance(data, dict) and valid_file_id(data.get("file_id")):
                        return True, data
                    return False, "Сервер вернул неверное подтверждение файла"
                return False, f"HTTP {response.status_code}: загрузка не подтверждена"
            finally:
                close_fn = getattr(response, "close", None)
                if callable(close_fn):
                    close_fn()
        except (requests.exceptions.RequestException, OSError, ValueError, TypeError) as e:
            return False, f"Ошибка сети при загрузке: {type(e).__name__}"

    def upload_file_reliable(self, server_url: str, token: str, file_id: str, path) -> Tuple[bool, Any]:
        """Stream a previously encrypted blob; never fall back to legacy upload."""
        url_ok, url_err = validate_server_url(server_url)
        if not url_ok:
            return False, url_err
        if not valid_file_id(file_id):
            return False, "Недопустимый идентификатор вложения"
        url = f"{server_url.rstrip('/')}/files/upload-reliable/{file_id}"
        try:
            import io
            import os
            stream = io.BytesIO(path) if isinstance(path, bytes) else open(path, "rb")
            with stream as blob:
                size = len(path) if isinstance(path, bytes) else os.fstat(blob.fileno()).st_size
                if not 1 <= size <= MAX_DOWNLOAD_BYTES:
                    return False, "Недопустимый размер вложения"
                response = requests.post(url, headers={"Authorization": f"Bearer {token}",
                                                        "Content-Type": "application/octet-stream"},
                                         data=blob, timeout=60.0, stream=True, allow_redirects=False)
            try:
                if response.status_code != 200:
                    return False, f"HTTP {response.status_code}: загрузка не подтверждена"
                result = _small_response_json(response)
                if (isinstance(result, dict) and result.get("file_id") == file_id
                        and type(result.get("size")) is int and result["size"] == size):
                    return True, result
                return False, "Сервер вернул неверное подтверждение файла"
            finally:
                response.close()
        except (requests.exceptions.RequestException, OSError, ValueError, TypeError) as e:
            return False, f"Ошибка загрузки: {type(e).__name__}"

    def download_file(self, server_url: str, token: str, file_id: str) -> Tuple[bool, Any]:
        url_ok, url_err = validate_server_url(server_url)
        if not url_ok:
            return False, url_err
        if not valid_file_id(file_id):
            return False, "Недопустимый идентификатор вложения"
        url = f"{server_url.rstrip('/')}/files/{file_id}"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.get(url, headers=headers, timeout=60.0, stream=True, allow_redirects=False)
            try:
                if response.status_code != 200:
                    return False, f"HTTP {response.status_code}"
                data = bytearray()
                for chunk in response.iter_content(64 * 1024):
                    if len(data) + len(chunk) > MAX_DOWNLOAD_BYTES:
                        return False, "Вложение превышает лимит загрузки 21 MiB"
                    data.extend(chunk)
                return True, bytes(data)
            finally:
                response.close()
        except (requests.exceptions.RequestException, OSError, ValueError) as e:
            return False, f"Ошибка сети при скачивании: {type(e).__name__}"

    def grant_file_access(self, server_url: str, token: str,
                          file_id: str, recipient_device_id: str) -> Tuple[bool, Any]:
        """Grant one device access; reject oversized or mismatched confirmations."""
        url_ok, url_err = validate_server_url(server_url)
        if not url_ok:
            return False, url_err
        if not valid_file_id(file_id):
            return False, "Недопустимый идентификатор вложения"
        if not isinstance(recipient_device_id, str) or not _SAFE_DEVICE_ID_RE.fullmatch(recipient_device_id):
            return False, "Недопустимый идентификатор устройства получателя"
        url = f"{server_url.rstrip('/')}/files/{file_id}/grant"
        try:
            response = requests.post(url, headers={"Authorization": f"Bearer {token}"},
                                     params={"recipient_device_id": recipient_device_id},
                                     timeout=15.0, stream=True, allow_redirects=False)
            try:
                if response.status_code != 200:
                    return False, f"HTTP {response.status_code}: доступ не подтверждён"
                data = _small_response_json(response)
                if (isinstance(data, dict) and data.get("status") == "ok"
                        and data.get("file_id") == file_id and data.get("granted_to") == recipient_device_id):
                    return True, data
                return False, "Сервер вернул неверное подтверждение доступа"
            finally:
                response.close()
        except (requests.exceptions.RequestException, OSError, ValueError, TypeError) as e:
            return False, f"Ошибка сети или ответа при выдаче доступа: {type(e).__name__}"

api = APIClient()