import requests
import json
from typing import Tuple, Any

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

    def register(self, server_url: str, payload: dict) -> Tuple[bool, Any]:
        url = f"{server_url.rstrip('/')}/auth/register"
        try:
            response = requests.post(url, json=payload, timeout=10.0)
            if response.status_code == 201: return True, response.json()
            return False, self._get_error(response)
        except requests.exceptions.RequestException as e:
            return False, f"Ошибка сети: {type(e).__name__}"

    def login(self, server_url: str, payload: dict) -> Tuple[bool, Any]:
        url = f"{server_url.rstrip('/')}/auth/login"
        try:
            response = requests.post(url, json=payload, timeout=10.0)
            if response.status_code == 200: return True, response.json()
            return False, self._get_error(response)
        except requests.exceptions.RequestException as e:
            return False, f"Ошибка сети: {type(e).__name__}"

    def find_user(self, server_url: str, token: str, target_username: str) -> Tuple[bool, Any]:
        url = f"{server_url.rstrip('/')}/auth/find/{target_username}"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.get(url, headers=headers, timeout=10.0)
            if response.status_code == 200: return True, response.json()
            elif response.status_code == 404: return False, "Союзник не найден."
            return False, f"Ошибка сервера: {response.status_code}"
        except requests.exceptions.RequestException as e:
            return False, f"Ошибка сети: {type(e).__name__}"

    def send_message(self, server_url: str, token: str, payload: dict) -> Tuple[bool, Any]:
        url = f"{server_url.rstrip('/')}/messages/send"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=10.0)
            if response.status_code == 200: return True, response.json()
            return False, f"Ошибка отправки: {self._get_error(response)}"
        except requests.exceptions.RequestException as e:
            return False, f"Ошибка сети: {type(e).__name__}"

    def upload_file(self, server_url: str, token: str, file_data: bytes) -> Tuple[bool, Any]:
        url = f"{server_url.rstrip('/')}/files/upload"
        headers = {"Authorization": f"Bearer {token}"}
        files = {"file": ("encrypted_blob.enc", file_data, "application/octet-stream")}
        try:
            response = requests.post(url, headers=headers, files=files, timeout=60.0)
            if response.status_code == 200: return True, response.json()
            return False, self._get_error(response)
        except requests.exceptions.RequestException as e:
            return False, f"Ошибка сети при загрузке: {type(e).__name__}"

    def download_file(self, server_url: str, token: str, file_id: str) -> Tuple[bool, Any]:
        url = f"{server_url.rstrip('/')}/files/{file_id}"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.get(url, headers=headers, timeout=60.0)
            if response.status_code == 200:
                return True, response.content
            return False, self._get_error(response)
        except requests.exceptions.RequestException as e:
            return False, f"Ошибка сети при скачивании: {type(e).__name__}"

    def grant_file_access(
        self, server_url: str, token: str,
        file_id: str, recipient_device_id: str
    ) -> Tuple[bool, Any]:
        """
        Выдаёт получателю право скачивать файл.

        Безопасность: теперь сервер не отдаёт файлы по UUID без проверки.
        После загрузки картинки мы должны явно разрешить устройству получателя
        её скачать — иначе у него будет file_id, но скачать он не сможет.
        Вызывается сразу после /files/upload, перед отправкой сообщения.
        """
        url = f"{server_url.rstrip('/')}/files/{file_id}/grant"
        headers = {"Authorization": f"Bearer {token}"}
        params = {"recipient_device_id": recipient_device_id}
        try:
            response = requests.post(url, headers=headers, params=params, timeout=15.0)
            if response.status_code == 200:
                return True, response.json()
            return False, self._get_error(response)
        except requests.exceptions.RequestException as e:
            return False, f"Ошибка сети при выдаче доступа: {type(e).__name__}"

api = APIClient()