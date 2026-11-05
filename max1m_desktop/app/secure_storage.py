import keyring
import json
import base64
import uuid
from pathlib import Path
from typing import List, Dict, Optional
import nacl.secret
import nacl.utils
import nacl.exceptions

SERVICE_NAME = "Max1m_Secure_Messenger"
BASE_DIR = Path.home() / ".max1m"
CONFIG_FILE = BASE_DIR / "local_state.json"


class SecureStorage:
    @staticmethod
    def _get_user_dir(username: str) -> Path:
        if not username:
            username = "default_user"
        user_dir = BASE_DIR / "profiles" / username
        user_dir.mkdir(parents=True, exist_ok=True)
        return user_dir

    @staticmethod
    def _get_allies_file(username: str) -> Path:
        return SecureStorage._get_user_dir(username) / "allies.json"

    @staticmethod
    def _get_messages_file(my_username: str, ally_username: str) -> Path:
        safe_name = "".join(c for c in ally_username if c.isalnum() or c in "_-")
        msg_dir = SecureStorage._get_user_dir(my_username) / "messages"
        msg_dir.mkdir(parents=True, exist_ok=True)
        return msg_dir / f"{safe_name}.enc"

    @staticmethod
    def save_private_key(username: str, private_key_b64: str):
        keyring.set_password(SERVICE_NAME, f"{username}_privkey", private_key_b64)

    @staticmethod
    def get_private_key(username: str) -> str | None:
        return keyring.get_password(SERVICE_NAME, f"{username}_privkey")

    @staticmethod
    def _get_or_create_local_key(username: str) -> bytes:
        if not username:
            raise ValueError("[SECURITY] Попытка получить ключ для пустого username!")
        key_name = f"{username}_local_storage_key"
        encoded_key = keyring.get_password(SERVICE_NAME, key_name)
        if encoded_key:
            return base64.b64decode(encoded_key)
        new_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        keyring.set_password(SERVICE_NAME, key_name, base64.b64encode(new_key).decode('utf-8'))
        return new_key

    @staticmethod
    def save_local_state(state_dict: dict):
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(state_dict, f, indent=4)

    @staticmethod
    def load_local_state() -> dict:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    @staticmethod
    def save_allies(my_username: str, allies_dict: dict):
        if not my_username:
            my_username = SecureStorage.load_local_state().get("username")
        if not my_username:
            return
        allies_file = SecureStorage._get_allies_file(my_username)
        with open(allies_file, "w", encoding="utf-8") as f:
            json.dump(allies_dict, f, indent=4, ensure_ascii=False)

    @staticmethod
    def load_allies(my_username: str) -> dict:
        if not my_username:
            my_username = SecureStorage.load_local_state().get("username")
        if not my_username:
            return {}
        allies_file = SecureStorage._get_allies_file(my_username)
        if allies_file.exists():
            try:
                with open(allies_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    @staticmethod
    def _save_messages_to_file(my_username: str, ally_username: str, messages: List[Dict]):
        messages_file = SecureStorage._get_messages_file(my_username, ally_username)
        json_data = json.dumps(messages, ensure_ascii=False).encode('utf-8')
        local_key = SecureStorage._get_or_create_local_key(my_username)
        box = nacl.secret.SecretBox(local_key)
        with open(messages_file, "wb") as f:
            f.write(box.encrypt(json_data))

    @staticmethod
    def save_message(
            my_username: str,
            ally_username: str,
            text: str,
            is_mine: bool,
            timestamp: str = None,
            msg_id: str = None,
            is_read: bool = False,
            reply_to_msg_id: str = None,
            reply_to_text: str = None,
            reply_to_sender: str = None
    ) -> bool:
        from datetime import datetime
        if not my_username:
            return False
        messages = SecureStorage.load_messages(my_username, ally_username)
        if msg_id:
            if any(m.get("msg_id") == msg_id for m in messages):
                return False
        else:
            msg_id = f"local_{uuid.uuid4().hex[:12]}"
        message_data = {
            "msg_id": msg_id,
            "text": text,
            "is_mine": is_mine,
            "is_read": is_read,
            "timestamp": timestamp or datetime.now().isoformat(),
            "deleted": False
        }
        if reply_to_msg_id:
            message_data["reply_to_msg_id"] = reply_to_msg_id
            message_data["reply_to_text"] = reply_to_text
            message_data["reply_to_sender"] = reply_to_sender
        messages.append(message_data)
        SecureStorage._save_messages_to_file(my_username, ally_username, messages)
        return True

    @staticmethod
    def load_messages(my_username: str, ally_username: str) -> List[Dict]:
        if not my_username:
            return []
        messages_file = SecureStorage._get_messages_file(my_username, ally_username)
        if not messages_file.exists():
            return []
        try:
            with open(messages_file, "rb") as f:
                encrypted_data = f.read()
            local_key = SecureStorage._get_or_create_local_key(my_username)
            box = nacl.secret.SecretBox(local_key)
            decrypted_data = box.decrypt(encrypted_data)
            messages = json.loads(decrypted_data.decode('utf-8'))
            return [m for m in messages if not m.get("deleted", False)]
        except (nacl.exceptions.CryptoError, json.JSONDecodeError, IOError):
            return []

    @staticmethod
    def delete_message(my_username: str, ally_username: str, msg_id: str) -> bool:
        if not my_username:
            return False
        messages_file = SecureStorage._get_messages_file(my_username, ally_username)
        if not messages_file.exists():
            return False
        try:
            with open(messages_file, "rb") as f:
                encrypted_data = f.read()
            local_key = SecureStorage._get_or_create_local_key(my_username)
            box = nacl.secret.SecretBox(local_key)
            decrypted_data = box.decrypt(encrypted_data)
            messages = json.loads(decrypted_data.decode('utf-8'))
            changed = False
            for msg in messages:
                if msg.get("msg_id") == msg_id:
                    msg["deleted"] = True
                    msg["text"] = ""
                    changed = True
                    break
            if changed:
                SecureStorage._save_messages_to_file(my_username, ally_username, messages)
                return True
            return False
        except Exception:
            return False

    @staticmethod
    def get_unread_incoming_msg_ids(my_username: str, ally_username: str) -> List[str]:
        messages = SecureStorage.load_messages(my_username, ally_username)
        return [m.get("msg_id") for m in messages if not m.get("is_mine") and not m.get("is_read") and m.get("msg_id")]

    @staticmethod
    def mark_messages_as_read(my_username: str, ally_username: str, msg_ids: List[str]) -> bool:
        if not my_username:
            return False
        messages_file = SecureStorage._get_messages_file(my_username, ally_username)
        if not messages_file.exists():
            return False
        try:
            with open(messages_file, "rb") as f:
                encrypted_data = f.read()
            local_key = SecureStorage._get_or_create_local_key(my_username)
            box = nacl.secret.SecretBox(local_key)
            decrypted_data = box.decrypt(encrypted_data)
            messages = json.loads(decrypted_data.decode('utf-8'))
            changed = False
            for msg in messages:
                if msg.get("msg_id") in msg_ids and not msg.get("is_read"):
                    msg["is_read"] = True
                    changed = True
            if changed:
                SecureStorage._save_messages_to_file(my_username, ally_username, messages)
            return changed
        except Exception:
            return False

    @staticmethod
    def clear_chat(my_username: str, ally_username: str) -> bool:
        messages_file = SecureStorage._get_messages_file(my_username, ally_username)
        if messages_file.exists():
            messages_file.unlink()
            return True
        return False

    @staticmethod
    def search_messages(my_username: str, ally_username: str, query: str) -> List[Dict]:
        if not query or not my_username:
            return []
        messages = SecureStorage.load_messages(my_username, ally_username)
        query_lower = query.lower()
        results = []
        for msg in messages:
            text = msg.get("text", "")
            if query_lower in text.lower():
                results.append(msg)
        return results


storage = SecureStorage()