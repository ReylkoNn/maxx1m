"""
Group E2EE — Sender Keys (как Signal).

Каждый участник группы генерирует свой SenderKey (симметричный ключ)
и рассылает его всем участникам зашифрованным их публичными ключами.

Сообщения шифруются SenderKey отправителя — один blob для всей группы.
Сервер слепой — видит только encrypted_blob + signature.
"""

import os
import json
import base64
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
from app.crypto_box import crypto


class GroupCrypto:

    def generate_sender_key(self) -> dict:
        """
        Генерирует новый SenderKey для участника группы.
        Возвращает:
            {
                "key_id": str,      # случайный ID ключа
                "key": str,         # base64 симметричный ключ
                "chain_index": int  # счётчик сообщений (для forward secrecy)
            }
        """
        key = nacl_random(32)
        key_id = os.urandom(16).hex()
        return {
            "key_id": key_id,
            "key": base64.b64encode(key).decode(),
            "chain_index": 0
        }

    def encrypt_sender_key_for_member(
            self,
            sender_key: dict,
            member_public_key_b64: str
    ) -> tuple[str, str]:
        """
        Шифрует SenderKey для конкретного участника через Curve25519 Box.
        Возвращает (encrypted_blob, signature).

        Получатель сможет верифицировать подпись и расшифровать.
        """
        payload = json.dumps(sender_key, ensure_ascii=False)
        result = crypto.encrypt_message(payload, member_public_key_b64)
        return result["encrypted_blob"], result["signature"]

    def decrypt_sender_key(
            self,
            encrypted_blob: str,
            signature: str,
            sender_public_key_b64: str
    ) -> dict | None:
        """
        Расшифровывает SenderKey полученный от участника группы.
        Верифицирует подпись перед расшифровкой.
        Возвращает dict или None при ошибке.
        """
        try:
            # Верификация подписи
            if not crypto.verify_signature(encrypted_blob, signature, sender_public_key_b64):
                print("[GROUP CRYPTO] ⚠️ Подпись SenderKey не прошла проверку!")
                return None

            # Расшифровка
            decrypted_json = crypto.decrypt_message(encrypted_blob, sender_public_key_b64)
            return json.loads(decrypted_json)
        except Exception as e:
            print(f"[GROUP CRYPTO] Ошибка расшифровки SenderKey: {e}")
            return None

    def encrypt_group_message(self, text: str, sender_key: dict) -> dict:
        """
        Шифрует сообщение группы своим SenderKey.
        Возвращает:
            {
                "key_id": str,       # ID текущего ключа
                "chain_index": int,  # счётчик до инкремента
                "blob": str          # base64 зашифрованный payload
            }
        """
        key_bytes = base64.b64decode(sender_key["key"])
        box = SecretBox(key_bytes)

        payload = json.dumps({
            "text": text,
            "chain_index": sender_key["chain_index"]
        }, ensure_ascii=False).encode("utf-8")

        encrypted = box.encrypt(payload)
        current_index = sender_key["chain_index"]
        sender_key["chain_index"] += 1  # инкремент для forward secrecy

        return {
            "key_id": sender_key["key_id"],
            "chain_index": current_index,
            "blob": base64.b64encode(encrypted).decode()
        }

    def decrypt_group_message(
            self,
            encrypted: dict,
            sender_key: dict
    ) -> str | None:
        """
        Расшифровывает групповое сообщение SenderKey отправителя.
        Возвращает текст или None при ошибке.
        """
        try:
            key_bytes = base64.b64decode(sender_key["key"])
            box = SecretBox(key_bytes)
            blob = base64.b64decode(encrypted["blob"])
            decrypted = box.decrypt(blob)
            payload = json.loads(decrypted.decode("utf-8"))
            return payload["text"]
        except Exception as e:
            print(f"[GROUP CRYPTO] Ошибка расшифровки сообщения: {e}")
            return None


group_crypto = GroupCrypto()