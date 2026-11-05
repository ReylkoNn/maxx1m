"""
app/voice_cache.py

Persistent encrypted cache для голосовых сообщений.

Модель безопасности:
  - Ключ шифрования кэша генерируется один раз и хранится в системном keyring
    (рядом с приватными ключами и local_storage_key)
  - На диске хранятся только зашифрованные .bin файлы (NaCl SecretBox)
  - Имена файлов — SHA-256 от msg_id (не угадываемо без доступа к БД)
  - Без keyring — кэш нечитаем, даже при полном доступе к диску
"""

import base64
import hashlib
from pathlib import Path

import keyring
import nacl.exceptions
import nacl.secret
import nacl.utils

SERVICE_NAME = "Max1m_Secure_Messenger"
CACHE_KEY_NAME = "voice_cache_encryption_key"


class VoiceCache:
    def __init__(self, cache_dir: Path = None):
        if cache_dir is None:
            from pathlib import Path as _Path
            cache_dir = _Path.home() / ".max1m" / "voice_cache"

        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._box: nacl.secret.SecretBox | None = None

    # ------------------------------------------------------------------
    # Внутреннее: ключ шифрования
    # ------------------------------------------------------------------

    def _get_box(self) -> nacl.secret.SecretBox:
        """
        Возвращает SecretBox для шифрования/расшифровки кэша.
        Ключ хранится в системном keyring — так же, как приватные E2EE ключи.
        Создаётся один раз при первом запуске.
        """
        if self._box is not None:
            return self._box

        encoded_key = keyring.get_password(SERVICE_NAME, CACHE_KEY_NAME)

        if encoded_key:
            key_bytes = base64.b64decode(encoded_key)
        else:
            # Первый запуск — генерируем ключ и сохраняем в keyring
            key_bytes = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
            keyring.set_password(
                SERVICE_NAME,
                CACHE_KEY_NAME,
                base64.b64encode(key_bytes).decode("utf-8")
            )
            print("[VOICE_CACHE] Новый ключ шифрования кэша сохранён в keyring")

        self._box = nacl.secret.SecretBox(key_bytes)
        return self._box

    # ------------------------------------------------------------------
    # Внутреннее: пути к файлам
    # ------------------------------------------------------------------

    def _get_path(self, msg_id: str) -> Path:
        """
        Имя файла = первые 32 символа SHA-256 от msg_id.
        Расширение .bin — явно не WAV, не открывается медиаплеерами.
        """
        safe_name = hashlib.sha256(msg_id.encode("utf-8")).hexdigest()[:32]
        return self.cache_dir / f"{safe_name}.bin"

    # ------------------------------------------------------------------
    # Публичный API
    # ------------------------------------------------------------------

    def exists(self, msg_id: str) -> bool:
        """Есть ли файл в кэше?"""
        return self._get_path(msg_id).exists()

    def save(self, msg_id: str, wav_data: bytes) -> bool:
        """
        Шифрует WAV-данные и сохраняет на диск.
        Возвращает True при успехе.
        """
        try:
            box = self._get_box()
            encrypted = box.encrypt(wav_data)
            self._get_path(msg_id).write_bytes(encrypted)
            print(f"[VOICE_CACHE] Сохранено (зашифровано): {msg_id[:16]}...")
            return True
        except Exception as e:
            print(f"[VOICE_CACHE] Ошибка сохранения: {e}")
            return False

    def load(self, msg_id: str) -> bytes | None:
        """
        Загружает и расшифровывает WAV из кэша.
        Если файл повреждён — удаляет его и возвращает None.
        """
        path = self._get_path(msg_id)
        if not path.exists():
            return None
        try:
            box = self._get_box()
            encrypted = path.read_bytes()
            wav_data = box.decrypt(encrypted)
            print(f"[VOICE_CACHE] Загружено из кэша: {msg_id[:16]}...")
            return wav_data
        except nacl.exceptions.CryptoError:
            # Файл повреждён или ключ сменился — удаляем
            print(f"[VOICE_CACHE] Ошибка расшифровки, удаляем: {msg_id[:16]}...")
            path.unlink(missing_ok=True)
            return None
        except Exception as e:
            print(f"[VOICE_CACHE] Неожиданная ошибка: {e}")
            return None

    def delete(self, msg_id: str):
        """Удаляет файл из кэша (например, при удалении сообщения)"""
        path = self._get_path(msg_id)
        if path.exists():
            path.unlink()
            print(f"[VOICE_CACHE] Удалено из кэша: {msg_id[:16]}...")

    def clear(self):
        """Полная очистка кэша (для настроек)"""
        count = 0
        for file in self.cache_dir.glob("*.bin"):
            file.unlink()
            count += 1
        print(f"[VOICE_CACHE] Кэш очищен: удалено {count} файлов")

    def get_cache_size_mb(self) -> float:
        """Размер кэша в МБ (для отображения в настройках)"""
        total = sum(f.stat().st_size for f in self.cache_dir.glob("*.bin"))
        return round(total / (1024 * 1024), 2)


# Глобальный экземпляр — импортируется везде
voice_cache = VoiceCache()