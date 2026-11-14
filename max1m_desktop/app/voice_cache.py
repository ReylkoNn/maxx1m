"""Encrypted voice cache. Legacy entries are preserved but not trusted as scoped entries."""
import base64
import hashlib
import json
import os
import tempfile
import threading
from pathlib import Path

import keyring
import nacl.secret
import nacl.utils

import re as _re

_VC_INST = _re.sub(r"[^A-Za-z0-9_-]", "", os.environ.get("MAX1M_INSTANCE", "").strip())[:32]
_VC_CUSTOM_DIR = os.environ.get("MAX1M_CLIENT_DATA_DIR", "").strip()

if _VC_CUSTOM_DIR:
    SERVICE_NAME = f"Max1m_Secure_Messenger__{_VC_INST or hashlib.sha256(_VC_CUSTOM_DIR.encode()).hexdigest()[:8]}"
elif _VC_INST and _VC_INST != "1":
    SERVICE_NAME = f"Max1m_Secure_Messenger__inst_{_VC_INST}"
else:
    SERVICE_NAME = "Max1m_Secure_Messenger"
CACHE_KEY_NAME = "voice_cache_encryption_key"
MAX_VOICE_BYTES = 21 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_ENTRIES = 500


def _ensure_private_dir(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix" and not directory.is_symlink():
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass


def _fsync_directory(directory: Path) -> None:
    if os.name != "posix" or not directory.is_dir():
        return
    fd = None
    try:
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        os.fsync(fd)
    except OSError:
        pass
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _digest(values):
    if any(not isinstance(v, str) or not v for v in values):
        raise ValueError("Incomplete voice cache identity")
    return hashlib.sha256(json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


def message_scope(owner, server, chat, msg_id):
    return _digest([owner, server, chat, msg_id])


def asset_scope(file_id, secret_key):
    return _digest([file_id, secret_key])


class VoiceCache:
    def __init__(
        self,
        cache_dir: Path = None,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ):
        if cache_dir is not None:
            self.cache_dir = Path(cache_dir)
            _ensure_private_dir(self.cache_dir)
        else:
            if _VC_CUSTOM_DIR:
                default_root = Path(_VC_CUSTOM_DIR).expanduser().resolve()
            elif _VC_INST and _VC_INST != "1":
                default_root = Path.home() / f".max1m_inst_{_VC_INST}"
            else:
                default_root = Path.home() / ".max1m"
            _ensure_private_dir(default_root)
            self.cache_dir = default_root / "voice_cache"
            _ensure_private_dir(self.cache_dir)
        self.max_total_bytes = max(MAX_VOICE_BYTES + 1024, int(max_total_bytes))
        self.max_entries = max(1, int(max_entries))
        self._box = None
        self._encoded_key = None
        self._lock = threading.RLock()

    def _get_box(self):
        if self._box is not None:
            return self._box
        encoded_key = keyring.get_password(SERVICE_NAME, CACHE_KEY_NAME)
        if encoded_key:
            key_bytes = base64.b64decode(encoded_key, validate=True)
        else:
            # A new key would make existing entries look corrupt. Preserve them
            # until the original keyring is restored, including legacy entries.
            if next(self.cache_dir.glob("*.bin"), None) is not None:
                raise ValueError("Voice cache key is missing; existing cache preserved")
            key_bytes = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
            encoded_new_key = base64.b64encode(key_bytes).decode("ascii")
            keyring.set_password(SERVICE_NAME, CACHE_KEY_NAME, encoded_new_key)
            if keyring.get_password(SERVICE_NAME, CACHE_KEY_NAME) != encoded_new_key:
                raise ValueError("Voice cache key was not persisted")
        self._box = nacl.secret.SecretBox(key_bytes)
        self._encoded_key = base64.b64encode(key_bytes).decode("ascii")
        return self._box

    def _get_path(self, group, asset):
        # Only hashes produced by message_scope/asset_scope are accepted.
        if any(not isinstance(x, str) or len(x) != 64 or any(c not in '0123456789abcdef' for c in x)
               for x in (group, asset)):
            raise ValueError("Invalid cache identity")
        return self.cache_dir / f"v2_{group}_{asset}.bin"

    def load(self, group, asset):
        try:
            path = self._get_path(group, asset)
            if not os.path.lexists(path) or path.is_symlink() or not path.is_file():
                return None
            with self._lock:
                if path.is_symlink() or not path.is_file():
                    return None
                with path.open('rb') as f:
                    encrypted = f.read(MAX_VOICE_BYTES + nacl.secret.SecretBox.NONCE_SIZE + nacl.secret.SecretBox.MACBYTES + 1)
                if len(encrypted) > MAX_VOICE_BYTES + nacl.secret.SecretBox.NONCE_SIZE + nacl.secret.SecretBox.MACBYTES:
                    return None
                plaintext = self._get_box().decrypt(encrypted)
                try:
                    if not path.is_symlink():
                        os.utime(path, None)
                except OSError:
                    pass
                return plaintext
        except Exception as e:
            # Missing/wrong key and corruption are indistinguishable: never delete.
            print(f"[VOICE_CACHE] Кэш недоступен: {type(e).__name__}")
            return None

    def _evict_overflow_locked(self, box: nacl.secret.SecretBox, exclude_path: Path | None = None) -> int:
        """Evict oldest verified-readable v2_*.bin entries to stay within disk bounds.

        Never touches legacy unscoped *.bin files or unreadable/corrupt v2_*.bin
        entries so offline recovery invariants remain intact.
        """
        max_cipher_len = MAX_VOICE_BYTES + nacl.secret.SecretBox.NONCE_SIZE + nacl.secret.SecretBox.MACBYTES
        evictable: list[tuple[float, str, Path, int]] = []
        total_bytes = 0
        total_count = 0

        for entry in self.cache_dir.glob("v2_*.bin"):
            try:
                if entry.is_symlink() or not entry.is_file():
                    continue
                st = entry.stat()
            except OSError:
                continue
            if entry == exclude_path:
                total_bytes += st.st_size
                total_count += 1
                continue
            if st.st_size > max_cipher_len:
                continue
            try:
                with entry.open("rb") as f:
                    raw = f.read(max_cipher_len + 1)
                if len(raw) > max_cipher_len:
                    continue
                box.decrypt(raw)
            except Exception:
                continue
            total_bytes += st.st_size
            total_count += 1
            evictable.append((st.st_mtime, entry.name, entry, st.st_size))

        if total_count <= self.max_entries and total_bytes <= self.max_total_bytes:
            return 0

        evictable.sort(key=lambda item: (item[0], item[1]))
        removed = 0
        for _mtime, _name, victim, sz in evictable:
            if total_count <= self.max_entries and total_bytes <= self.max_total_bytes:
                break
            try:
                victim.unlink(missing_ok=True)
                total_count -= 1
                total_bytes -= sz
                removed += 1
            except OSError:
                continue
        return removed

    def save(self, group, asset, wav_data):
        temp_name = None
        try:
            if not isinstance(wav_data, bytes) or len(wav_data) > MAX_VOICE_BYTES:
                return False
            path = self._get_path(group, asset)
            with self._lock:
                _ensure_private_dir(self.cache_dir)
                if os.path.islink(path):
                    return False
                # Do not overwrite an unreadable entry, which may be recoverable
                # with an old key. This also avoids losing an offline copy.
                if os.path.lexists(path) and self.load(group, asset) is None:
                    return False
                box = self._get_box()
                if keyring.get_password(SERVICE_NAME, CACHE_KEY_NAME) != self._encoded_key:
                    raise ValueError("Voice cache key changed or disappeared")
                encrypted = box.encrypt(wav_data)
                with tempfile.NamedTemporaryFile(dir=self.cache_dir, prefix='.voice-', delete=False) as f:
                    temp_name = f.name
                    if os.name == "posix":
                        try:
                            os.fchmod(f.fileno(), 0o600)
                        except OSError:
                            pass
                    f.write(encrypted)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(temp_name, path)
                temp_name = None
                self._evict_overflow_locked(box, exclude_path=path)
                _fsync_directory(self.cache_dir)
            return True
        except Exception as e:
            print(f"[VOICE_CACHE] Ошибка сохранения: {type(e).__name__}")
            return False
        finally:
            if temp_name is not None:
                Path(temp_name).unlink(missing_ok=True)

    def delete_group(self, group):
        if not isinstance(group, str) or len(group) != 64 or any(c not in '0123456789abcdef' for c in group):
            raise ValueError("Invalid cache identity")
        removed = False
        with self._lock:
            for path in self.cache_dir.glob(f"v2_{group}_*.bin"):
                if path.is_symlink() or path.is_file():
                    path.unlink(missing_ok=True)
                    removed = True
            if removed:
                _fsync_directory(self.cache_dir)

    def clear(self):
        removed = False
        with self._lock:
            for file in self.cache_dir.glob("*.bin"):
                if file.is_symlink() or file.is_file():
                    file.unlink(missing_ok=True)
                    removed = True
            if removed:
                _fsync_directory(self.cache_dir)

    def get_cache_size_mb(self):
        total = 0
        for f in self.cache_dir.glob("*.bin"):
            try:
                if not f.is_symlink() and f.is_file():
                    total += f.stat().st_size
            except OSError:
                continue
        return round(total / (1024 * 1024), 2)


voice_cache = VoiceCache()
