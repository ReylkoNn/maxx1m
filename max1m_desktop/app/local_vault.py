"""
Anti-Forensic Local Vault, Plausibly-Deniable Duress PIN, Panic Wipe, and Auto-Lock.

Security guarantees against physical device seizure:
1. Zero OS Keyring Exposure:
   When enabled for a profile, both `<username>_local_storage_key` and
   `<username>_privkey` are purged from the OS keyring (Windows Credential Manager /
   macOS Keychain / Linux SecretService) and wrapped inside `vault.enc` under a
   memory-hard `libsodium` Argon2id key (`nacl.pwhash.argon2id.kdf`).
2. Volatile Mutable RAM Storage:
   Unwrapped keys live strictly in process RAM inside mutable `bytearray` buffers
   that are explicitly zero-filled (`buf[:] = b"\\x00" * len(buf)`) upon lock,
   inactivity timeout, logout, or panic wipe.
3. Plausibly-Deniable Duress Slot:
   Every `vault.enc` contains two Argon2id salts and two fixed-size XSalsa20-Poly1305
   ciphertexts (`wrapped_keys` and `duress_slot`). When no Duress PIN is configured,
   `duress_slot` is encrypted under a discarded CSPRNG 32-byte key over a 64-byte
   block — making the presence or absence of a Duress PIN computationally
   indistinguishable on disk. Entering the Duress PIN immediately overwrites and
   destroys all local profile keys, histories, queues, and caches.
"""

import base64
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import threading
import time
from typing import Dict, Optional, Tuple

import keyring
import nacl.exceptions
from nacl.pwhash import argon2id
import nacl.secret
import nacl.utils

from app.crypto_box import pad_traffic_bytes, unpad_traffic_bytes

DEFAULT_OPSLIMIT = int(argon2id.OPSLIMIT_MODERATE)
DEFAULT_MEMLIMIT = int(argon2id.MEMLIMIT_MODERATE)
MIN_OPSLIMIT = int(argon2id.OPSLIMIT_INTERACTIVE)
MIN_MEMLIMIT = int(argon2id.MEMLIMIT_INTERACTIVE)
MAX_VAULT_FILE_BYTES = 64 * 1024
DURESS_TOKEN_LEN = 64
DURESS_MAGIC_PREFIX = b"MAX1M_DURESS_V1:"


class VaultLockedError(RuntimeError):
    """Raised when encrypted profile storage is accessed while Local Vault is locked."""


class VaultAuthenticationError(ValueError):
    """Raised when an invalid Master Password is supplied to Local Vault."""


class _UnlockedSlot:
    __slots__ = ("local_key", "private_key_utf8", "unlocked_at", "auto_lock_seconds")

    def __init__(self, local_key: bytes, private_key_b64: str, auto_lock_seconds: int = 0):
        if len(local_key) != 32:
            raise ValueError("Invalid 32-byte local storage key")
        raw_priv = private_key_b64.encode("ascii")
        self.local_key = bytearray(local_key)
        self.private_key_utf8 = bytearray(raw_priv)
        self.unlocked_at = time.monotonic()
        self.auto_lock_seconds = max(0, int(auto_lock_seconds))

    def zeroize(self) -> None:
        for buf in (self.local_key, self.private_key_utf8):
            for i in range(len(buf)):
                buf[i] = 0


_VAULT_LOCK = threading.RLock()
_UNLOCKED_VAULTS: Dict[str, _UnlockedSlot] = {}
_LAST_ACTIVITY_MONOTONIC: float = time.monotonic()


def record_user_activity() -> None:
    global _LAST_ACTIVITY_MONOTONIC
    _LAST_ACTIVITY_MONOTONIC = time.monotonic()


def idle_seconds() -> float:
    return max(0.0, time.monotonic() - _LAST_ACTIVITY_MONOTONIC)


def _zeroize_bytearray(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def _derive_kek(password: str, salt: bytes, opslimit: int, memlimit: int) -> bytearray:
    if not isinstance(password, str) or not password:
        raise ValueError("Пароль сейфа не может быть пустым")
    if len(salt) != argon2id.SALTBYTES:
        raise ValueError("Invalid Argon2id salt length")
    pw_bytes = bytearray(password.encode("utf-8"))
    try:
        derived = argon2id.kdf(
            nacl.secret.SecretBox.KEY_SIZE,
            bytes(pw_bytes),
            salt,
            opslimit=int(opslimit),
            memlimit=int(memlimit),
        )
        return bytearray(derived)
    finally:
        _zeroize_bytearray(pw_bytes)


def _build_duress_plaintext(username: str) -> bytes:
    prefix = DURESS_MAGIC_PREFIX + username.encode("utf-8") + b"\x00"
    if len(prefix) > DURESS_TOKEN_LEN:
        raise ValueError("Username too long for duress token")
    return prefix + (b"\x00" * (DURESS_TOKEN_LEN - len(prefix)))


def _verify_duress_plaintext(decrypted: bytes, username: str) -> bool:
    if len(decrypted) != DURESS_TOKEN_LEN:
        return False
    expected = _build_duress_plaintext(username)
    # Constant-time byte comparison
    diff = 0
    for a, b in zip(decrypted, expected):
        diff |= a ^ b
    return diff == 0


def _vault_file_for_user(username: str) -> Path:
    from app.secure_storage import SecureStorage

    return SecureStorage._get_user_dir(username) / "vault.enc"


def is_vault_enabled(username: str) -> bool:
    if not isinstance(username, str) or not username:
        return False
    try:
        vfile = _vault_file_for_user(username)
        return os.path.lexists(vfile)
    except Exception:
        return False


def is_vault_unlocked(username: str) -> bool:
    with _VAULT_LOCK:
        return username in _UNLOCKED_VAULTS


def get_unlocked_local_key(username: str) -> Optional[bytes]:
    with _VAULT_LOCK:
        slot = _UNLOCKED_VAULTS.get(username)
        if slot is None:
            return None
        return bytes(slot.local_key)


def get_unlocked_private_key(username: str) -> Optional[str]:
    with _VAULT_LOCK:
        slot = _UNLOCKED_VAULTS.get(username)
        if slot is None:
            return None
        return bytes(slot.private_key_utf8).decode("ascii")


def get_vault_auto_lock_seconds(username: str) -> int:
    with _VAULT_LOCK:
        slot = _UNLOCKED_VAULTS.get(username)
        if slot is not None:
            return slot.auto_lock_seconds
    try:
        rec = _read_vault_envelope(username)
        return max(0, int(rec.get("auto_lock_seconds", 0) or 0))
    except Exception:
        return 0


def lock_vault(username: str) -> None:
    with _VAULT_LOCK:
        slot = _UNLOCKED_VAULTS.pop(username, None)
        if slot is not None:
            slot.zeroize()


def lock_all_vaults() -> None:
    with _VAULT_LOCK:
        slots = list(_UNLOCKED_VAULTS.values())
        _UNLOCKED_VAULTS.clear()
        for s in slots:
            s.zeroize()


def _purge_os_keyring_entries(username: str) -> None:
    from app.secure_storage import SERVICE_NAME

    for suffix in ("_local_storage_key", "_privkey"):
        kname = f"{username}{suffix}"
        try:
            keyring.delete_password(SERVICE_NAME, kname)
        except Exception:
            # Fallback if mock or platform backend lacks delete_password
            try:
                if keyring.get_password(SERVICE_NAME, kname) is not None:
                    keyring.set_password(SERVICE_NAME, kname, "")
            except Exception:
                pass


def secure_wipe_file(path: Path) -> None:
    """Two-pass overwrite (CSPRNG + zeros) + fsync before unlinking a single-link regular file."""
    fd = None
    try:
        st_pre = os.lstat(path)
        if os.path.islink(path) or not stat.S_ISREG(st_pre.st_mode):
            os.unlink(path)
            return
        if st_pre.st_nlink == 1 and st_pre.st_size > 0:
            flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            st_fd = os.fstat(fd)
            if stat.S_ISREG(st_fd.st_mode) and st_fd.st_nlink == 1 and st_fd.st_ino == st_pre.st_ino:
                capped_size = min(st_fd.st_size, 64 * 1024 * 1024)
                for pass_zero in (False, True):
                    os.lseek(fd, 0, os.SEEK_SET)
                    rem = capped_size
                    zero_buf = b"\x00" * 65536
                    while rem > 0:
                        step = min(65536, rem)
                        chunk = zero_buf[:step] if pass_zero else os.urandom(step)
                        written = os.write(fd, chunk)
                        if written <= 0:
                            break
                        rem -= written
                    os.fsync(fd)
    except OSError:
        pass
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    try:
        os.unlink(path)
    except OSError:
        pass


def secure_wipe_directory_tree(root: Path) -> int:
    """Recursively shred all files under `root` and remove the directory tree."""
    wiped_files = 0
    if not os.path.lexists(root):
        return 0
    if os.path.islink(root) or not root.is_dir():
        secure_wipe_file(root)
        return 1
    for dirpath, _dirnames, filenames in os.walk(root, topdown=False, followlinks=False):
        dp = Path(dirpath)
        for fname in filenames:
            secure_wipe_file(dp / fname)
            wiped_files += 1
        try:
            os.rmdir(dp)
        except OSError:
            shutil.rmtree(dp, ignore_errors=True)
    return wiped_files


def _read_vault_envelope(username: str) -> dict:
    vfile = _vault_file_for_user(username)
    if os.path.islink(vfile):
        raise ValueError("Vault file must not be a symlink")
    with vfile.open("rb") as f:
        raw = f.read(MAX_VAULT_FILE_BYTES + 1)
    if len(raw) > MAX_VAULT_FILE_BYTES:
        raise ValueError("Vault file exceeds size limit")
    rec = json.loads(raw.decode("utf-8"))
    if (
        not isinstance(rec, dict)
        or rec.get("version") != 1
        or rec.get("owner") != username
        or not isinstance(rec.get("master_salt"), str)
        or not isinstance(rec.get("wrapped_keys"), str)
        or not isinstance(rec.get("duress_salt"), str)
        or not isinstance(rec.get("duress_slot"), str)
    ):
        raise ValueError("Invalid vault envelope")
    opslimit = rec.get("opslimit")
    memlimit = rec.get("memlimit")
    if (
        isinstance(opslimit, bool)
        or not isinstance(opslimit, int)
        or opslimit < 1
        or isinstance(memlimit, bool)
        or not isinstance(memlimit, int)
        or memlimit < 8192
    ):
        raise ValueError("Unsafe vault KDF parameters")
    return rec


def enable_local_vault(
    username: str,
    master_password: str,
    *,
    duress_password: Optional[str] = None,
    auto_lock_seconds: int = 300,
    opslimit: int = DEFAULT_OPSLIMIT,
    memlimit: int = DEFAULT_MEMLIMIT,
) -> None:
    """Wrap profile keys under Argon2id `vault.enc` and purge them from OS keyring."""
    from app.secure_storage import (
        SERVICE_NAME,
        SecureStorage,
        _fsync_directory,
        _restrict_file_permissions,
    )

    if not isinstance(username, str) or not username:
        raise ValueError("Не указан профиль")
    if not isinstance(master_password, str) or len(master_password) < 8:
        raise ValueError("Мастер-пароль сейфа должен содержать минимум 8 символов")
    if duress_password is not None and duress_password != "":
        if not isinstance(duress_password, str) or len(duress_password) < 6:
            raise ValueError("Пароль под принуждением должен содержать минимум 6 символов")
        if duress_password == master_password:
            raise ValueError("Пароль под принуждением должен отличаться от мастер-пароля")

    with _VAULT_LOCK:
        # Retrieve active keys (either from already-unlocked vault or OS keyring)
        local_key = get_unlocked_local_key(username)
        priv_b64 = get_unlocked_private_key(username)

        if local_key is None:
            local_key = SecureStorage._get_or_create_local_key(username)
        if priv_b64 is None:
            priv_b64 = keyring.get_password(SERVICE_NAME, f"{username}_privkey")
        if not isinstance(priv_b64, str) or not priv_b64.strip():
            raise ValueError("Приватный ключ устройства не найден для переноса в сейф")
        priv_b64 = priv_b64.strip()

        master_salt = nacl.utils.random(argon2id.SALTBYTES)
        duress_salt = nacl.utils.random(argon2id.SALTBYTES)

        master_kek = _derive_kek(master_password, master_salt, opslimit, memlimit)
        duress_kek: Optional[bytearray] = None
        try:
            inner_bytes = json.dumps(
                {
                    "v": 1,
                    "owner": username,
                    "local_storage_key": base64.b64encode(local_key).decode("ascii"),
                    "private_key": priv_b64,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            padded_inner = pad_traffic_bytes(inner_bytes)
            wrapped_keys = bytes(nacl.secret.SecretBox(bytes(master_kek)).encrypt(padded_inner))

            if duress_password:
                duress_kek = _derive_kek(duress_password, duress_salt, opslimit, memlimit)
                duress_pt = _build_duress_plaintext(username)
                duress_ct = bytes(nacl.secret.SecretBox(bytes(duress_kek)).encrypt(duress_pt))
            else:
                # Plausible deniability: encrypt random 64-byte block under discarded random key!
                discarded_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
                duress_ct = bytes(
                    nacl.secret.SecretBox(discarded_key).encrypt(nacl.utils.random(DURESS_TOKEN_LEN))
                )
        finally:
            _zeroize_bytearray(master_kek)
            if duress_kek is not None:
                _zeroize_bytearray(duress_kek)

        vfile = _vault_file_for_user(username)
        envelope = {
            "version": 1,
            "owner": username,
            "opslimit": int(opslimit),
            "memlimit": int(memlimit),
            "auto_lock_seconds": max(0, int(auto_lock_seconds)),
            "master_salt": base64.b64encode(master_salt).decode("ascii"),
            "wrapped_keys": base64.b64encode(wrapped_keys).decode("ascii"),
            "duress_salt": base64.b64encode(duress_salt).decode("ascii"),
            "duress_slot": base64.b64encode(duress_ct).decode("ascii"),
        }

        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=vfile.parent, delete=False) as f:
                temp_name = f.name
                json.dump(envelope, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            _restrict_file_permissions(Path(temp_name))
            os.replace(temp_name, vfile)
            _restrict_file_permissions(vfile)
            _fsync_directory(vfile.parent)
        finally:
            if temp_name and os.path.exists(temp_name):
                os.unlink(temp_name)

        old_slot = _UNLOCKED_VAULTS.pop(username, None)
        if old_slot is not None:
            old_slot.zeroize()
        _UNLOCKED_VAULTS[username] = _UnlockedSlot(
            local_key=local_key,
            private_key_b64=priv_b64,
            auto_lock_seconds=max(0, int(auto_lock_seconds)),
        )
        record_user_activity()

        # Purge raw keys from OS keyring AND scrub plaintext session token from local_state.json!
        _purge_os_keyring_entries(username)
        try:
            st = SecureStorage.load_local_state()
            if st.get("username") == username and "token" in st:
                st.pop("token", None)
                SecureStorage.save_local_state(st)
        except Exception:
            pass


def unlock_vault(username: str, password: str) -> str:
    """
    Unlock `vault.enc` into RAM.
    Returns:
      - `"unlocked"` when `password` matches the Master Password;
      - `"duress_wiped"` when `password` matches the Duress Password (after wiping profile!).
    Raises `VaultAuthenticationError` on wrong password.
    """
    if not isinstance(password, str) or not password:
        raise VaultAuthenticationError("Введите мастер-пароль сейфа")

    rec = _read_vault_envelope(username)
    opslimit = int(rec["opslimit"])
    memlimit = int(rec["memlimit"])
    auto_lock_sec = max(0, int(rec.get("auto_lock_seconds", 0) or 0))
    master_salt = base64.b64decode(rec["master_salt"].encode("ascii"), validate=True)
    duress_salt = base64.b64decode(rec["duress_salt"].encode("ascii"), validate=True)
    wrapped_ct = base64.b64decode(rec["wrapped_keys"].encode("ascii"), validate=True)
    duress_ct = base64.b64decode(rec["duress_slot"].encode("ascii"), validate=True)

    # Always compute BOTH KDFs in uniform order so timing never reveals which slot matched.
    duress_kek = _derive_kek(password, duress_salt, opslimit, memlimit)
    master_kek = _derive_kek(password, master_salt, opslimit, memlimit)
    try:
        is_duress = False
        try:
            duress_pt = nacl.secret.SecretBox(bytes(duress_kek)).decrypt(duress_ct)
            if _verify_duress_plaintext(duress_pt, username):
                is_duress = True
        except nacl.exceptions.CryptoError:
            is_duress = False

        if is_duress:
            execute_panic_wipe(username)
            return "duress_wiped"

        try:
            padded_inner = nacl.secret.SecretBox(bytes(master_kek)).decrypt(wrapped_ct)
            inner = json.loads(unpad_traffic_bytes(padded_inner).decode("utf-8"))
        except (nacl.exceptions.CryptoError, UnicodeDecodeError, ValueError) as exc:
            raise VaultAuthenticationError("Неверный мастер-пароль локального сейфа") from exc

        if not isinstance(inner, dict) or inner.get("owner") != username:
            raise VaultAuthenticationError("Повреждённый контейнер локального сейфа")

        lk_raw = base64.b64decode(inner["local_storage_key"].encode("ascii"), validate=True)
        priv_b64 = str(inner["private_key"]).strip()
        if len(lk_raw) != 32 or not priv_b64:
            raise VaultAuthenticationError("Некорректные ключи внутри локального сейфа")

        with _VAULT_LOCK:
            old = _UNLOCKED_VAULTS.pop(username, None)
            if old is not None:
                old.zeroize()
            _UNLOCKED_VAULTS[username] = _UnlockedSlot(
                local_key=lk_raw,
                private_key_b64=priv_b64,
                auto_lock_seconds=auto_lock_sec,
            )
            record_user_activity()
        return "unlocked"
    finally:
        _zeroize_bytearray(duress_kek)
        _zeroize_bytearray(master_kek)


def disable_local_vault(username: str, password: str) -> str:
    """Verify Master Password (or trigger wipe on Duress Password!), restore keys to OS keyring, and shred `vault.enc`."""
    from app.secure_storage import SERVICE_NAME, _fsync_directory

    outcome = unlock_vault(username, password)
    if outcome == "duress_wiped":
        return "duress_wiped"

    with _VAULT_LOCK:
        lk = get_unlocked_local_key(username)
        priv = get_unlocked_private_key(username)
        if lk is None or priv is None:
            raise VaultLockedError("Сейф не разблокирован")

        lk_b64 = base64.b64encode(lk).decode("ascii")
        keyring.set_password(SERVICE_NAME, f"{username}_local_storage_key", lk_b64)
        keyring.set_password(SERVICE_NAME, f"{username}_privkey", priv)
        if (
            keyring.get_password(SERVICE_NAME, f"{username}_local_storage_key") != lk_b64
            or keyring.get_password(SERVICE_NAME, f"{username}_privkey") != priv
        ):
            raise RuntimeError("Системный keyring не сохранил ключи; отключение сейфа отменено")

        vfile = _vault_file_for_user(username)
        parent = vfile.parent
        secure_wipe_file(vfile)
        _fsync_directory(parent)
        lock_vault(username)
    return "disabled"


def execute_panic_wipe(username: Optional[str] = None, *, wipe_all_profiles: bool = False) -> int:
    """
    Emergency cryptographic + multi-pass file destruction.
    Zeroes RAM keys, clears `crypto`, purges keyring entries, shreds profile files,
    shreds voice_cache, and scrubs `local_state.json`.
    """
    from app import secure_storage
    from app.crypto_box import crypto as global_crypto
    from app.secure_storage import SecureStorage, _fsync_directory

    if wipe_all_profiles or not username:
        lock_all_vaults()
    else:
        lock_vault(username)

    try:
        global_crypto.clear()
    except Exception:
        pass

    wiped_count = 0
    base_dir = secure_storage.BASE_DIR
    profiles_dir = base_dir / "profiles"

    target_users = []
    if wipe_all_profiles:
        if profiles_dir.is_dir():
            for child in profiles_dir.iterdir():
                if child.is_dir():
                    target_users.append(child.name)
    elif isinstance(username, str) and username:
        target_users.append(username)

    for uname in target_users:
        _purge_os_keyring_entries(uname)
        user_dir = profiles_dir / uname
        wiped_count += secure_wipe_directory_tree(user_dir)
    if profiles_dir.is_dir():
        _fsync_directory(profiles_dir)

    # Shred voice_cache directory as well
    vcache_dir = base_dir / "voice_cache"
    if os.path.lexists(vcache_dir):
        wiped_count += secure_wipe_directory_tree(vcache_dir)

    # Scrub local_state.json if it belonged to a wiped user (or wipe_all_profiles)
    cfg = secure_storage.CONFIG_FILE
    if os.path.lexists(cfg):
        try:
            st = SecureStorage.load_local_state()
            if wipe_all_profiles or st.get("username") in target_users:
                secure_wipe_file(cfg)
                wiped_count += 1
                _fsync_directory(base_dir)
        except Exception:
            secure_wipe_file(cfg)
            wiped_count += 1

    return wiped_count
