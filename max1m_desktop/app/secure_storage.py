import keyring
import json
import base64
import errno
import hashlib
import time
import uuid
import os
import tempfile
import re
import hmac
import threading
from functools import wraps
from pathlib import Path
from typing import List, Dict, Optional
import nacl.secret
import nacl.utils
import nacl.exceptions

_RAW_INST = re.sub(r"[^A-Za-z0-9_-]", "", os.environ.get("MAX1M_INSTANCE", "").strip())[:32]
_CUSTOM_CLIENT_DIR = os.environ.get("MAX1M_CLIENT_DATA_DIR", "").strip()

if _CUSTOM_CLIENT_DIR:
    BASE_DIR = Path(_CUSTOM_CLIENT_DIR).expanduser().resolve()
    _inst_tag = _RAW_INST or hashlib.sha256(str(BASE_DIR).encode("utf-8")).hexdigest()[:8]
    SERVICE_NAME = f"Max1m_Secure_Messenger__{_inst_tag}"
elif _RAW_INST and _RAW_INST != "1":
    BASE_DIR = Path.home() / f".max1m_inst_{_RAW_INST}"
    SERVICE_NAME = f"Max1m_Secure_Messenger__inst_{_RAW_INST}"
else:
    SERVICE_NAME = "Max1m_Secure_Messenger"
    BASE_DIR = Path.home() / ".max1m"

CONFIG_FILE = BASE_DIR / "local_state.json"
MAX_GROUPS_INDEX_BYTES = 1024 * 1024
MAX_GROUPS_INDEX_ENTRIES = 1000
MAX_ALLIES_INDEX_BYTES = 4 * 1024 * 1024
MAX_DEVICE_IDENTITY_BYTES = 64 * 1024
MAX_LOCAL_STATE_BYTES = 64 * 1024


def _restrict_dir_permissions(directory: Path) -> None:
    """Best-effort 0o700 restriction on POSIX so other local OS users cannot list profile/chat metadata."""
    if os.name == "nt":
        return
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass


def _restrict_file_permissions(file_path: Path) -> None:
    """Best-effort 0o600 restriction on POSIX for local state and encrypted index files."""
    if os.name == "nt":
        return
    try:
        os.chmod(file_path, 0o600)
    except OSError:
        pass


def _fsync_directory(directory: Path) -> None:
    """Best-effort POSIX directory entry flush after atomic rename/unlink."""
    if os.name == "nt":
        return
    fd = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        fd = os.open(directory, flags)
        os.fsync(fd)
    except OSError:
        pass
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _safe_fsync_fd(fd: int) -> None:
    """Flush file descriptor to storage; tolerate Windows filter/volume quirks after flush()."""
    try:
        os.fsync(fd)
    except OSError as exc:
        winerr = getattr(exc, "winerror", None)
        if os.name == "nt" and (exc.errno == errno.EINVAL or winerr in (1, 5, 6, 50, 87)):
            return
        raise


def _atomic_replace_file(src: str | Path, dst: str | Path) -> None:
    """
    Atomically replace `dst` with `src`, retrying brief Windows Defender (`WdFilter.sys`)
    or indexer sharing locks (`WinError 5` / `WinError 32` / `EACCES`) on newly closed files.
    """
    delays = (0.005, 0.01, 0.02, 0.03, 0.05, 0.07, 0.1, 0.12)
    for attempt in range(len(delays) + 1):
        try:
            os.replace(src, dst)
            return
        except OSError as exc:
            winerr = getattr(exc, "winerror", None)
            retryable = isinstance(exc, PermissionError) or exc.errno == errno.EACCES or winerr in (5, 32)
            if not retryable or attempt >= len(delays):
                raise
            time.sleep(delays[attempt])


def _unlink_temp_quietly(temp_path: str | Path | None) -> None:
    """Best-effort cleanup of a leftover temp file in `finally:` without masking outcomes."""
    if not temp_path:
        return
    for delay in (0.0, 0.01, 0.03):
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            return
        except OSError:
            if delay:
                time.sleep(delay)


# Fixed-size lock striping avoids an unbounded lock map. A whole profile is
# serialized because its key and catalog are shared by all chats. This only
# coordinates threads in this process, not old clients or external programs.
_PROFILE_LOCKS = tuple(threading.RLock() for _ in range(64))
_REVISION_LOCK = threading.Lock()
_PROFILE_REVISIONS = [0] * len(_PROFILE_LOCKS)
_PROFILE_WRITES = [0] * len(_PROFILE_LOCKS)
_MUTATIONS = frozenset({"_save_messages_to_file", "save_message", "delete_message",
                        "delete_message_with_meta", "delete_incoming_message",
                        "mark_messages_as_read", "clear_chat", "purge_expired_messages"})


def history_revision(owner):
    index = hash(owner) % len(_PROFILE_LOCKS) if isinstance(owner, str) else 0
    with _REVISION_LOCK:
        return _PROFILE_REVISIONS[index], _PROFILE_WRITES[index]


def _change_revision(index, delta):
    with _REVISION_LOCK:
        _PROFILE_REVISIONS[index] += 1
        _PROFILE_WRITES[index] += delta


def _profile_locked(fn):
    @wraps(fn)
    def locked(*args, **kwargs):
        owner = args[0] if args else kwargs.get("my_username", kwargs.get("username"))
        if not owner and fn.__name__ in {"save_allies", "load_allies"}:
            owner = SecureStorage.load_local_state().get("username")
            if not owner:
                if fn.__name__ == "load_allies":
                    return {}
                raise ValueError("Missing username")
            # Pin the same resolved account for both locking and file access.
            if args:
                args = (owner, *args[1:])
            else:
                kwargs = {**kwargs, "my_username": owner}
        index = hash(owner) % len(_PROFILE_LOCKS) if isinstance(owner, str) else 0
        lock = _PROFILE_LOCKS[index]
        cancel = kwargs.get("cancel")
        if cancel is None and fn.__name__ == "load_history_page" and len(args) > 5:
            cancel = args[5]
        if cancel is None:
            lock.acquire()
        else:
            from app.history_paging import check_cancel
            while not lock.acquire(timeout=0.05):
                check_cancel(cancel)
        mutation = fn.__name__ in _MUTATIONS
        started = False
        try:
            if cancel is not None:
                from app.history_paging import check_cancel
                check_cancel(cancel)
            if mutation:
                _change_revision(index, 1)  # Invalidate scans before any write starts.
                started = True
            return fn(*args, **kwargs)
        finally:
            if started:
                _change_revision(index, -1)  # Also invalidate after uncertain failures.
            lock.release()
    return locked


class SecureStorage:
    @staticmethod
    def _get_user_dir(username: str) -> Path:
        if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_]{1,50}", username):
            raise ValueError("Invalid local profile name")
        profiles_root = BASE_DIR / "profiles"
        user_dir = profiles_root / username
        user_dir.mkdir(parents=True, exist_ok=True)
        _restrict_dir_permissions(BASE_DIR)
        _restrict_dir_permissions(profiles_root)
        _restrict_dir_permissions(user_dir)
        return user_dir

    @staticmethod
    def _get_allies_file(username: str) -> Path:
        return SecureStorage._get_user_dir(username) / "allies.json"

    @staticmethod
    def _get_encrypted_allies_file(username: str) -> Path:
        return SecureStorage._get_user_dir(username) / "allies.enc"

    @staticmethod
    def _get_device_identity_file(username: str) -> Path:
        return SecureStorage._get_user_dir(username) / "device_identity.enc"

    @staticmethod
    def _get_groups_file(username: str) -> Path:
        return SecureStorage._get_user_dir(username) / "groups.enc"

    @staticmethod
    def _get_group_keys_file(username: str) -> Path:
        return SecureStorage._get_user_dir(username) / "group_keys.enc"

    @staticmethod
    def _get_tls_pins_file(username: str) -> Path:
        return SecureStorage._get_user_dir(username) / "tls_pins.enc"

    @staticmethod
    def _valid_group_id(group_id: str) -> bool:
        return isinstance(group_id, str) and bool(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", group_id))

    @staticmethod
    def _get_messages_file(my_username: str, ally_username: str) -> Path:
        # Do not silently strip characters: different chat identifiers could
        # otherwise resolve to the same encrypted history and overwrite it.
        if not isinstance(ally_username, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", ally_username):
            raise ValueError("Invalid chat history identifier")
        safe_name = ally_username
        msg_dir = SecureStorage._get_user_dir(my_username) / "messages"
        msg_dir.mkdir(parents=True, exist_ok=True)
        _restrict_dir_permissions(msg_dir)
        return msg_dir / f"{safe_name}.enc"

    @staticmethod
    def _vault_file_present(username: str) -> bool:
        return isinstance(username, str) and bool(username) and os.path.lexists(
            BASE_DIR / "profiles" / username / "vault.enc"
        )

    @staticmethod
    def _load_local_vault_mod():
        try:
            from app import local_vault as lv
            return lv
        except ModuleNotFoundError:
            import importlib.util
            cb_spec = importlib.util.spec_from_file_location("app.crypto_box", Path(__file__).with_name("crypto_box.py"))
            cb_mod = importlib.util.module_from_spec(cb_spec)
            import sys as _sys
            _sys.modules.setdefault("app.crypto_box", cb_mod)
            cb_spec.loader.exec_module(cb_mod)
            lv_spec = importlib.util.spec_from_file_location("app.local_vault", Path(__file__).with_name("local_vault.py"))
            lv_mod = importlib.util.module_from_spec(lv_spec)
            lv_spec.loader.exec_module(lv_mod)
            return lv_mod

    @staticmethod
    @_profile_locked
    def save_private_key(username: str, private_key_b64: str):
        SecureStorage._get_user_dir(username)  # Validate profile before touching keyring.
        if SecureStorage._vault_file_present(username):
            lv = SecureStorage._load_local_vault_mod()
            if lv.is_vault_enabled(username):
                unlocked_priv = lv.get_unlocked_private_key(username)
                if unlocked_priv is None:
                    raise lv.VaultLockedError("Локальный сейф профиля заблокирован")
                if unlocked_priv != private_key_b64:
                    raise ValueError("Refusing to replace an existing private key")
                return
        key_name = f"{username}_privkey"
        existing = keyring.get_password(SERVICE_NAME, key_name)
        if existing is not None and existing != private_key_b64:
            raise ValueError("Refusing to replace an existing private key")
        if existing is None:
            keyring.set_password(SERVICE_NAME, key_name, private_key_b64)
            if keyring.get_password(SERVICE_NAME, key_name) != private_key_b64:
                raise ValueError("Private key was not persisted")

    @staticmethod
    @_profile_locked
    def get_private_key(username: str) -> str | None:
        if SecureStorage._vault_file_present(username):
            lv = SecureStorage._load_local_vault_mod()
            if lv.is_vault_enabled(username):
                unlocked_priv = lv.get_unlocked_private_key(username)
                if unlocked_priv is None:
                    raise lv.VaultLockedError("Локальный сейф профиля заблокирован")
                return unlocked_priv
        return keyring.get_password(SERVICE_NAME, f"{username}_privkey")

    @staticmethod
    @_profile_locked
    def _get_or_create_local_key(username: str) -> bytes:
        if not username:
            raise ValueError("[SECURITY] Попытка получить ключ для пустого username!")
        if SecureStorage._vault_file_present(username):
            lv = SecureStorage._load_local_vault_mod()
            if lv.is_vault_enabled(username):
                unlocked_lk = lv.get_unlocked_local_key(username)
                if unlocked_lk is None:
                    raise lv.VaultLockedError("Локальный сейф профиля заблокирован")
                return unlocked_lk
        key_name = f"{username}_local_storage_key"
        encoded_key = keyring.get_password(SERVICE_NAME, key_name)
        if encoded_key:
            decoded = base64.b64decode(encoded_key, validate=True)
            if len(decoded) != nacl.secret.SecretBox.KEY_SIZE:
                raise ValueError("Invalid local storage key")
            return decoded
        profile = SecureStorage._get_user_dir(username)
        history = profile / "messages"
        outbox_dir = profile / "outbox"
        if ((history.exists() and (any(history.glob("*.enc"))
                                  or any(p.is_file() for p in history.glob("*.sqlite3*"))))
                or (profile / "history_catalog.enc").exists()
                or (profile / "groups.enc").exists()
                or (profile / "group_keys.enc").exists()
                or (profile / "tls_pins.enc").exists()
                or (profile / "allies.enc").exists()
                or (profile / "device_identity.enc").exists()
                or (outbox_dir.exists() and any(p.is_file() for p in outbox_dir.rglob("*")))):
            raise ValueError("Local storage key is missing while encrypted data exists")
        new_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        encoded_new_key = base64.b64encode(new_key).decode('utf-8')
        keyring.set_password(SERVICE_NAME, key_name, encoded_new_key)
        # Never encrypt durable data with a key that was not actually saved.
        if keyring.get_password(SERVICE_NAME, key_name) != encoded_new_key:
            raise ValueError("Local storage key was not persisted")
        return new_key

    @staticmethod
    def save_local_state(state_dict: dict):
        if not isinstance(state_dict, dict):
            raise ValueError("Invalid local state")
        to_write = dict(state_dict)
        if "tls_spki_pins" not in to_write and CONFIG_FILE.exists():
            try:
                prev = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                if isinstance(prev, dict) and isinstance(prev.get("tls_spki_pins"), dict) and prev["tls_spki_pins"]:
                    to_write["tls_spki_pins"] = prev["tls_spki_pins"]
            except Exception:
                pass
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        _restrict_dir_permissions(BASE_DIR)
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=BASE_DIR, delete=False) as f:
                temp_name = f.name
                json.dump(to_write, f, indent=4)
                f.flush()
                _safe_fsync_fd(f.fileno())
            _restrict_file_permissions(Path(temp_name))
            _atomic_replace_file(temp_name, CONFIG_FILE)
            _restrict_file_permissions(CONFIG_FILE)
            _fsync_directory(BASE_DIR)
        finally:
            _unlink_temp_quietly(temp_name)

    @staticmethod
    def load_local_state() -> dict:
        if CONFIG_FILE.exists():
            with CONFIG_FILE.open("rb") as f:
                raw = f.read(MAX_LOCAL_STATE_BYTES + 1)
            if len(raw) > MAX_LOCAL_STATE_BYTES:
                raise ValueError("Local state file is too large")
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, RecursionError) as exc:
                raise ValueError("Invalid local state") from exc
            if not isinstance(parsed, dict):
                raise ValueError("Invalid local state")
            return parsed
        return {}

    @staticmethod
    def _decrypt_allies_file(my_username: str, enc_file: Path) -> dict:
        with enc_file.open("rb") as f:
            raw = f.read(MAX_ALLIES_INDEX_BYTES + 1)
        if len(raw) > MAX_ALLIES_INDEX_BYTES:
            raise ValueError("Encrypted contact store is too large")
        box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(my_username))
        try:
            record = json.loads(box.decrypt(raw).decode("utf-8"))
        except (nacl.exceptions.CryptoError, UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise ValueError("Invalid contact store") from exc
        if (not isinstance(record, dict)
                or record.get("version") != 1
                or record.get("owner") != my_username
                or not isinstance(record.get("allies"), dict)):
            raise ValueError("Invalid contact store")
        return record["allies"]

    @staticmethod
    @_profile_locked
    def save_allies(my_username: str, allies_dict: dict):
        if not my_username:
            my_username = SecureStorage.load_local_state().get("username")
        if not my_username:
            raise ValueError("Missing username")
        allies_file = SecureStorage._get_allies_file(my_username)
        enc_file = SecureStorage._get_encrypted_allies_file(my_username)
        if not isinstance(allies_dict, dict):
            raise ValueError("Invalid contact store")
        if enc_file.exists():
            # Never overwrite a damaged or foreign encrypted trust store.
            SecureStorage._decrypt_allies_file(my_username, enc_file)
        elif allies_file.exists():
            # Do not overwrite a damaged legacy trust store with an empty/new one.
            with allies_file.open("r", encoding="utf-8") as existing:
                if not isinstance(json.load(existing), dict):
                    raise ValueError("Invalid contact store")
        box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(my_username))
        envelope = {"version": 1, "owner": my_username, "allies": allies_dict}
        encrypted = box.encrypt(
            json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        if len(encrypted) > MAX_ALLIES_INDEX_BYTES:
            raise ValueError("Contact store exceeds size limit")
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(dir=enc_file.parent, delete=False) as f:
                temp_name = f.name
                f.write(encrypted)
                f.flush()
                _safe_fsync_fd(f.fileno())
            _atomic_replace_file(temp_name, enc_file)
            _fsync_directory(enc_file.parent)
        finally:
            _unlink_temp_quietly(temp_name)

    @staticmethod
    @_profile_locked
    def load_allies(my_username: str) -> dict:
        if not my_username:
            my_username = SecureStorage.load_local_state().get("username")
        if not my_username:
            return {}
        enc_file = SecureStorage._get_encrypted_allies_file(my_username)
        if enc_file.exists():
            return SecureStorage._decrypt_allies_file(my_username, enc_file)
        allies_file = SecureStorage._get_allies_file(my_username)
        if allies_file.exists():
            with open(allies_file, "r", encoding="utf-8") as f:
                contacts = json.load(f)
            if not isinstance(contacts, dict):
                raise ValueError("Invalid contact store")
            return contacts
        return {}

    @staticmethod
    @_profile_locked
    def load_profile_device(my_username: str) -> Optional[dict]:
        if not my_username:
            return None
        path = SecureStorage._get_device_identity_file(my_username)
        if not path.exists():
            return None
        with path.open("rb") as f:
            raw = f.read(MAX_DEVICE_IDENTITY_BYTES + 1)
        if len(raw) > MAX_DEVICE_IDENTITY_BYTES:
            raise ValueError("Invalid profile device identity")
        box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(my_username))
        try:
            record = json.loads(box.decrypt(raw).decode("utf-8"))
        except (nacl.exceptions.CryptoError, UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise ValueError("Invalid profile device identity") from exc
        server_url = record.get("server_url") if isinstance(record, dict) else None
        device_id = record.get("device_id") if isinstance(record, dict) else None
        device_name = record.get("device_name", "") if isinstance(record, dict) else None
        public_key = record.get("public_key") if isinstance(record, dict) else None
        if (not isinstance(record, dict)
                or record.get("version") != 1
                or record.get("owner") != my_username
                or not isinstance(server_url, str) or not server_url.strip()
                or not isinstance(device_id, str) or not 1 <= len(device_id) <= 64
                or not isinstance(device_name, str)
                or (public_key is not None and not isinstance(public_key, str))):
            raise ValueError("Invalid profile device identity")
        return {
            "server_url": server_url.rstrip("/"),
            "device_id": device_id,
            "device_name": device_name,
            "public_key": public_key,
        }

    @staticmethod
    @_profile_locked
    def save_profile_device(
        my_username: str,
        server_url: str,
        device_id: str,
        device_name: str = "",
        public_key: Optional[str] = None,
    ) -> None:
        if (not isinstance(my_username, str) or not my_username
                or not isinstance(server_url, str) or not server_url.strip()
                or not isinstance(device_id, str) or not 1 <= len(device_id) <= 64):
            raise ValueError("Invalid profile device parameters")
        clean_server = server_url.rstrip("/")
        path = SecureStorage._get_device_identity_file(my_username)
        if path.exists():
            existing = SecureStorage.load_profile_device(my_username)
            if (existing["server_url"] != clean_server
                    or existing["device_id"] != device_id
                    or (existing.get("public_key") and public_key and existing["public_key"] != public_key)):
                raise ValueError("Conflicting profile device identity")
        box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(my_username))
        envelope = {
            "version": 1,
            "owner": my_username,
            "server_url": clean_server,
            "device_id": device_id,
            "device_name": device_name or "",
            "public_key": public_key,
        }
        encrypted = box.encrypt(
            json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        if len(encrypted) > MAX_DEVICE_IDENTITY_BYTES:
            raise ValueError("Profile device identity too large")
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
                temp_name = f.name
                f.write(encrypted)
                f.flush()
                _safe_fsync_fd(f.fileno())
            _atomic_replace_file(temp_name, path)
            _fsync_directory(path.parent)
        finally:
            _unlink_temp_quietly(temp_name)

    @staticmethod
    @_profile_locked
    def load_groups_index(my_username: str) -> dict:
        if not my_username:
            return {}
        groups_file = SecureStorage._get_groups_file(my_username)
        if not os.path.lexists(groups_file):
            return {}
        with groups_file.open("rb") as f:
            encrypted = f.read(MAX_GROUPS_INDEX_BYTES + 1)
        if len(encrypted) > MAX_GROUPS_INDEX_BYTES:
            raise ValueError("Groups index exceeds size limit")
        local_key = SecureStorage._get_or_create_local_key(my_username)
        record = json.loads(nacl.secret.SecretBox(local_key).decrypt(encrypted).decode("utf-8"))
        if (not isinstance(record, dict) or set(record) != {"version", "owner", "groups"}
                or record["version"] != 1 or record["owner"] != my_username
                or not isinstance(record["groups"], dict)
                or len(record["groups"]) > MAX_GROUPS_INDEX_ENTRIES):
            raise ValueError("Invalid groups index")
        cleaned = {}
        for gid, meta in record["groups"].items():
            if (not SecureStorage._valid_group_id(gid) or not isinstance(meta, dict)
                    or not set(meta).issubset({"name", "created_by_device_id", "archived"})):
                raise ValueError("Invalid group index entry")
            name = meta.get("name", "")
            creator = meta.get("created_by_device_id", "")
            archived = meta.get("archived", False)
            if (not isinstance(name, str) or len(name) > 200
                    or not isinstance(creator, str) or len(creator) > 64
                    or not isinstance(archived, bool)):
                raise ValueError("Invalid group index entry")
            cleaned[gid] = {
                "name": name,
                "created_by_device_id": creator,
                "archived": archived,
            }
        return cleaned

    @staticmethod
    @_profile_locked
    def save_groups_index(my_username: str, groups_dict: dict):
        if not my_username:
            raise ValueError("Missing username")
        if not isinstance(groups_dict, dict) or len(groups_dict) > MAX_GROUPS_INDEX_ENTRIES:
            raise ValueError("Invalid groups index")
        cleaned = {}
        for gid, meta in groups_dict.items():
            if not SecureStorage._valid_group_id(gid) or not isinstance(meta, dict):
                raise ValueError("Invalid group index entry")
            name = meta.get("name", "")
            creator = meta.get("created_by_device_id", "")
            archived = bool(meta.get("archived", False))
            if not isinstance(name, str) or not isinstance(creator, str):
                raise ValueError("Invalid group index entry")
            cleaned[gid] = {
                "name": name[:200],
                "created_by_device_id": creator[:64],
                "archived": archived,
            }
        groups_file = SecureStorage._get_groups_file(my_username)
        if os.path.lexists(groups_file):
            # Refuse to overwrite an unreadable or corrupt local group index.
            SecureStorage.load_groups_index(my_username)
        elif not cleaned:
            return
        local_key = SecureStorage._get_or_create_local_key(my_username)
        payload = json.dumps(
            {"version": 1, "owner": my_username, "groups": cleaned},
            ensure_ascii=False, separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
        encrypted = bytes(nacl.secret.SecretBox(local_key).encrypt(payload))
        if len(encrypted) > MAX_GROUPS_INDEX_BYTES:
            raise ValueError("Groups index exceeds size limit")
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(dir=groups_file.parent, delete=False) as f:
                temp_name = f.name
                f.write(encrypted)
                f.flush()
                _safe_fsync_fd(f.fileno())
            _atomic_replace_file(temp_name, groups_file)
            _fsync_directory(groups_file.parent)
        finally:
            _unlink_temp_quietly(temp_name)

    @staticmethod
    @_profile_locked
    def load_group_keys(my_username: str) -> dict:
        if not my_username:
            return {}
        keys_file = SecureStorage._get_group_keys_file(my_username)
        if not os.path.lexists(keys_file):
            return {}
        max_bytes = 8 * 1024 * 1024
        with keys_file.open("rb") as f:
            encrypted = f.read(max_bytes + 1)
        if len(encrypted) > max_bytes:
            raise ValueError("Group keys store exceeds size limit")
        local_key = SecureStorage._get_or_create_local_key(my_username)
        record = json.loads(nacl.secret.SecretBox(local_key).decrypt(encrypted).decode("utf-8"))
        if (
            not isinstance(record, dict)
            or record.get("version") != 1
            or record.get("owner") != my_username
            or not isinstance(record.get("groups"), dict)
            or len(record["groups"]) > MAX_GROUPS_INDEX_ENTRIES
        ):
            raise ValueError("Invalid group keys store")
        out = {}
        for gid, gstate in record["groups"].items():
            if not SecureStorage._valid_group_id(gid) or not isinstance(gstate, dict):
                raise ValueError("Invalid group key entry")
            out[gid] = {
                "epoch": int(gstate.get("epoch", 1) or 1),
                "my_sender_key": gstate.get("my_sender_key"),
                "sender_keys": gstate.get("sender_keys") if isinstance(gstate.get("sender_keys"), dict) else {},
                "distributed_epoch": int(gstate.get("distributed_epoch", 0) or 0),
            }
        return out

    @staticmethod
    @_profile_locked
    def save_group_keys(my_username: str, groups_state: dict) -> None:
        if not my_username:
            raise ValueError("Missing username")
        if not isinstance(groups_state, dict) or len(groups_state) > MAX_GROUPS_INDEX_ENTRIES:
            raise ValueError("Invalid group keys state")
        cleaned = {}
        for gid, meta in groups_state.items():
            if not SecureStorage._valid_group_id(gid) or not isinstance(meta, dict):
                continue
            my_sk = meta.get("my_sender_key")
            peer_sks = meta.get("sender_keys") if isinstance(meta.get("sender_keys"), dict) else {}
            epoch = int(meta.get("epoch", 1) or 1)
            dist_epoch = int(meta.get("distributed_epoch", 0) or 0)
            if my_sk is None and not peer_sks and epoch <= 1:
                continue
            cleaned[gid] = {
                "epoch": epoch,
                "my_sender_key": my_sk,
                "sender_keys": peer_sks,
                "distributed_epoch": dist_epoch,
            }
        keys_file = SecureStorage._get_group_keys_file(my_username)
        if os.path.lexists(keys_file):
            SecureStorage.load_group_keys(my_username)
        elif not cleaned:
            return
        local_key = SecureStorage._get_or_create_local_key(my_username)
        payload = json.dumps(
            {"version": 1, "owner": my_username, "groups": cleaned},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        max_bytes = 8 * 1024 * 1024
        encrypted = bytes(nacl.secret.SecretBox(local_key).encrypt(payload))
        if len(encrypted) > max_bytes:
            raise ValueError("Group keys store exceeds size limit")
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(dir=keys_file.parent, delete=False) as f:
                temp_name = f.name
                f.write(encrypted)
                f.flush()
                _safe_fsync_fd(f.fileno())
            _restrict_file_permissions(Path(temp_name))
            _atomic_replace_file(temp_name, keys_file)
            _restrict_file_permissions(keys_file)
            _fsync_directory(keys_file.parent)
        finally:
            _unlink_temp_quietly(temp_name)

    @staticmethod
    @_profile_locked
    def load_tls_pins(my_username: str) -> Dict[str, List[str]]:
        if not my_username:
            return {}
        pins_file = SecureStorage._get_tls_pins_file(my_username)
        if not os.path.lexists(pins_file):
            return {}
        if os.path.islink(pins_file):
            raise ValueError("TLS pins store must not be a symlink")
        max_bytes = 256 * 1024
        with pins_file.open("rb") as f:
            encrypted = f.read(max_bytes + 1)
        if len(encrypted) > max_bytes:
            raise ValueError("TLS pins store exceeds size limit")
        local_key = SecureStorage._get_or_create_local_key(my_username)
        record = json.loads(nacl.secret.SecretBox(local_key).decrypt(encrypted).decode("utf-8"))
        if (
            not isinstance(record, dict)
            or record.get("version") != 1
            or record.get("owner") != my_username
            or not isinstance(record.get("pins"), dict)
            or len(record["pins"]) > 256
        ):
            raise ValueError("Invalid TLS pins store")
        from app.tls_pinning import normalize_host, normalize_spki_pin

        out: Dict[str, List[str]] = {}
        for raw_host, pin_list in record["pins"].items():
            if not isinstance(raw_host, str) or not isinstance(pin_list, list) or len(pin_list) > 16:
                raise ValueError("Invalid TLS pin entry")
            norm_h = normalize_host(raw_host)
            cleaned_pins = [normalize_spki_pin(p) for p in pin_list]
            if cleaned_pins:
                out[norm_h] = sorted(set(cleaned_pins))
        return out

    @staticmethod
    @_profile_locked
    def save_tls_pins(my_username: str, pins_by_host: Dict[str, List[str]]) -> None:
        if not my_username:
            raise ValueError("Missing username")
        if not isinstance(pins_by_host, dict) or len(pins_by_host) > 256:
            raise ValueError("Invalid TLS pins map")
        from app.tls_pinning import normalize_host, normalize_spki_pin

        cleaned: Dict[str, List[str]] = {}
        for raw_host, pin_list in pins_by_host.items():
            if not isinstance(raw_host, str) or not isinstance(pin_list, list) or len(pin_list) > 16:
                raise ValueError("Invalid TLS pin entry")
            norm_h = normalize_host(raw_host)
            vals = sorted({normalize_spki_pin(p) for p in pin_list if isinstance(p, str) and p.strip()})
            if vals:
                cleaned[norm_h] = vals

        pins_file = SecureStorage._get_tls_pins_file(my_username)
        if os.path.lexists(pins_file):
            SecureStorage.load_tls_pins(my_username)
        local_key = SecureStorage._get_or_create_local_key(my_username)
        payload = json.dumps(
            {"version": 1, "owner": my_username, "pins": cleaned},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        encrypted = bytes(nacl.secret.SecretBox(local_key).encrypt(payload))
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(dir=pins_file.parent, delete=False) as f:
                temp_name = f.name
                f.write(encrypted)
                f.flush()
                _safe_fsync_fd(f.fileno())
            _restrict_file_permissions(Path(temp_name))
            _atomic_replace_file(temp_name, pins_file)
            _restrict_file_permissions(pins_file)
            _fsync_directory(pins_file.parent)
        finally:
            _unlink_temp_quietly(temp_name)

        # Mirror to local_state.json so pre-login /auth/login requests also enforce the pin!
        try:
            st = SecureStorage.load_local_state()
            st["tls_spki_pins"] = cleaned
            SecureStorage.save_local_state(st)
        except Exception:
            pass

    @staticmethod
    @_profile_locked
    def list_local_group_ids(my_username: str) -> List[str]:
        """Read-only discovery of local group_<id> histories without modifying files."""
        if not my_username:
            return []
        profile = SecureStorage._get_user_dir(my_username)
        msg_dir = profile / "messages"
        found = set()
        if msg_dir.exists():
            for path in msg_dir.glob("group_*.enc"):
                if not path.is_file():
                    continue
                gid = path.stem[len("group_"):]
                if SecureStorage._valid_group_id(gid) and len(f"group_{gid}") <= 80:
                    found.add(gid)
        catalog_path = profile / "history_catalog.enc"
        if os.path.lexists(catalog_path):
            from app.history_activation import read_catalog
            local_key = SecureStorage._get_or_create_local_key(my_username)
            for chat in read_catalog(catalog_path, local_key, my_username):
                if chat.startswith("group_"):
                    gid = chat[len("group_"):]
                    if SecureStorage._valid_group_id(gid) and len(chat) <= 80:
                        found.add(gid)
        return sorted(found)

    @staticmethod
    @_profile_locked
    def _save_messages_to_file(my_username: str, ally_username: str, messages: List[Dict]):
        from app.history_activation import active_adapter
        with active_adapter(my_username, ally_username) as active:
            if active is not None:
                raise ValueError("Refusing to overwrite legacy backup of an active history")
        messages_file = SecureStorage._get_messages_file(my_username, ally_username)
        json_data = json.dumps(messages, ensure_ascii=False).encode('utf-8')
        local_key = SecureStorage._get_or_create_local_key(my_username)
        box = nacl.secret.SecretBox(local_key)
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(dir=messages_file.parent, delete=False) as f:
                temp_name = f.name
                f.write(box.encrypt(json_data))
                f.flush()
                _safe_fsync_fd(f.fileno())
            _atomic_replace_file(temp_name, messages_file)
            _fsync_directory(messages_file.parent)
        finally:
            _unlink_temp_quietly(temp_name)

    @staticmethod
    @_profile_locked
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
            reply_to_sender: str = None,
            expires_at: int = None,
            sender_name: str = None
    ) -> bool:
        from datetime import datetime
        if not my_username:
            return False
        from app.history_activation import active_adapter
        with active_adapter(my_username, ally_username) as active:
            if active is not None:
                return active.save_message(my_username, ally_username, text, is_mine, timestamp, msg_id,
                                           is_read, reply_to_msg_id, reply_to_text, reply_to_sender,
                                           expires_at=expires_at, sender_name=sender_name)
        messages = SecureStorage._load_all_messages(my_username, ally_username)
        if not msg_id:
            msg_id = f"local_{uuid.uuid4().hex[:12]}"
        message_data = {
            "msg_id": msg_id,
            "text": text,
            "is_mine": is_mine,
            "is_read": is_read,
            "timestamp": timestamp or datetime.now().isoformat(),
            "deleted": False
        }
        if isinstance(sender_name, str) and sender_name:
            message_data["sender_name"] = sender_name
        if reply_to_msg_id:
            message_data["reply_to_msg_id"] = reply_to_msg_id
            message_data["reply_to_text"] = reply_to_text
            message_data["reply_to_sender"] = reply_to_sender
        if isinstance(expires_at, (int, float)) and not isinstance(expires_at, bool) and expires_at > 0:
            message_data["expires_at"] = int(expires_at)
        matches = [m for m in messages if m.get("msg_id") == msg_id]
        if matches:
            if len(matches) != 1:
                raise ValueError("Ambiguous message id")
            from app.history_store import content_identity
            key = SecureStorage._get_or_create_local_key(my_username)
            existing = matches[0]
            cand_identity = content_identity(key, my_username, ally_username, message_data)
            if existing.get("deleted", False):
                identity = existing.get("_legacy_content_identity")
                if not isinstance(identity, str) or not re.fullmatch(r'[0-9a-f]{64}', identity):
                    raise ValueError("Cannot verify deleted message retry")
            else:
                identity = content_identity(key, my_username, ally_username, existing)
            orig_edit_id = existing.get("_legacy_content_identity") if existing.get("edited") else None
            if not hmac.compare_digest(identity, cand_identity) and not (
                isinstance(orig_edit_id, str)
                and re.fullmatch(r'[0-9a-f]{64}', orig_edit_id)
                and hmac.compare_digest(orig_edit_id, cand_identity)
            ):
                raise ValueError("Conflicting message id")
            return False
        messages.append(message_data)
        SecureStorage._save_messages_to_file(my_username, ally_username, messages)
        return True

    @staticmethod
    @_profile_locked
    def _load_all_messages(my_username: str, ally_username: str) -> List[Dict]:
        """Read strictly for writes: never overwrite an unreadable chat history."""
        if not my_username:
            raise ValueError("Missing username")
        from app.history_activation import active_adapter
        with active_adapter(my_username, ally_username) as active:
            if active is not None:
                # Compatibility API only; the UI uses bounded page/offset methods.
                with active.store._connection() as conn:
                    return list(active.store._rows(conn, descending=False))
        messages_file = SecureStorage._get_messages_file(my_username, ally_username)
        if not messages_file.exists():
            return []
        with open(messages_file, "rb") as f:
            encrypted_data = f.read()
        local_key = SecureStorage._get_or_create_local_key(my_username)
        decrypted = nacl.secret.SecretBox(local_key).decrypt(encrypted_data)
        messages = json.loads(decrypted.decode('utf-8'))
        if not isinstance(messages, list) or any(not isinstance(m, dict) for m in messages):
            raise ValueError("Invalid chat history")
        return messages

    @staticmethod
    @_profile_locked
    def load_messages_strict(my_username: str, ally_username: str) -> List[Dict]:
        """Read a chat without conflating a damaged or inaccessible file with an empty one."""
        from app.history_store import _is_message_expired

        return [
            m
            for m in SecureStorage._load_all_messages(my_username, ally_username)
            if not m.get("deleted", False) and not _is_message_expired(m)
        ]

    @staticmethod
    @_profile_locked
    def purge_expired_messages(my_username: str, now_ts: Optional[float] = None) -> Dict[str, List[str]]:
        """Physically remove expired disappearing messages across all local chats of `my_username`."""
        if not my_username:
            return {}
        from app.history_activation import active_adapter, read_catalog
        from app.history_store import _is_message_expired

        profile = SecureStorage._get_user_dir(my_username)
        msg_dir = profile / "messages"
        chats = set()
        if msg_dir.is_dir():
            for p in msg_dir.glob("*.enc"):
                if p.is_file() and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", p.stem):
                    chats.add(p.stem)
        catalog_path = profile / "history_catalog.enc"
        if os.path.lexists(catalog_path):
            local_key = SecureStorage._get_or_create_local_key(my_username)
            for chat_key in read_catalog(catalog_path, local_key, my_username):
                if re.fullmatch(r"[A-Za-z0-9_-]{1,80}", chat_key):
                    chats.add(chat_key)

        purged_by_chat: Dict[str, List[str]] = {}
        for chat_key in sorted(chats):
            with active_adapter(my_username, chat_key) as active:
                if active is not None:
                    ids = active.purge_expired(my_username, chat_key, now_ts=now_ts)
                    if ids:
                        purged_by_chat[chat_key] = ids
                    continue
            all_msgs = SecureStorage._load_all_messages(my_username, chat_key)
            kept = []
            expired_ids: List[str] = []
            for m in all_msgs:
                if _is_message_expired(m, now_ts=now_ts):
                    mid = m.get("msg_id")
                    if isinstance(mid, str) and mid:
                        expired_ids.append(mid)
                else:
                    kept.append(m)
            if len(kept) != len(all_msgs):
                SecureStorage._save_messages_to_file(my_username, chat_key, kept)
                if expired_ids:
                    purged_by_chat[chat_key] = expired_ids
        return purged_by_chat

    @staticmethod
    @_profile_locked
    def load_history_page(my_username: str, ally_username: str, offset=0, page_size=25, query=None, cancel=None):
        from app.history_activation import active_adapter
        from app.history_paging import legacy_history_view, check_cancel
        check_cancel(cancel)
        with active_adapter(my_username, ally_username, cancel=cancel) as active:
            if active is not None:
                return active.load_history_page(my_username, ally_username, offset, page_size, query, cancel=cancel)
        # The legacy SecretBox JSON is monolithic: decrypt/parse cannot be
        # interrupted once started and still loads all history into memory.
        check_cancel(cancel)
        messages = SecureStorage.load_messages_strict(my_username, ally_username)
        check_cancel(cancel)
        return legacy_history_view(messages, offset, page_size, query, cancel=cancel)

    @staticmethod
    def history_background_enabled(my_username, ally_username):
        # Both row storage and legacy snapshots can be read in the worker;
        # legacy decrypt/parse still consumes the full history in memory.
        SecureStorage._get_messages_file(my_username, ally_username)
        return True

    @staticmethod
    def history_revision(my_username):
        return history_revision(my_username)

    @staticmethod
    def load_history_page_background(my_username, ally_username, offset=0, page_size=25, query=None, cancel=None, *, target_id=None):
        """Read outside the profile lock; caller must check the revision before use.

        Legacy files are atomically replaced, so an already-open descriptor keeps
        the old snapshot. SQLite reads use short chunk transactions. This does not
        protect against older clients or external direct file/keyring changes.
        """
        from app.history_activation import active_adapter
        from app.history_paging import legacy_history_view, check_cancel, HistoryStale
        if target_id is not None and (not isinstance(target_id, str) or not target_id):
            raise ValueError("Invalid message id")
        before = history_revision(my_username)
        check_cancel(cancel)
        with active_adapter(my_username, ally_username, cancel=cancel) as active:
            if active is not None:
                if target_id is not None:
                    offset = active.store.offset_for_id_concurrent(target_id, cancel=cancel)
                    query = None
                page = (None if target_id is not None and offset is None else
                        active.store.page_concurrent(offset, page_size, query, cancel=cancel))
            else:
                path = SecureStorage._get_messages_file(my_username, ally_username)
                try:
                    stream = path.open("rb")
                except FileNotFoundError:
                    messages = []
                else:
                    with stream:
                        key = SecureStorage._get_or_create_local_key(my_username)
                        check_cancel(cancel)
                        encrypted = stream.read()  # Legacy format is monolithic.
                    check_cancel(cancel)
                    decrypted = nacl.secret.SecretBox(key).decrypt(encrypted)
                    messages = json.loads(decrypted.decode("utf-8"))
                    if not isinstance(messages, list):
                        raise ValueError("Invalid chat history")
                    visible = []
                    for message in messages:
                        check_cancel(cancel)
                        if not isinstance(message, dict):
                            raise ValueError("Invalid chat history")
                        if not message.get("deleted", False):
                            visible.append(message)
                    messages = visible
                if target_id is not None:
                    offset = None
                    for position, message in enumerate(messages):
                        check_cancel(cancel)
                        if message.get("msg_id") == target_id:
                            offset = len(messages) - position - 1
                            break
                    query = None
                page = (None if target_id is not None and offset is None else
                        legacy_history_view(messages, offset, page_size, query, cancel=cancel))
        check_cancel(cancel)
        after = history_revision(my_username)
        if before != after or before[1] or after[1]:
            raise HistoryStale()
        return page, after

    @staticmethod
    @_profile_locked
    def mark_messages_as_read_if_revision(my_username, ally_username, msg_ids, revision):
        # The revision check and the following mutation share the profile lock.
        # None means the scanned page is stale and must be reloaded.
        if history_revision(my_username) != revision or revision[1]:
            return None
        return SecureStorage.mark_messages_as_read(my_username, ally_username, msg_ids)

    @staticmethod
    @_profile_locked
    def history_offset_for_id(my_username: str, ally_username: str, msg_id: str):
        if not isinstance(msg_id, str) or not msg_id:
            raise ValueError("Invalid message id")
        from app.history_activation import active_adapter
        with active_adapter(my_username, ally_username) as active:
            if active is not None:
                return active.history_offset_for_id(my_username, ally_username, msg_id)
        messages = SecureStorage.load_messages_strict(my_username, ally_username)
        for index, message in enumerate(messages):
            if message.get("msg_id") == msg_id:
                return len(messages) - index - 1
        return None

    @staticmethod
    @_profile_locked
    def load_messages(my_username: str, ally_username: str) -> List[Dict]:
        if not my_username:
            return []
        # Never hide an inaccessible history or failed migration as an empty chat.
        return SecureStorage.load_messages_strict(my_username, ally_username)

    @staticmethod
    @_profile_locked
    def delete_message_with_meta(my_username: str, ally_username: str, msg_id: str) -> tuple[bool, bool]:
        """Delete a message locally and return (deleted, was_mine)."""
        if not my_username:
            return False, False
        from app.history_activation import active_adapter
        with active_adapter(my_username, ally_username) as active:
            if active is not None:
                return active.delete_message_with_meta(my_username, ally_username, msg_id)
        messages = SecureStorage._load_all_messages(my_username, ally_username)
        for msg in messages:
            if msg.get("msg_id") == msg_id:
                was_mine = bool(msg.get("is_mine") is True)
                if msg.get("deleted", False):
                    return False, was_mine
                from app.history_store import content_identity
                key = SecureStorage._get_or_create_local_key(my_username)
                msg["_legacy_content_identity"] = content_identity(key, my_username, ally_username, msg)
                msg["deleted"] = True
                msg["text"] = ""
                SecureStorage._save_messages_to_file(my_username, ally_username, messages)
                return True, was_mine
        return False, False

    @staticmethod
    @_profile_locked
    def delete_message(my_username: str, ally_username: str, msg_id: str) -> bool:
        deleted, _was_mine = SecureStorage.delete_message_with_meta(my_username, ally_username, msg_id)
        return deleted

    @staticmethod
    @_profile_locked
    def delete_incoming_message(my_username: str, ally_username: str, msg_id: str) -> bool:
        """Allow a peer to delete only their own messages; retry unknown IDs."""
        if not my_username or not msg_id:
            return False
        from app.history_activation import active_adapter
        with active_adapter(my_username, ally_username) as active:
            if active is not None:
                return active.delete_incoming_message(my_username, ally_username, msg_id)
        messages = SecureStorage._load_all_messages(my_username, ally_username)
        for msg in messages:
            if msg.get("msg_id") == msg_id:
                if msg.get("is_mine") is not False:
                    return False
                if msg.get("deleted", False):
                    return True
                from app.history_store import content_identity
                key = SecureStorage._get_or_create_local_key(my_username)
                msg["_legacy_content_identity"] = content_identity(key, my_username, ally_username, msg)
                msg["deleted"] = True
                msg["text"] = ""
                SecureStorage._save_messages_to_file(my_username, ally_username, messages)
                return True
        return False

    @staticmethod
    @_profile_locked
    def get_unread_incoming_msg_ids(my_username: str, ally_username: str) -> List[str]:
        messages = SecureStorage.load_messages(my_username, ally_username)
        return [m.get("msg_id") for m in messages if not m.get("is_mine") and not m.get("is_read") and m.get("msg_id")]

    @staticmethod
    @_profile_locked
    def mark_messages_as_read(my_username: str, ally_username: str, msg_ids: List[str], only_mine: bool = False) -> bool:
        if not my_username:
            return False
        from app.history_activation import active_adapter
        with active_adapter(my_username, ally_username) as active:
            if active is not None:
                return active.mark_messages_as_read(my_username, ally_username, msg_ids, only_mine=only_mine)
        messages = SecureStorage._load_all_messages(my_username, ally_username)
        ids = set(msg_ids)
        changed = False
        for msg in messages:
            if (msg.get("msg_id") in ids and not msg.get("is_read")
                    and (not only_mine or msg.get("is_mine") is True)):
                msg["is_read"] = True
                changed = True
        if changed:
            SecureStorage._save_messages_to_file(my_username, ally_username, messages)
        return changed

    @staticmethod
    @_profile_locked
    def list_message_ids(my_username: str, ally_username: str) -> List[str]:
        if not my_username or not ally_username:
            return []
        from app.history_activation import active_adapter
        with active_adapter(my_username, ally_username) as active:
            if active is not None:
                return active.list_message_ids(my_username, ally_username)
        messages = SecureStorage._load_all_messages(my_username, ally_username)
        return [
            m["msg_id"]
            for m in messages
            if isinstance(m, dict) and isinstance(m.get("msg_id"), str) and m.get("msg_id")
        ]

    @staticmethod
    @_profile_locked
    def clear_chat(my_username: str, ally_username: str) -> bool:
        from app.history_activation import active_adapter
        with active_adapter(my_username, ally_username) as active:
            if active is not None:
                return active.clear_chat(my_username, ally_username)
        messages_file = SecureStorage._get_messages_file(my_username, ally_username)
        if messages_file.exists():
            from app.local_vault import secure_wipe_file
            secure_wipe_file(messages_file)
            _fsync_directory(messages_file.parent)
            return True
        return False

    @staticmethod
    @_profile_locked
    def load_security_prefs(my_username: str) -> Dict:
        if not my_username:
            return {}
        prefs_file = SecureStorage._get_user_dir(my_username) / "security_prefs.enc"
        if not prefs_file.exists():
            return {}
        try:
            from app.crypto_box import unpad_traffic_bytes
            raw = prefs_file.read_bytes()
            if len(raw) > 256 * 1024:
                return {}
            box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(my_username))
            pt = unpad_traffic_bytes(box.decrypt(raw))
            data = json.loads(pt.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    @staticmethod
    @_profile_locked
    def save_security_prefs(my_username: str, prefs: Dict) -> bool:
        if not my_username or not isinstance(prefs, dict):
            return False
        from app.crypto_box import pad_traffic_bytes
        pdir = SecureStorage._get_user_dir(my_username)
        prefs_file = pdir / "security_prefs.enc"
        box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(my_username))
        encoded = pad_traffic_bytes(json.dumps(prefs, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        encrypted = box.encrypt(encoded)
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(dir=pdir, delete=False) as f:
                temp_name = f.name
                f.write(encrypted)
                f.flush()
                _safe_fsync_fd(f.fileno())
            _restrict_file_permissions(Path(temp_name))
            _atomic_replace_file(temp_name, prefs_file)
            _fsync_directory(pdir)
            return True
        finally:
            _unlink_temp_quietly(temp_name)

    @staticmethod
    @_profile_locked
    def get_chat_ttl(my_username: str, chat_key: str) -> Optional[int]:
        if not my_username or not chat_key:
            return None
        prefs = SecureStorage.load_security_prefs(my_username)
        ttls = prefs.get("chat_ttls")
        if not isinstance(ttls, dict):
            return None
        val = ttls.get(chat_key)
        if not isinstance(val, bool) and isinstance(val, int) and 5 <= val <= 30 * 86400:
            return val
        return None

    @staticmethod
    @_profile_locked
    def set_chat_ttl(my_username: str, chat_key: str, ttl_seconds: Optional[int]) -> bool:
        if not my_username or not chat_key:
            return False
        prefs = SecureStorage.load_security_prefs(my_username)
        ttls = prefs.get("chat_ttls")
        if not isinstance(ttls, dict):
            ttls = {}
        if ttl_seconds is None or ttl_seconds == 0:
            ttls.pop(chat_key, None)
        else:
            if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not (5 <= ttl_seconds <= 30 * 86400):
                raise ValueError("Invalid TTL seconds")
            ttls[chat_key] = ttl_seconds
        prefs["chat_ttls"] = ttls
        return SecureStorage.save_security_prefs(my_username, prefs)

    @staticmethod
    @_profile_locked
    def get_auto_lock_seconds(my_username: str) -> int:
        if not my_username:
            return 0
        from app.local_vault import get_vault_auto_lock_seconds, is_vault_enabled
        if is_vault_enabled(my_username):
            vsec = get_vault_auto_lock_seconds(my_username)
            if vsec > 0:
                return vsec
        prefs = SecureStorage.load_security_prefs(my_username)
        val = prefs.get("auto_lock_seconds", 0)
        if not isinstance(val, bool) and isinstance(val, int) and 0 <= val <= 86400:
            return val
        return 0

    @staticmethod
    @_profile_locked
    def set_auto_lock_seconds(my_username: str, seconds: int) -> bool:
        if not my_username or isinstance(seconds, bool) or not isinstance(seconds, int) or not (0 <= seconds <= 86400):
            return False
        prefs = SecureStorage.load_security_prefs(my_username)
        prefs["auto_lock_seconds"] = seconds
        return SecureStorage.save_security_prefs(my_username, prefs)

    @staticmethod
    @_profile_locked
    def get_call_audio_prefs(my_username: str) -> Dict:
        defaults = {
            "ice_relay_only": False,
            "noise_gate_db": -45.0,
            "push_to_talk": False,
            "ptt_key": "V",
            "peer_volumes": {},
        }
        if not my_username:
            return dict(defaults)
        prefs = SecureStorage.load_security_prefs(my_username)
        raw = prefs.get("call_audio")
        if not isinstance(raw, dict):
            return dict(defaults)
        out = dict(defaults)
        out["ice_relay_only"] = bool(raw.get("ice_relay_only", False))
        ng = raw.get("noise_gate_db", -45.0)
        if ng is None:
            out["noise_gate_db"] = None
        elif not isinstance(ng, bool) and isinstance(ng, (int, float)) and -85.0 <= float(ng) <= -10.0:
            out["noise_gate_db"] = float(ng)
        out["push_to_talk"] = bool(raw.get("push_to_talk", False))
        pkey = raw.get("ptt_key", "V")
        if isinstance(pkey, str) and 1 <= len(pkey) <= 16:
            out["ptt_key"] = pkey
        pvols = raw.get("peer_volumes")
        if isinstance(pvols, dict):
            clean_vols = {}
            for k, v in pvols.items():
                if isinstance(k, str) and 1 <= len(k) <= 128 and not isinstance(v, bool) and isinstance(v, (int, float)):
                    clean_vols[k] = max(0.0, min(2.0, float(v)))
            out["peer_volumes"] = clean_vols
        return out

    @staticmethod
    @_profile_locked
    def set_call_audio_prefs(my_username: str, updates: Dict) -> bool:
        if not my_username or not isinstance(updates, dict):
            return False
        prefs = SecureStorage.load_security_prefs(my_username)
        current = SecureStorage.get_call_audio_prefs(my_username)
        if "ice_relay_only" in updates:
            current["ice_relay_only"] = bool(updates["ice_relay_only"])
        if "noise_gate_db" in updates:
            ng = updates["noise_gate_db"]
            if ng is None:
                current["noise_gate_db"] = None
            elif not isinstance(ng, bool) and isinstance(ng, (int, float)) and -85.0 <= float(ng) <= -10.0:
                current["noise_gate_db"] = float(ng)
        if "push_to_talk" in updates:
            current["push_to_talk"] = bool(updates["push_to_talk"])
        if "ptt_key" in updates and isinstance(updates["ptt_key"], str) and 1 <= len(updates["ptt_key"]) <= 16:
            current["ptt_key"] = updates["ptt_key"]
        if "peer_volumes" in updates and isinstance(updates["peer_volumes"], dict):
            clean_vols = dict(current.get("peer_volumes", {}))
            for k, v in updates["peer_volumes"].items():
                if isinstance(k, str) and 1 <= len(k) <= 128 and not isinstance(v, bool) and isinstance(v, (int, float)):
                    clean_vols[k] = max(0.0, min(2.0, float(v)))
            current["peer_volumes"] = clean_vols
        prefs["call_audio"] = current
        return SecureStorage.save_security_prefs(my_username, prefs)

    @staticmethod
    @_profile_locked
    def get_ice_relay_only(my_username: str) -> bool:
        return bool(SecureStorage.get_call_audio_prefs(my_username).get("ice_relay_only", False))

    @staticmethod
    @_profile_locked
    def set_ice_relay_only(my_username: str, enabled: bool) -> bool:
        from app.ice_config import set_ui_relay_only
        set_ui_relay_only(bool(enabled))
        return SecureStorage.set_call_audio_prefs(my_username, {"ice_relay_only": bool(enabled)})

    @staticmethod
    @_profile_locked
    def set_peer_volume(my_username: str, peer_key: str, volume: float) -> bool:
        clamped = max(0.0, min(2.0, float(volume)))
        return SecureStorage.set_call_audio_prefs(my_username, {"peer_volumes": {peer_key: clamped}})

    @staticmethod
    @_profile_locked
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

    @staticmethod
    @_profile_locked
    def edit_message(
        my_username: str,
        ally_username: str,
        msg_id: str,
        new_text: str,
        *,
        only_mine: bool = False,
        only_incoming: bool = False,
        expected_sender_name: Optional[str] = None,
    ) -> bool:
        if (
            not my_username
            or not ally_username
            or not isinstance(msg_id, str)
            or not 1 <= len(msg_id) <= 256
            or not isinstance(new_text, str)
            or not 1 <= len(new_text) <= 256 * 1024
            or new_text.startswith(("[IMAGE_META]|", "[VOICE_META]|", "[FILE_META]|"))
        ):
            return False
        from app.history_activation import active_adapter

        with active_adapter(my_username, ally_username) as active:
            if active is not None:
                return bool(
                    active.edit_message(
                        my_username,
                        ally_username,
                        msg_id,
                        new_text,
                        only_mine=only_mine,
                        only_incoming=only_incoming,
                        expected_sender_name=expected_sender_name,
                    )
                )
        messages = SecureStorage._load_all_messages(my_username, ally_username)
        for msg in messages:
            if msg.get("msg_id") == msg_id:
                if msg.get("deleted", False):
                    return False
                cur_text = msg.get("text", "")
                if isinstance(cur_text, str) and cur_text.startswith(
                    ("[IMAGE_META]|", "[VOICE_META]|", "[FILE_META]|")
                ):
                    return False
                if only_mine and msg.get("is_mine") is not True:
                    return False
                if only_incoming and msg.get("is_mine") is not False:
                    return False
                if expected_sender_name is not None and msg.get("sender_name") != expected_sender_name:
                    return False
                if "_legacy_content_identity" not in msg:
                    from app.history_store import content_identity

                    key = SecureStorage._get_or_create_local_key(my_username)
                    msg["_legacy_content_identity"] = content_identity(key, my_username, ally_username, msg)
                msg["text"] = new_text
                msg["edited"] = True
                SecureStorage._save_messages_to_file(my_username, ally_username, messages)
                return True
        return False

    @staticmethod
    @_profile_locked
    def get_pinned_message(my_username: str, chat_key: str) -> Optional[Dict]:
        if not my_username or not chat_key:
            return None
        prefs = SecureStorage.load_security_prefs(my_username)
        pins = prefs.get("pinned_messages")
        if not isinstance(pins, dict):
            return None
        entry = pins.get(chat_key)
        if (
            isinstance(entry, dict)
            and isinstance(entry.get("msg_id"), str)
            and 1 <= len(entry["msg_id"]) <= 256
            and isinstance(entry.get("preview"), str)
        ):
            return {"msg_id": entry["msg_id"], "preview": entry["preview"][:512]}
        return None

    @staticmethod
    @_profile_locked
    def set_pinned_message(my_username: str, chat_key: str, pin_info: Optional[Dict]) -> bool:
        if not my_username or not chat_key:
            return False
        prefs = SecureStorage.load_security_prefs(my_username)
        pins = prefs.get("pinned_messages")
        if not isinstance(pins, dict):
            pins = {}
        if not pin_info or not pin_info.get("msg_id"):
            pins.pop(chat_key, None)
        else:
            mid = pin_info.get("msg_id")
            prev = pin_info.get("preview", "")
            if not isinstance(mid, str) or not 1 <= len(mid) <= 256 or not isinstance(prev, str):
                return False
            pins[chat_key] = {"msg_id": mid, "preview": prev[:512]}
        prefs["pinned_messages"] = pins
        return SecureStorage.save_security_prefs(my_username, prefs)

    @staticmethod
    @_profile_locked
    def get_private_notifications(my_username: str) -> bool:
        if not my_username:
            return False
        prefs = SecureStorage.load_security_prefs(my_username)
        return bool(prefs.get("private_notifications", False))

    @staticmethod
    @_profile_locked
    def set_private_notifications(my_username: str, enabled: bool) -> bool:
        if not my_username:
            return False
        prefs = SecureStorage.load_security_prefs(my_username)
        prefs["private_notifications"] = bool(enabled)
        return SecureStorage.save_security_prefs(my_username, prefs)

    @staticmethod
    def should_mask_notifications(my_username: str) -> bool:
        """Mask notification sender & text when private notifications OR Argon2id LocalVault is active."""
        if not my_username:
            return True
        try:
            from app.local_vault import is_vault_enabled, is_vault_unlocked

            if is_vault_enabled(my_username):
                if not is_vault_unlocked(my_username):
                    return True
                prefs = SecureStorage.load_security_prefs(my_username)
                # Default to private (masked) when LocalVault is enabled unless explicitly turned off
                if "private_notifications" not in prefs:
                    return True
                return bool(prefs.get("private_notifications"))
        except Exception:
            pass
        try:
            return SecureStorage.get_private_notifications(my_username)
        except Exception:
            return True


storage = SecureStorage()