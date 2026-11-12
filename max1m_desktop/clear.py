"""Guarded developer utility for removing test account keys from OS keyring.

Importing this module never touches keyring or disk. Key deletion requires:
1. No running Max1m Desktop instance (enforced via acquire_instance_lock).
2. An explicit --username and --confirm-permanent-key-loss CLI flag.
3. No encrypted local profile files on disk unless
   --allow-unrecoverable-encrypted-files is also passed.
"""
import argparse
import re
import sys

import keyring
from keyring.errors import PasswordDeleteError

from app import secure_storage
from app.instance_guard import InstanceAlreadyRunning, acquire_instance_lock

SERVICE_NAME = "Max1m_Secure_Messenger"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{1,50}$")


def _has_encrypted_profile_data(username: str) -> bool:
    for candidate in (
        secure_storage.BASE_DIR / "profiles" / username,
        secure_storage.BASE_DIR / username,
    ):
        if not candidate.is_dir():
            continue
        for marker in ("groups.enc", "history_catalog.enc", "allies.enc", "device_identity.enc"):
            if (candidate / marker).exists():
                return True
        for subdir in ("messages", "outbox"):
            target = candidate / subdir
            if target.is_dir() and any(target.rglob("*")):
                return True
    return False


def wipe_user_keys(
    username: str,
    *,
    confirm_permanent_key_loss: bool = False,
    allow_unrecoverable_encrypted_files: bool = False,
) -> list[str]:
    if not confirm_permanent_key_loss:
        raise RuntimeError(
            "Операция отклонена: необходимо явное подтверждение confirm_permanent_key_loss=True."
        )
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise ValueError("Некорректное имя пользователя.")

    try:
        lock = acquire_instance_lock(secure_storage.BASE_DIR)
    except (InstanceAlreadyRunning, OSError) as exc:
        raise RuntimeError(
            "Max1m Desktop сейчас запущен или блокировка недоступна. Закройте приложение перед удалением ключей."
        ) from exc
    try:
        if _has_encrypted_profile_data(username) and not allow_unrecoverable_encrypted_files:
            raise RuntimeError(
                f"В профиле '{username}' обнаружены зашифрованные локальные данные. "
                "Удаление ключей сделает историю и очередь нечитаемыми. "
                "Если это действительно тестовый профиль, укажите "
                "--allow-unrecoverable-encrypted-files."
            )
        removed = []
        for suffix in ("_privkey", "_local_storage_key"):
            key_name = f"{username}{suffix}"
            try:
                keyring.delete_password(SERVICE_NAME, key_name)
                removed.append(key_name)
            except PasswordDeleteError:
                pass
        return removed
    finally:
        lock.unlock()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Удаление ключей тестового аккаунта из системного keyring (ОПАСНО)."
    )
    parser.add_argument("--username", required=True, help="Имя аккаунта для удаления ключей")
    parser.add_argument(
        "--confirm-permanent-key-loss",
        action="store_true",
        help="Подтвердить необратимое удаление приватного ключа и ключа локального хранилища",
    )
    parser.add_argument(
        "--allow-unrecoverable-encrypted-files",
        action="store_true",
        help="Разрешить удаление ключей даже при наличии зашифрованных файлов в .max1m/<username>",
    )
    args = parser.parse_args(argv)
    try:
        removed = wipe_user_keys(
            args.username,
            confirm_permanent_key_loss=args.confirm_permanent_key_loss,
            allow_unrecoverable_encrypted_files=args.allow_unrecoverable_encrypted_files,
        )
    except (RuntimeError, ValueError) as exc:
        print(f"[clear] ОТКЛОНЕНО: {exc}", file=sys.stderr)
        return 2
    if removed:
        print(f"[clear] Удалены ключи: {', '.join(removed)}")
    else:
        print(f"[clear] Ключи для '{args.username}' не найдены.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
