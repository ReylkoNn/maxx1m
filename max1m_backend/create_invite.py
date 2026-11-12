import argparse
import asyncio
import secrets
import string
from datetime import datetime, timedelta, timezone
from sqlalchemy import delete, or_, select

from app.database import AsyncSessionLocal, init_models
from app.models import InviteCode


def generate_secure_invite_code() -> str:
    """
    Генерирует криптостойкий инвайт-код формата:
    MAX1M-X7K9-2PQM-N5RJ-8WTA

    Энтропия: 36^16 ≈ 7.95 × 10^24 комбинаций (~82.7 бит).
    """
    alphabet = string.ascii_uppercase + string.digits
    code = "".join(secrets.choice(alphabet) for _ in range(16))
    return f"MAX1M-{code[:4]}-{code[4:8]}-{code[8:12]}-{code[12:16]}"


async def create_new_invite(
    expires_in_days: int | None = 30,
    *,
    ensure_schema: bool = True,
) -> str:
    """
    Создаёт новый инвайт-код.

    Args:
        expires_in_days: срок действия кода в сутках (по умолчанию 30; None — бессрочный).
        ensure_schema: гарантировать наличие таблиц SQLite перед вставкой.
    """
    if expires_in_days is not None:
        if isinstance(expires_in_days, bool) or not isinstance(expires_in_days, int) or not 1 <= expires_in_days <= 3650:
            raise ValueError("expires_in_days must be an integer between 1 and 3650, or None")
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
    else:
        expires_at = None

    if ensure_schema:
        await init_models()

    new_code = generate_secure_invite_code()
    async with AsyncSessionLocal() as session:
        invite = InviteCode(
            code=new_code,
            expires_at=expires_at,
        )
        session.add(invite)
        await session.commit()

        expiry_str = (
            expires_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            if expires_at is not None
            else "бессрочно"
        )
        print("=" * 50)
        print("✅ НОВЫЙ ИНВАЙТ-КОД СОЗДАН")
        print("=" * 50)
        print(f"🔑 Код: {new_code}")
        print(f"⏰ Действителен до: {expiry_str}")
        print("📦 Энтропия: ~82.7 бит")
        print("=" * 50)

        return new_code


async def list_active_invites(*, ensure_schema: bool = True) -> list[str]:
    """Показывает и возвращает все активные неиспользованные инвайт-коды."""
    if ensure_schema:
        await init_models()
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        stmt = (
            select(InviteCode)
            .where(
                InviteCode.is_used == False,
                or_(InviteCode.expires_at.is_(None), InviteCode.expires_at > now),
            )
            .order_by(InviteCode.created_at.asc(), InviteCode.code.asc())
        )
        result = await session.execute(stmt)
        invites = result.scalars().all()

        if not invites:
            print("❌ Нет активных инвайт-кодов.")
            return []

        print("\n📋 АКТИВНЫЕ ИНВАЙТ-КОДЫ:")
        active_codes: list[str] = []
        for inv in invites:
            active_codes.append(inv.code)
            exp_label = (
                f"до {inv.expires_at.strftime('%Y-%m-%d')}"
                if inv.expires_at is not None
                else "бессрочно"
            )
            print(f"  • {inv.code} ({exp_label})")
        return active_codes


async def revoke_invite(code: str, *, ensure_schema: bool = True) -> bool:
    """Отзывает неиспользованный инвайт-код, не трогая уже использованные записи аудита."""
    cleaned = (code or "").strip()
    if not cleaned or len(cleaned) > 50:
        raise ValueError("Invalid invite code")
    if ensure_schema:
        await init_models()
    async with AsyncSessionLocal() as session:
        res = await session.execute(
            delete(InviteCode)
            .where(InviteCode.code == cleaned, InviteCode.is_used == False)
            .execution_options(synchronize_session=False)
        )
        await session.commit()
        if res.rowcount == 1:
            print(f"✅ Инвайт-код отозван: {cleaned}")
            return True
        print("❌ Неиспользованный инвайт-код с таким значением не найден.")
        return False


async def purge_expired_invites(*, ensure_schema: bool = True) -> int:
    """Удаляет только неиспользованные и уже истёкшие инвайт-коды."""
    if ensure_schema:
        await init_models()
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        res = await session.execute(
            delete(InviteCode)
            .where(
                InviteCode.is_used == False,
                InviteCode.expires_at.is_not(None),
                InviteCode.expires_at <= now,
            )
            .execution_options(synchronize_session=False)
        )
        await session.commit()
        removed = int(res.rowcount or 0)
        print(f"🧹 Удалено истёкших неиспользованных инвайт-кодов: {removed}")
        return removed


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Управление инвайт-кодами Max1m")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--list", action="store_true", help="показать активные неиспользованные инвайт-коды")
    mode.add_argument("--revoke", metavar="CODE", help="отозвать неиспользованный инвайт-код")
    mode.add_argument("--purge-expired", action="store_true", help="удалить истёкшие неиспользованные инвайт-коды")
    expiry = parser.add_mutually_exclusive_group()
    expiry.add_argument(
        "--expires-days",
        type=int,
        default=30,
        help="срок действия нового инвайта в днях (1..3650, по умолчанию 30)",
    )
    expiry.add_argument(
        "--no-expiry",
        action="store_true",
        help="создать бессрочный инвайт-код",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.list:
        asyncio.run(list_active_invites())
        return 0
    if args.revoke is not None:
        ok = asyncio.run(revoke_invite(args.revoke))
        return 0 if ok else 1
    if args.purge_expired:
        asyncio.run(purge_expired_invites())
        return 0
    days = None if args.no_expiry else args.expires_days
    asyncio.run(create_new_invite(expires_in_days=days))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
