import asyncio
import secrets
import string
from datetime import datetime, timezone
from app.database import AsyncSessionLocal
from app.models import InviteCode


def generate_secure_invite_code() -> str:
    """
    Генерирует криптостойкий инвайт-код формата:
    MAX1M-X7K9-2PQM-N5RJ-8WTA

    Энтропия: 62^16 ≈ 4.7 × 10^28 комбинаций (невозможно перебрать)
    """
    alphabet = string.ascii_uppercase + string.digits
    code = ''.join(secrets.choice(alphabet) for _ in range(16))

    # Форматируем для удобства чтения: группы по 4 символа
    formatted = f"MAX1M-{code[:4]}-{code[4:8]}-{code[8:12]}-{code[12:16]}"
    return formatted


async def create_new_invite(expires_in_days: int = 30):
    """
    Создает новый инвайт-код.

    Args:
        expires_in_days: срок действия кода (по умолчанию 30 дней)
    """
    new_code = generate_secure_invite_code()
    expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

    async with AsyncSessionLocal() as session:
        invite = InviteCode(
            code=new_code,
            expires_at=expires_at
        )
        session.add(invite)
        await session.commit()

        print("=" * 50)
        print("✅ НОВЫЙ ИНВАЙТ-КОД СОЗДАН")
        print("=" * 50)
        print(f"🔑 Код: {new_code}")
        print(f"⏰ Действителен до: {expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"📦 Энтропия: ~80 бит")
        print("=" * 50)

        return new_code


async def list_active_invites():
    """Показывает все неиспользованные инвайт-коды."""
    async with AsyncSessionLocal() as session:
        from sqlalchemy import select
        stmt = select(InviteCode).where(
            InviteCode.is_used == False,
            InviteCode.expires_at > datetime.now(timezone.utc)
        )
        result = await session.execute(stmt)
        invites = result.scalars().all()

        if not invites:
            print("❌ Нет активных инвайт-кодов.")
            return

        print("\n📋 АКТИВНЫЕ ИНВАЙТ-КОДЫ:")
        for inv in invites:
            print(f"  • {inv.code} (до {inv.expires_at.strftime('%Y-%m-%d')})")


if __name__ == "__main__":
    import sys
    from datetime import timedelta

    if len(sys.argv) > 1 and sys.argv[1] == "--list":
        asyncio.run(list_active_invites())
    else:
        asyncio.run(create_new_invite())