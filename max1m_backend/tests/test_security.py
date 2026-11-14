from datetime import datetime, timedelta, timezone
from jose import jwt
from app import security
from app.config import settings


def test_zero_expiry_does_not_create_week_long_token():
    token = security.create_access_token({"sub": "user"}, timedelta(0))
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM], options={"verify_exp": False})
    assert payload["exp"] <= int(datetime.now(timezone.utc).timestamp())


def test_corrupt_hash_is_rejected():
    assert security.verify_password("password", "not-a-valid-hash") is False
