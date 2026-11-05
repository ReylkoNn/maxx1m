"""
Rate limiting для Max1m backend.

Вынесен в отдельный модуль, чтобы избежать циклического импорта:
main.py импортирует роутеры, роутеры импортируют limiter —
если limiter жил бы в main.py, получился бы цикл.
Здесь limiter создаётся без зависимостей от app, поэтому безопасен
для импорта из любого места.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# key_func=get_remote_address — лимитим по IP клиента.
# default_limits — мягкая защита "по умолчанию" для эндпоинтов без явного лимита,
# чтобы забытое декоратором не осталось полностью открытым.
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])
