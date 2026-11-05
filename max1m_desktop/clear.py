import keyring

SERVICE_NAME = "Max1m_Secure_Messenger"

# Напиши сюда имена ВСЕХ аккаунтов, под которыми ты пытался заходить
USERNAMES_TO_WIPE = ["YARIK", "ALEX", "AGENT1", "AGENT2", "TEST1", "TEST2", "MAS1MA"]

print("🔥 Начинаем полное стирание ключей E2EE из памяти Windows...\n")

for username in USERNAMES_TO_WIPE:
    try:
        keyring.delete_password(SERVICE_NAME, f"{username}_privkey")
        print(f"✅ Приватный ключ удален: {username}")
    except keyring.errors.PasswordDeleteError:
        print(f"⚪ Приватный ключ не найден: {username}")

    try:
        keyring.delete_password(SERVICE_NAME, f"{username}_local_storage_key")
        print(f"✅ Локальный ключ БД удален: {username}")
    except keyring.errors.PasswordDeleteError:
        print(f"⚪ Локальный ключ БД не найден: {username}")

print("\n🚀 Очистка завершена! Теперь ключи сгенерируются с чистого листа.")