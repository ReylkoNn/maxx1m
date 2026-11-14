import subprocess
import sys
import pytest
from app.instance_guard import acquire_instance_lock, InstanceAlreadyRunning


def test_process_lock_blocks_second_instance_and_releases(tmp_path):
    lock = acquire_instance_lock(tmp_path)
    try:
        with pytest.raises(InstanceAlreadyRunning):
            acquire_instance_lock(tmp_path)
        script = '''from app.instance_guard import acquire_instance_lock, InstanceAlreadyRunning
import sys
try:
    lock = acquire_instance_lock(sys.argv[1])
except InstanceAlreadyRunning:
    sys.exit(17)
else:
    lock.unlock()
'''
        blocked = subprocess.run([sys.executable, '-c', script, str(tmp_path)], timeout=10)
        assert blocked.returncode == 17
    finally:
        lock.unlock()
    unlocked = acquire_instance_lock(tmp_path)
    unlocked.unlock()


def test_crashed_process_lock_can_be_recovered(tmp_path):
    script = '''from app.instance_guard import acquire_instance_lock
import os, sys
lock = acquire_instance_lock(sys.argv[1])
os._exit(0)
'''
    assert subprocess.run([sys.executable, '-c', script, str(tmp_path)], timeout=10).returncode == 0
    lock = acquire_instance_lock(tmp_path)
    lock.unlock()


def test_local_keyring_write_must_be_read_back_before_history_save(tmp_path, monkeypatch):
    from app import secure_storage
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    monkeypatch.setattr(secure_storage.keyring, 'get_password', lambda *args: None)
    monkeypatch.setattr(secure_storage.keyring, 'set_password', lambda *args: None)
    with pytest.raises(ValueError, match='not persisted'):
        secure_storage.SecureStorage.save_message('alice', 'bob', 'important', False, msg_id='id')
    assert not secure_storage.SecureStorage._get_messages_file('alice', 'bob').exists()


def test_voice_keyring_write_must_be_read_back_before_cache_save(tmp_path, monkeypatch):
    from app import voice_cache
    monkeypatch.setattr(voice_cache.keyring, 'get_password', lambda *args: None)
    monkeypatch.setattr(voice_cache.keyring, 'set_password', lambda *args: None)
    cache = voice_cache.VoiceCache(tmp_path)
    group = voice_cache.message_scope('alice', 'server', 'bob', 'msg')
    asset = voice_cache.asset_scope('file', 'key')
    assert not cache.save(group, asset, b'unique offline voice')
    assert not list(tmp_path.glob('*.bin'))


def test_qt_void_methods_do_not_decrement_none_references(tmp_path):
    """Guard against a PySide6 6.12.0/CPython 3.11 regression seen on Linux."""
    import platform
    import subprocess
    import sys
    if platform.python_implementation() != 'CPython':
        pytest.skip('CPython reference-count regression')
    program = '''
import sys
from PySide6.QtCore import QLockFile
lock = QLockFile(sys.argv[1])
before = sys.getrefcount(None)
for _ in range(100):
    lock.setStaleLockTime(0)
after = sys.getrefcount(None)
assert after >= before - 20, (before, after)
'''
    result = subprocess.run([sys.executable, '-c', program, str(tmp_path/'lock')],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_multi_instance_cli_flag_isolates_storage_keyring_and_lock(tmp_path):
    """Verify `--instance 1` and `--instance 2` can run side-by-side with isolated dirs, keyring, and locks."""
    probe = '''
import json, os, sys
os.environ["HOME"] = sys.argv[1]
os.environ["USERPROFILE"] = sys.argv[1]
import run_desktop
inst, rem = run_desktop._configure_instance_env_from_argv(["Max1m", "--instance", sys.argv[2], "--extra"])
from app import secure_storage, voice_cache
from app.instance_guard import acquire_instance_lock
lock = acquire_instance_lock(secure_storage.BASE_DIR)
print(json.dumps({
    "inst": inst,
    "rem": rem,
    "base_dir": str(secure_storage.BASE_DIR),
    "ss_service": secure_storage.SERVICE_NAME,
    "vc_service": voice_cache.SERVICE_NAME,
}))
lock.unlock()
'''
    r1 = subprocess.run([sys.executable, "-c", probe, str(tmp_path), "1"], capture_output=True, text=True, timeout=10)
    r2 = subprocess.run([sys.executable, "-c", probe, str(tmp_path), "2"], capture_output=True, text=True, timeout=10)
    assert r1.returncode == 0, r1.stderr
    assert r2.returncode == 0, r2.stderr

    import json
    d1 = json.loads(r1.stdout.strip())
    d2 = json.loads(r2.stdout.strip())
    assert d1["base_dir"] != d2["base_dir"]
    assert d2["base_dir"].endswith(".max1m_inst_2")
    assert d1["ss_service"] == "Max1m_Secure_Messenger"
    assert d2["ss_service"] == "Max1m_Secure_Messenger__inst_2"
    assert d2["vc_service"] == "Max1m_Secure_Messenger__inst_2"
    assert d2["rem"] == ["Max1m", "--extra"]

    # Also verify simultaneous locks on instance 1 and instance 2 succeed concurrently!
    from pathlib import Path
    lock1 = acquire_instance_lock(Path(d1["base_dir"]))
    try:
        lock2 = acquire_instance_lock(Path(d2["base_dir"]))
        lock2.unlock()
    finally:
        lock1.unlock()

