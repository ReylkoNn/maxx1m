"""Prevent concurrent desktop processes from writing the same profile files."""
from pathlib import Path
from PySide6.QtCore import QLockFile

class InstanceAlreadyRunning(RuntimeError):
    pass

def acquire_instance_lock(base_dir):
    directory = Path(base_dir)
    directory.mkdir(parents=True, exist_ok=True)
    lock = QLockFile(str(directory / 'desktop.lock'))
    # Never treat a long-running owner as stale merely because of lock age.
    # Qt still checks whether the owning local process exists.
    lock.setStaleLockTime(0)
    if not lock.tryLock(0):
        raise InstanceAlreadyRunning('Another desktop instance is running or the lock is unavailable')
    return lock
