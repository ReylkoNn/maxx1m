"""Additional limit and unsafe-file coverage for offline diagnostics."""
import importlib.util
import sqlite3
from pathlib import Path
import uuid

import pytest

spec = importlib.util.spec_from_file_location('audit_upload_limits',
    Path(__file__).resolve().parents[1] / 'tools' / 'audit_upload_snapshot.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def test_uuid_symlink_not_counted_as_blob(tmp_path):
    database, directory = tmp_path / 'db', tmp_path / 'uploads'
    directory.mkdir()
    identifier = str(uuid.uuid4())
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE file_records (id TEXT PRIMARY KEY)')
        db.execute('CREATE TABLE upload_reservations (file_id TEXT PRIMARY KEY)')
        db.execute('INSERT INTO file_records VALUES (?)', (identifier,))
    (directory / identifier).symlink_to(database)
    result = audit.audit(database, directory)
    assert result['unsafe_entries'] == 1
    assert result['record_without_blob'] == 1 and result['record_with_blob'] == 0
    assert (directory / identifier).is_symlink()


def test_directory_entry_limit_refuses_partial_report(tmp_path, monkeypatch):
    database, directory = tmp_path / 'db', tmp_path / 'uploads'
    directory.mkdir()
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE file_records (id TEXT PRIMARY KEY)')
        db.execute('CREATE TABLE upload_reservations (file_id TEXT PRIMARY KEY)')
    for i in range(3):
        (directory / str(i)).write_bytes(b'x')
    monkeypatch.setattr(audit, 'MAX_ENTRIES', 2)
    with pytest.raises(ValueError, match='directory entry limit'):
        audit.audit(database, directory)
    assert len(list(directory.iterdir())) == 3
