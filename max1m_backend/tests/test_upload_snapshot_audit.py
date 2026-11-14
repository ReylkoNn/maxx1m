"""Detached snapshot audit never changes the files or claims safe deletion."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import uuid

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'tools' / 'audit_upload_snapshot.py'
spec = importlib.util.spec_from_file_location('upload_snapshot_audit', SCRIPT)
audit_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_module)


def snapshot(tmp_path):
    dbpath = tmp_path / 'snapshot.db'
    uploads = tmp_path / 'uploads'
    uploads.mkdir()
    ids = [str(uuid.uuid4()) for _ in range(6)]
    with sqlite3.connect(dbpath) as db:
        db.execute('CREATE TABLE file_records (id TEXT PRIMARY KEY)')
        db.execute('CREATE TABLE upload_reservations (file_id TEXT PRIMARY KEY)')
        db.executemany('INSERT INTO file_records VALUES (?)', [(ids[0],), (ids[1],), (ids[2],)])
        db.executemany('INSERT INTO upload_reservations VALUES (?)', [(ids[2],), (ids[3],), (ids[4],)])
    for identifier in (ids[0], ids[2], ids[3], ids[5]):
        (uploads / identifier).write_bytes(b'blob')
    (uploads / '.upload-incomplete').write_bytes(b'partial')
    (uploads / 'other').write_bytes(b'untouched')
    (uploads / 'unsafe-link').symlink_to(dbpath)
    return dbpath, uploads, ids


def state(root):
    return {str(p.relative_to(root)): ('link', os.readlink(p)) if p.is_symlink() else
            ('dir',) if p.is_dir() else ('file', p.read_bytes()) for p in root.rglob('*')}


def run(db, uploads, *extra):
    return subprocess.run([sys.executable, str(SCRIPT), '--database', str(db), '--uploads', str(uploads), *extra],
                          capture_output=True, text=True, timeout=10)


def test_aggregate_report_and_no_changes(tmp_path):
    db, uploads, ids = snapshot(tmp_path)
    before = state(tmp_path)
    result = run(db, uploads, '--confirm-offline-snapshot')
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data['snapshot_only'] and not data['deletion_safe']
    assert data['counts'] == {'file_records': 3, 'reservations': 3, 'reservation_with_blob': 2,
        'reservation_without_blob': 1, 'record_with_blob': 2, 'record_without_blob': 1,
        'record_and_reservation': 1, 'unowned_uuid_files': 1, 'staging_files': 1,
        'staging_bytes': 7, 'other_entries': 1, 'unsafe_entries': 1}
    assert all(identifier not in result.stdout for identifier in ids)
    assert state(tmp_path) == before


def test_refuses_without_confirmation_and_with_sqlite_sidecars(tmp_path):
    db, uploads, _ = snapshot(tmp_path)
    assert run(db, uploads).returncode != 0
    for suffix in ('-wal', '-shm', '-journal'):
        sidecar = Path(str(db) + suffix)
        sidecar.write_bytes(b'not a real journal')
        before = state(tmp_path)
        result = run(db, uploads, '--confirm-offline-snapshot')
        assert result.returncode != 0 and 'snapshot not assessed' in result.stderr
        assert state(tmp_path) == before
        sidecar.unlink()


def test_invalid_identifier_and_capacity_fail_closed(tmp_path, monkeypatch):
    db, uploads, _ = snapshot(tmp_path)
    monkeypatch.setattr(audit_module, 'MAX_ENTRIES', 2)
    with pytest.raises(ValueError, match='limit'):
        audit_module.audit(db, uploads)
    monkeypatch.setattr(audit_module, 'MAX_ENTRIES', 100)
    with sqlite3.connect(db) as conn:
        conn.execute('INSERT INTO file_records VALUES (?)', ('../not-an-id',))
    before = state(tmp_path)
    with pytest.raises(ValueError, match='invalid file identifier'):
        audit_module.audit(db, uploads)
    assert state(tmp_path) == before


def test_no_database_or_upload_creation_on_missing_paths(tmp_path):
    missing = tmp_path / 'no.db'
    result = run(missing, tmp_path / 'missing', '--confirm-offline-snapshot')
    assert result.returncode != 0
    assert list(tmp_path.iterdir()) == []
