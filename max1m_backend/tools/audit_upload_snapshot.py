#!/usr/bin/env python3
"""Read-only aggregate audit of a *detached, quiescent* upload snapshot.

This is not garbage collection and does not decide whether anything is safe to
remove. The operator must supply a consistent offline copy of the SQLite DB and
upload directory. Immutable SQLite mode deliberately does not replay WAL or hot
journals; sidecars are rejected instead. Never run against a live data directory.
"""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import uuid

MAX_ENTRIES = 100_000


def canonical_uuid(name):
    try:
        value = uuid.UUID(name)
        return value.version == 4 and str(value) == name
    except (ValueError, AttributeError):
        return False


def audit(database, uploads):
    database = Path(database).absolute()
    uploads = Path(uploads).absolute()
    if not database.is_file() or not uploads.is_dir():
        raise ValueError('Expected an existing database file and upload directory')
    # An immutable connection cannot see data in a WAL, and cannot recover a
    # rollback journal. Do not report a deceptively complete result.
    for suffix in ('-wal', '-shm', '-journal'):
        if os.path.lexists(str(database) + suffix):
            raise ValueError('SQLite sidecar present; provide a clean offline snapshot')
    uri = database.as_uri() + '?mode=ro&immutable=1'
    result = {
        'file_records': 0, 'reservations': 0, 'reservation_with_blob': 0,
        'reservation_without_blob': 0, 'record_with_blob': 0,
        'record_without_blob': 0, 'record_and_reservation': 0,
        'unowned_uuid_files': 0, 'staging_files': 0, 'staging_bytes': 0,
        'other_entries': 0, 'unsafe_entries': 0,
    }
    # Open immutable to avoid any SQLite file creation or journal recovery.
    with sqlite3.connect(uri, uri=True, timeout=1) as db:
        db.execute('PRAGMA query_only=ON')
        records = set()
        reservations = set()
        for table, target, key in (('file_records', records, 'file_records'),
                                   ('upload_reservations', reservations, 'reservations')):
            column = 'id' if table == 'file_records' else 'file_id'
            for (identifier,) in db.execute(f'SELECT {column} FROM {table}'):
                if len(target) >= MAX_ENTRIES:
                    raise ValueError('Snapshot exceeds database entry limit')
                if not canonical_uuid(identifier):
                    raise ValueError('Snapshot contains an invalid file identifier')
                target.add(identifier)
            result[key] = len(target)
        result['record_and_reservation'] = len(records & reservations)
        blobs = set()
        seen = 0
        with os.scandir(uploads) as entries:
            for entry in entries:
                seen += 1
                if seen > MAX_ENTRIES:
                    raise ValueError('Snapshot exceeds directory entry limit')
                # Never follow symlinks or special files; do not open blobs.
                info = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    result['unsafe_entries'] += 1
                elif entry.name.startswith('.upload-'):
                    result['staging_files'] += 1
                    result['staging_bytes'] += info.st_size
                elif canonical_uuid(entry.name):
                    blobs.add(entry.name)
                else:
                    result['other_entries'] += 1
        result['record_with_blob'] = len(records & blobs)
        result['record_without_blob'] = len(records - blobs)
        result['reservation_with_blob'] = len(reservations & blobs)
        result['reservation_without_blob'] = len(reservations - blobs)
        result['unowned_uuid_files'] = len(blobs - records - reservations)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, help='SQLite database in an offline, consistent snapshot')
    parser.add_argument('--uploads', required=True, help='upload directory from the same snapshot')
    parser.add_argument('--confirm-offline-snapshot', action='store_true', help='confirm these are detached copies, not live data')
    args = parser.parse_args()
    if not args.confirm_offline_snapshot:
        parser.error('explicit --confirm-offline-snapshot is required')
    try:
        summary = audit(args.database, args.uploads)
    except (OSError, sqlite3.Error, ValueError) as exc:
        # Do not print paths, filenames, UUIDs or database contents.
        print(f'Audit failed: {type(exc).__name__}; snapshot not assessed', file=sys.stderr)
        return 1
    print(json.dumps({'counts': summary, 'snapshot_only': True, 'deletion_safe': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
