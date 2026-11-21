# Offline upload snapshot audit

`max1m_backend/tools/audit_upload_snapshot.py` reports aggregate inconsistencies
in a **detached, consistent offline copy** of the server SQLite database and
its `secure_uploads` directory. It is diagnostic only: it does not delete,
repair, release reservations, open blob contents, or output file/device IDs.
The snapshot must come from a point in time at which **all** server processes
and upload writers were stopped; the database and directory must be from that
same point. Follow your existing backup procedures and retain the original
backup. Do not run it on the live database/directory. The confirmation flag is
an operator assertion, not a lock or proof that writers are stopped.

From `max1m_backend`:

```sh
python tools/audit_upload_snapshot.py --database /path/to/copy/max1m_secure.db \
  --uploads /path/to/copy/secure_uploads --confirm-offline-snapshot
```

The tool opens SQLite in immutable read-only mode and refuses a database copy
with `-wal`, `-shm` or `-journal` sidecars: such a copy may need recovery or may
not include committed data. Prepare a clean consistent snapshot rather than
removing those files. It reports counts of file records and reservations with
or without UUID-named regular blobs, unowned UUID-named blobs, `.upload-` files
and their apparent total bytes, other regular files, and symlinks/directories/
special entries. Record/reservation counts overlap intentionally. Staging byte
counts are apparent sizes, not disk usage (hard links may share storage). The
tool stops without a report on invalid database identifiers, unreadable files,
missing tables or over 100,000 rows per table or directory entries. It does not
verify blob contents, hashes, ownership authorization, database integrity or
that a snapshot really is quiescent and complete.

**None of these counts means deletion is safe.** A reservation may still be
needed for retry; a published file may correspond to an uncertain commit; and
an older server may have left files that cannot be reliably attributed. Never
delete records or files solely based on this report. Safe coordinated cleanup,
including multi-process and older-server deployments, remains future work.
