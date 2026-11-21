#!/usr/bin/env python3
"""Linux-only local crash/restart smoke test on an isolated temporary profile.

Starts a child Uvicorn process on a pre-bound loopback socket, kills that child
while an upload is incomplete, then restarts it using the same temporary files.
No remote address or user data path can be supplied. Not a power-loss test.
"""
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone

import httpx
from jose import jwt

BACKEND = Path(__file__).resolve().parents[1]

# Ask the Linux kernel to kill the child if this harness itself dies. This
# avoids leaving a server behind even on a forced termination of the harness.
_CHILD = r"""
import ctypes, os, signal, sys
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
    sys.exit(1)
if os.getppid() != int(os.environ['MAX1M_SMOKE_PARENT_PID']):
    sys.exit(1)
import uvicorn
if os.environ.get('MAX1M_SMOKE_CRASH_AFTER_LINK') == '1':
    from app.api import files
    original_verify = files._verify_published_file
    async def crash_after_link(path, size, digest):
        await original_verify(path, size, digest)
        os.kill(os.getpid(), signal.SIGKILL)
    files._verify_published_file = crash_after_link
if os.environ.get('MAX1M_SMOKE_CRASH_AFTER_COMMIT') == '1':
    from sqlalchemy.ext.asyncio import AsyncSession
    original_commit = AsyncSession.commit
    commits = 0
    async def crash_after_commit(self):
        global commits
        await original_commit(self)
        commits += 1
        if commits == 2:
            os.kill(os.getpid(), signal.SIGKILL)
    AsyncSession.commit = crash_after_commit
uvicorn.run('app.main:app', fd=int(os.environ['MAX1M_SMOKE_FD']), workers=1,
            loop='asyncio', access_log=False, log_level='error')
"""


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def seed_database(path):
    user_id, sender, receiver = (str(uuid.uuid4()) for _ in range(3))
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(path, timeout=5) as db:
        db.execute('INSERT INTO users (id, username, password_hash, is_active, created_at) VALUES (?, ?, ?, 1, ?)',
                   (user_id, 'restart-test', 'synthetic', now))
        for device in (sender, receiver):
            db.execute('INSERT INTO devices (id, user_id, device_name, public_key, fingerprint, is_revoked, last_seen, created_at) '
                       'VALUES (?, ?, ?, ?, ?, 0, ?, ?)',
                       (device, user_id, 'test', 'synthetic', uuid.uuid4().hex, now, now))
    return user_id, sender, receiver


def start_server(listener, directory, env, *, crash_after_link=False, crash_after_commit=False):
    child_env = {**env, 'MAX1M_SMOKE_FD': str(listener.fileno()), 'MAX1M_SMOKE_PARENT_PID': str(os.getpid())}
    if crash_after_link:
        child_env['MAX1M_SMOKE_CRASH_AFTER_LINK'] = '1'
    if crash_after_commit:
        child_env['MAX1M_SMOKE_CRASH_AFTER_COMMIT'] = '1'
    process = subprocess.Popen([sys.executable, '-c', _CHILD],
                               cwd=directory, env=child_env, pass_fds=(listener.fileno(),),
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base_url = f'http://127.0.0.1:{listener.getsockname()[1]}'
    deadline = time.monotonic() + 15
    try:
        with httpx.Client(base_url=base_url, timeout=.5, trust_env=False) as client:
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError('isolated server exited during startup')
                try:
                    response = client.get('/')
                    if response.status_code == 200 and response.json().get('node') == 'Max1m Relay':
                        return process
                except (httpx.HTTPError, ValueError):
                    pass
                time.sleep(.05)
        raise RuntimeError('isolated server startup timed out')
    except BaseException:
        process.kill()
        process.wait(timeout=5)
        raise


def stop_server(process, *, crash=False):
    if process is None or process.poll() is not None:
        return
    if crash:
        process.kill()
    else:
        process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise RuntimeError('isolated server failed to stop')


def main():
    if not sys.platform.startswith('linux'):
        raise SystemExit('This isolated process-crash test requires Linux.')
    with tempfile.TemporaryDirectory(prefix='max1m-restart-smoke-') as directory:
        # Never trust .env, a preexisting profile, proxy variables or a caller's
        # DB path. We only own/kill children created by this program.
        secret = secrets.token_hex(32)
        env = {'PATH': os.defpath, 'MAX1M_DATA_DIR': directory, 'SECRET_KEY': secret,
               'ALGORITHM': 'HS256', 'ACCESS_TOKEN_EXPIRE_MINUTES': '60',
               'PYTHONPATH': str(BACKEND), 'WEB_CONCURRENCY': '1',
               'MAX_PENDING_PER_DEVICE': '1000', 'MAX_PENDING_PER_SENDER': '200',
               'MAX_PENDING_BYTES_PER_DEVICE': str(64 * 1024 * 1024),
               'MAX_MESSAGE_PAYLOAD_BYTES': str(1024 * 1024),
               'MAX_CONCURRENT_UPLOADS_PER_PROCESS': '8', 'RATE_LIMIT_UPLOAD': '1000/minute'}
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        database = Path(directory) / 'max1m_secure.db'
        first = second = third = fourth = fifth = sixth = None
        partial_connection = None
        try:
            first = start_server(listener, directory, env)
            user_id, sender, receiver = seed_database(database)
            def headers(device):
                token = jwt.encode({'sub': user_id, 'device_id': device, 'exp': int(time.time()) + 3600},
                                   secret, algorithm='HS256')
                return {'Authorization': 'Bearer ' + token}
            sender_auth, receiver_auth = headers(sender), headers(receiver)
            messages = [{'client_message_id': str(uuid.uuid4()), 'receiver_device_id': receiver,
                         'encrypted_blob': f'synthetic-{i}', 'signature': 'synthetic-signature'} for i in range(2)]
            file_id = str(uuid.uuid4())
            blob = b'valid-encrypted-blob' * 200
            with httpx.Client(base_url=base, timeout=10, trust_env=False) as client:
                response = client.post('/messages/send-reliable', headers=sender_auth, json=messages[0])
                require(response.status_code == 200, 'initial send failed')
                # This message is committed, but the sender never reads its response.
                body = json.dumps(messages[1], separators=(',', ':')).encode()
                wire = (f"POST /messages/send-reliable HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                        f"Authorization: {sender_auth['Authorization']}\r\nContent-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
                with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
                    sock.sendall(wire)
                deadline = time.monotonic() + 5
                expected_ids = {item['client_message_id'] for item in messages}
                while time.monotonic() < deadline:
                    response = client.get('/messages/sync-safe', headers=receiver_auth)
                    if response.status_code == 200 and {m['id'] for m in response.json()} == expected_ids:
                        break
                    time.sleep(.05)
                else:
                    raise RuntimeError('messages not persisted before crash')
                # Begin a real raw upload but send only a prefix. Wait for the
                # committed reservation and temp file before killing the server.
                partial_connection = socket.create_connection(('127.0.0.1', port), timeout=5)
                request = (f"POST /files/upload-reliable/{file_id} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                           f"Authorization: {sender_auth['Authorization']}\r\nContent-Type: application/octet-stream\r\n"
                           f"Content-Length: {len(blob)}\r\nConnection: close\r\n\r\n").encode() + blob[:64]
                partial_connection.sendall(request)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    with sqlite3.connect(database, timeout=2) as db:
                        reservation = db.execute('SELECT device_id FROM upload_reservations WHERE file_id=?', (file_id,)).fetchone()
                    staging = list((Path(directory) / 'secure_uploads').glob('.upload-*'))
                    if reservation == (sender,) and staging:
                        break
                    time.sleep(.05)
                else:
                    raise RuntimeError('upload reservation was not established')
                stop_server(first, crash=True)
                first = None
                partial_connection.close()
                partial_connection = None
            with sqlite3.connect(database, timeout=5) as db:
                require(db.execute('SELECT device_id FROM upload_reservations WHERE file_id=?', (file_id,)).fetchone() == (sender,),
                        'reservation missing after crash')
                require(db.execute('SELECT count(*) FROM messages WHERE is_delivered=0').fetchone()[0] == 2,
                        'pending messages missing after crash')
            leftover_temp = len(list((Path(directory) / 'secure_uploads').glob('.upload-*')))
            # This synthetic profile has no running writers at this point.
            # Exercise the read-only diagnostic on the crash-created snapshot.
            audit_result = subprocess.run(
                [sys.executable, str(BACKEND / 'tools' / 'audit_upload_snapshot.py'),
                 '--database', str(database), '--uploads', str(Path(directory) / 'secure_uploads'),
                 '--confirm-offline-snapshot'], cwd=directory, env=env,
                capture_output=True, text=True, timeout=10)
            require(audit_result.returncode == 0, 'offline upload audit failed')
            audit = json.loads(audit_result.stdout)
            require(not audit['deletion_safe'] and audit['counts']['staging_files'] >= 1
                    and audit['counts']['reservation_without_blob'] == 1,
                    'offline audit missed interrupted upload')
            second = start_server(listener, directory, env)
            with httpx.Client(base_url=base, timeout=10, trust_env=False) as client:
                response = client.get('/messages/sync-safe', headers=receiver_auth)
                require(response.status_code == 200 and {m['id'] for m in response.json()} == expected_ids,
                        'pending messages missing after restart')
                for item in messages:
                    retry = client.post('/messages/send-reliable', headers=sender_auth, json=item)
                    require(retry.status_code == 200 and retry.json()['id'] == item['client_message_id'], 'message retry failed')
                ack_other = client.post('/messages/ack', headers=sender_auth, json={'message_ids': list(expected_ids)})
                require(ack_other.status_code == 200 and len(client.get('/messages/sync-safe', headers=receiver_auth).json()) == 2,
                        'wrong device acknowledged messages')
                for _ in range(2):
                    require(client.post('/messages/ack', headers=receiver_auth, json={'message_ids': list(expected_ids)}).status_code == 200,
                            'ACK retry failed')
                require(client.get('/messages/sync-safe', headers=receiver_auth).json() == [], 'messages still pending')
                path = '/files/upload-reliable/' + file_id
                require(client.post(path, headers=receiver_auth, content=blob).status_code == 409,
                        'other device claimed reservation')
                for _ in range(2):
                    result = client.post(path, headers=sender_auth, content=blob)
                    require(result.status_code == 200 and result.json() == {'file_id': file_id, 'size': len(blob)},
                            'upload retry failed')
                require(client.get('/files/' + file_id, headers=receiver_auth).status_code == 404, 'file access leaked')
                grant = client.post('/files/' + file_id + '/grant', headers=sender_auth,
                                    params={'recipient_device_id': receiver})
                require(grant.status_code == 200, 'file grant failed')
                retrieved = client.get('/files/' + file_id, headers=receiver_auth)
                require(retrieved.status_code == 200 and retrieved.content == blob, 'uploaded bytes mismatch')
            with sqlite3.connect(database, timeout=5) as db:
                require(db.execute('SELECT count(*) FROM messages').fetchone()[0] == 2, 'message duplicates after restart')
                require(db.execute('SELECT count(*) FROM messages WHERE is_delivered=0').fetchone()[0] == 0, 'pending messages remain')
                require(db.execute('SELECT count(*) FROM upload_reservations WHERE file_id=?', (file_id,)).fetchone()[0] == 0,
                        'reservation still exists after upload')
            # Crash after publication but before the database record commits.
            stop_server(second)
            second = None
            published_id = str(uuid.uuid4())
            published_blob = b'published-before-db-commit' * 100
            third = start_server(listener, directory, env, crash_after_link=True)
            try:
                with httpx.Client(base_url=base, timeout=10, trust_env=False) as client:
                    client.post('/files/upload-reliable/' + published_id, headers=sender_auth, content=published_blob)
                raise RuntimeError('fault-injected server unexpectedly replied')
            except httpx.RemoteProtocolError:
                pass
            require(third.wait(timeout=5) == -9, 'server did not die at injected boundary')
            third = None
            published_path = Path(directory) / 'secure_uploads' / published_id
            require(published_path.read_bytes() == published_blob, 'published blob missing after crash')
            with sqlite3.connect(database, timeout=5) as db:
                require(db.execute('SELECT device_id FROM upload_reservations WHERE file_id=?', (published_id,)).fetchone() == (sender,), 'published reservation missing')
                require(db.execute('SELECT count(*) FROM file_records WHERE id=?', (published_id,)).fetchone()[0] == 0, 'unexpected file record before retry')
            fourth = start_server(listener, directory, env)
            with httpx.Client(base_url=base, timeout=10, trust_env=False) as client:
                path = '/files/upload-reliable/' + published_id
                require(client.post(path, headers=receiver_auth, content=published_blob).status_code == 409, 'foreign takeover after crash')
                require(client.post(path, headers=sender_auth, content=b'wrong').status_code == 409, 'different bytes accepted after crash')
                require(client.post(path, headers=sender_auth, content=published_blob).status_code == 200, 'published upload retry failed')
                require(client.get('/files/' + published_id, headers=sender_auth).content == published_blob, 'recovered published blob differs')
            with sqlite3.connect(database, timeout=5) as db:
                require(db.execute('SELECT count(*) FROM file_records WHERE id=?', (published_id,)).fetchone()[0] == 1, 'file record not recovered')
                require(db.execute('SELECT count(*) FROM upload_reservations WHERE file_id=?', (published_id,)).fetchone()[0] == 0, 'reservation not released')
            # Also lose the HTTP response after SQLite committed the file.
            stop_server(fourth)
            fourth = None
            committed_id = str(uuid.uuid4())
            committed_blob = b'committed-before-response' * 100
            fifth = start_server(listener, directory, env, crash_after_commit=True)
            try:
                with httpx.Client(base_url=base, timeout=10, trust_env=False) as client:
                    client.post('/files/upload-reliable/' + committed_id, headers=sender_auth, content=committed_blob)
                raise RuntimeError('post-commit server unexpectedly replied')
            except httpx.RemoteProtocolError:
                pass
            require(fifth.wait(timeout=5) == -9, 'server did not die after commit')
            fifth = None
            with sqlite3.connect(database, timeout=5) as db:
                require(db.execute('SELECT count(*) FROM file_records WHERE id=?', (committed_id,)).fetchone()[0] == 1, 'file record missing after commit')
                require(db.execute('SELECT count(*) FROM upload_reservations WHERE file_id=?', (committed_id,)).fetchone()[0] == 0, 'committed reservation still exists')
            sixth = start_server(listener, directory, env)
            with httpx.Client(base_url=base, timeout=10, trust_env=False) as client:
                path = '/files/upload-reliable/' + committed_id
                require(client.post(path, headers=receiver_auth, content=committed_blob).status_code == 409, 'foreign retry accepted')
                require(client.post(path, headers=sender_auth, content=b'wrong').status_code == 409, 'wrong committed bytes accepted')
                require(client.post(path, headers=sender_auth, content=committed_blob).status_code == 200, 'committed upload retry failed')
                require(client.get('/files/' + committed_id, headers=sender_auth).content == committed_blob, 'committed blob differs')
            print(json.dumps({'offline_audit_detected_incomplete': True, 'published_before_commit_recovered': True, 'committed_before_response_recovered': True, 'server_process_killed': True, 'server_restarted': True, 'messages_recovered': 2,
                              'duplicate_messages': 0, 'pending_after_ack': 0, 'upload_resumed': True,
                              'foreign_device_blocked': True, 'orphan_staging_files_observed': leftover_temp,
                              'transport': 'HTTP over 127.0.0.1; no TLS', 'crash': 'process kill, not power loss'}))
        finally:
            if partial_connection:
                partial_connection.close()
            stop_server(first)
            stop_server(second)
            stop_server(third)
            stop_server(fourth)
            stop_server(fifth)
            stop_server(sixth)
            listener.close()


if __name__ == '__main__':
    main()
