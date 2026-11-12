#!/usr/bin/env python3
"""Isolated delivery/upload smoke test; never contacts an external server.

Creates its own throwaway SQLite database and identities. The optional local
HTTP transport binds only to 127.0.0.1; this is not a production benchmark.
"""
import argparse
import asyncio
from contextlib import asynccontextmanager, contextmanager
import socket
from types import SimpleNamespace
import json
import logging
import os
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

BACKEND = Path(__file__).resolve().parents[1]


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--messages', type=int, default=120)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--payload-bytes', type=int, default=256)
    parser.add_argument('--transport', choices=('in-process', 'loopback'), default='in-process')
    args = parser.parse_args()
    if not 1 <= args.messages <= 400 or not 1 <= args.workers <= 16 or not 1 <= args.payload_bytes <= 4096:
        parser.error('messages must be 1..400, workers 1..16, payload-bytes 1..4096')
    return args


def require(condition, what):
    if not condition:
        raise RuntimeError(what)


@contextmanager
def isolated_client(app, transport):
    """Run either an in-process client or a bounded, loopback-only HTTP server."""
    if transport == 'in-process':
        from fastapi.testclient import TestClient
        with TestClient(app) as client:
            yield client
        return

    import httpx
    import uvicorn
    # Use an already-bound ephemeral loopback socket; no host/port argument is
    # exposed to callers, and environment proxy settings are explicitly ignored.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    started = threading.Event()
    loop_ref = []
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application):
        async with original_lifespan(application):
            loop_ref.append(asyncio.get_running_loop())
            started.set()
            yield

    app.router.lifespan_context = lifespan
    server = uvicorn.Server(uvicorn.Config(app, log_level='warning', access_log=False))
    thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
    thread.start()
    try:
        if not started.wait(10) or not loop_ref:
            raise RuntimeError('loopback server failed to start')
        with httpx.Client(base_url=f'http://127.0.0.1:{port}', timeout=15, trust_env=False) as client:
            # Match TestClient's portal API for seeding and DB checks, keeping
            # all DB operations on the server's own event loop.
            client.portal = SimpleNamespace(call=lambda fn: asyncio.run_coroutine_threadsafe(fn(), loop_ref[0]).result(15))
            client.loopback_port = port
            yield client
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        listener.close()
        app.router.lifespan_context = original_lifespan
        if thread.is_alive():
            raise RuntimeError('loopback server did not stop')


def exercise_uploads(client, sender_headers, devices, workers):
    """Check parallel idempotent uploads and device-bound grants/downloads."""
    blobs = [bytes([65 + i]) * 4096 for i in range(4)]
    ids = [str(uuid.uuid4()) for _ in blobs]
    def upload(index):
        file_id, blob = ids[index], blobs[index]
        headers = sender_headers[index]
        for _ in range(2):
            response = client.post('/files/upload-reliable/' + file_id, headers=headers, content=blob)
            require(response.status_code == 200 and response.json() == {'file_id': file_id, 'size': len(blob)},
                    f'upload or retry failed: HTTP {response.status_code}')
        conflict = client.post('/files/upload-reliable/' + file_id, headers=headers, content=blob + b'x')
        require(conflict.status_code == 409, 'conflicting upload accepted')
        # A different device starts with no access; grant twice and verify.
        other = (index + 1) % len(sender_headers)
        require(client.get('/files/' + file_id, headers=sender_headers[other]).status_code == 404,
                'unauthorized download succeeded')
        for _ in range(2):
            result = client.post('/files/' + file_id + '/grant', headers=headers,
                                 params={'recipient_device_id': devices[other]})
            require(result.status_code == 200 and result.json().get('granted_to') == devices[other], 'grant failed')
        result = client.get('/files/' + file_id, headers=sender_headers[other])
        require(result.status_code == 200 and result.content == blob, 'download content mismatch')
    with ThreadPoolExecutor(max_workers=min(workers, len(blobs))) as pool:
        list(pool.map(upload, range(len(blobs))))
    return len(blobs)


def exercise_lost_response(client, sender_headers, receiver_headers, receiver):
    """Send a complete HTTP request then close the TCP socket before reading."""
    item = {'client_message_id': str(uuid.uuid4()), 'receiver_device_id': receiver,
            'encrypted_blob': 'disconnect-test', 'signature': 'synthetic-signature'}
    body = json.dumps(item, separators=(',', ':')).encode()
    request = (f"POST /messages/send-reliable HTTP/1.1\r\n"
               f"Host: 127.0.0.1\r\nAuthorization: {sender_headers['Authorization']}\r\n"
               f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
               f"Connection: close\r\n\r\n").encode('ascii') + body
    with socket.create_connection(('127.0.0.1', client.loopback_port), timeout=5) as connection:
        connection.sendall(request)
        # Do not read the server response; model a client dropping its connection.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        page = client.get('/messages/sync-safe', headers=receiver_headers, params={'limit': 20})
        require(page.status_code == 200, 'sync after disconnect failed')
        matches = [row for row in page.json() if row['id'] == item['client_message_id']]
        if matches:
            break
        time.sleep(.05)
    else:
        raise RuntimeError('dropped-response request did not commit')
    retry = client.post('/messages/send-reliable', headers=sender_headers, json=item)
    require(retry.status_code == 200 and retry.json().get('id') == item['client_message_id'],
            'retry after disconnected response failed')
    page = client.get('/messages/sync-safe', headers=receiver_headers).json()
    require(sum(row['id'] == item['client_message_id'] for row in page) == 1, 'disconnect retry created duplicates')
    require(client.post('/messages/ack', headers=receiver_headers,
                        json={'message_ids': [item['client_message_id']]}).status_code == 200, 'disconnect ACK failed')
    return True


def main():
    args = arguments()
    with tempfile.TemporaryDirectory(prefix='max1m-load-smoke-') as directory:
        # Configure *before importing the application*, regardless of caller's
        # .env, environment, or current working directory. No path is accepted
        # from the user and the test never opens a user's database or keyring.
        os.chdir(directory)
        os.environ['MAX1M_DATA_DIR'] = directory
        os.environ['SECRET_KEY'] = secrets.token_hex(32)
        os.environ['ALGORITHM'] = 'HS256'
        os.environ['ACCESS_TOKEN_EXPIRE_MINUTES'] = '60'
        os.environ['MAX_PENDING_PER_DEVICE'] = '1000'
        os.environ['MAX_PENDING_PER_SENDER'] = '200'
        os.environ['MAX_PENDING_BYTES_PER_DEVICE'] = str(64 * 1024 * 1024)
        os.environ['MAX_MESSAGE_PAYLOAD_BYTES'] = str(1024 * 1024)
        os.environ['MAX_CONCURRENT_UPLOADS_PER_PROCESS'] = '8'
        sys.path.insert(0, str(BACKEND))
        from sqlalchemy import select, func
        from app import models
        from app.database import AsyncSessionLocal
        from app.main import app
        from app.config import settings
        from app.security import create_access_token
        logging.getLogger('httpx').setLevel(logging.WARNING)

        # Explicitly isolate application and fixture behavior from production
        # rate limits; this is a delivery correctness smoke test, not rate-limit testing.
        app.state.limiter.enabled = False
        with isolated_client(app, args.transport) as client:
            async def seed():
                async with AsyncSessionLocal() as db:
                    user = models.User(username='load-smoke', password_hash='not-a-real-password')
                    db.add(user)
                    await db.flush()
                    devices = [models.Device(user_id=user.id, device_name=f'device-{i}',
                               public_key='synthetic-key', fingerprint=uuid.uuid4().hex) for i in range(5)]
                    db.add_all(devices)
                    await db.commit()
                    return user.id, [item.id for item in devices]
            user_id, devices = client.portal.call(seed)
            senders, receiver = devices[:4], devices[4]
            def auth(device):
                return {'Authorization': 'Bearer ' + create_access_token({'sub': user_id, 'device_id': device})}
            sender_headers = [auth(device) for device in senders]
            receiver_headers = auth(receiver)
            # Synthetic data deliberately does not claim cryptographic coverage.
            items = [{'client_message_id': str(uuid.uuid4()), 'receiver_device_id': receiver,
                      'encrypted_blob': 'x' * args.payload_bytes, 'signature': 'synthetic-signature'}
                     for _ in range(args.messages)]
            expected = {item['client_message_id'] for item in items}
            expected_senders = {item['client_message_id']: senders[index % 4] for index, item in enumerate(items)}
            latencies = []
            samples = 0
            lock = threading.Lock()
            failed = threading.Event()
            def send_one(index):
                item = items[index]
                headers = sender_headers[index % len(senders)]
                start = time.perf_counter()
                for _ in range(2):  # Identical retry models a lost server response.
                    response = client.post('/messages/send-reliable', headers=headers, json=item)
                    require(response.status_code == 200 and response.json().get('id') == item['client_message_id'],
                            f'send/retry failed: HTTP {response.status_code}')
                with lock:
                    latencies.append((time.perf_counter() - start) * 1000)
            def sample_until_done(stop):
                nonlocal samples
                try:
                    while not stop.wait(.05):
                        response = client.get('/messages/sync-safe', headers=receiver_headers, params={'limit': 20})
                        if response.status_code != 200:
                            failed.set()
                            return
                        ids = [m['id'] for m in response.json()]
                        if len(ids) != len(set(ids)) or not set(ids).issubset(expected):
                            failed.set()
                            return
                        samples += 1
                except Exception:
                    failed.set()
            stop = threading.Event()
            monitor = threading.Thread(target=sample_until_done, args=(stop,), daemon=True)
            start = time.perf_counter()
            monitor.start()
            try:
                with ThreadPoolExecutor(max_workers=args.workers) as pool:
                    list(pool.map(send_one, range(len(items))))
            finally:
                stop.set()
                monitor.join()
            require(not failed.is_set(), 'concurrent sync returned invalid data')
            send_seconds = time.perf_counter() - start
            # Repeated safe sync is nondestructive, then ACK each page twice.
            first = client.get('/messages/sync-safe', headers=receiver_headers, params={'limit': 20})
            again = client.get('/messages/sync-safe', headers=receiver_headers, params={'limit': 20})
            require(first.status_code == again.status_code == 200 and first.json() == again.json(), 'sync changed before ACK')
            first_ids = [item['id'] for item in first.json()]
            foreign_ack = client.post('/messages/ack', headers=sender_headers[0], json={'message_ids': first_ids})
            require(foreign_ack.status_code == 200, 'foreign ACK request failed')
            require(client.get('/messages/sync-safe', headers=receiver_headers, params={'limit': 20}).json() == first.json(),
                    'foreign device acknowledged recipient messages')
            seen = set()
            cursor = None
            pages = 0
            while True:
                params = {'limit': 20}
                if cursor:
                    params['after'] = cursor
                response = client.get('/messages/sync-safe', headers=receiver_headers, params=params)
                require(response.status_code == 200, 'sync page failed')
                page = response.json()
                if not page:
                    break
                ids = [m['id'] for m in page]
                require(all(m['id'] in expected_senders and m['sender_device_id'] == expected_senders[m['id']]
                            and m['encrypted_blob'] == 'x' * args.payload_bytes
                            and m['signature'] == 'synthetic-signature' for m in page), 'envelope mismatch')
                require(len(set(ids)) == len(ids) and not seen.intersection(ids), 'duplicate sync delivery')
                seen.update(ids)
                cursor = ids[-1]
                for _ in range(2):
                    ack = client.post('/messages/ack', headers=receiver_headers, json={'message_ids': ids})
                    require(ack.status_code == 200, 'ACK/retry failed')
                pages += 1
            require(seen == expected, f'delivery mismatch: expected {len(expected)}, got {len(seen)}')
            require(client.get('/messages/sync-safe', headers=receiver_headers).json() == [], 'pending after ACK')
            conflict = {**items[0], 'encrypted_blob': items[0]['encrypted_blob'] + 'changed'}
            require(client.post('/messages/send-reliable', headers=sender_headers[0], json=conflict).status_code == 409,
                    'conflicting id was accepted')
            async def db_counts():
                async with AsyncSessionLocal() as db:
                    total = (await db.execute(select(func.count()).select_from(models.Message))).scalar_one()
                    pending = (await db.execute(select(func.count()).select_from(models.Message)
                                               .where(models.Message.is_delivered == False))).scalar_one()
                    return total, pending
            total, pending = client.portal.call(db_counts)
            require((total, pending) == (args.messages, 0), 'database count mismatch')
            # Independently exercise concurrent quota admission, preserving
            # successful retries even when full, and freeing capacity on ACK.
            settings.MAX_PENDING_PER_DEVICE = 12
            quota_items = [{'client_message_id': str(uuid.uuid4()), 'receiver_device_id': receiver,
                            'encrypted_blob': 'quota-sample', 'signature': 'synthetic-signature'} for _ in range(30)]
            def quota_send(index):
                return client.post('/messages/send-reliable', headers=sender_headers[index % 4], json=quota_items[index]).status_code
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                quota_statuses = list(pool.map(quota_send, range(len(quota_items))))
            require(quota_statuses.count(200) == 12 and quota_statuses.count(429) == 18,
                    'concurrent quota admission violated')
            accepted = [i for i, status in enumerate(quota_statuses) if status == 200]
            rejected = [i for i, status in enumerate(quota_statuses) if status == 429]
            require(quota_send(accepted[0]) == 200, 'identical retry failed when full')
            ids = [quota_items[i]['client_message_id'] for i in accepted]
            require(client.post('/messages/ack', headers=receiver_headers, json={'message_ids': ids}).status_code == 200,
                    'quota ACK failed')
            require(quota_send(rejected[0]) == 200, 'capacity did not recover after ACK')
            require(client.post('/messages/ack', headers=receiver_headers,
                                json={'message_ids': [quota_items[rejected[0]]['client_message_id']]}).status_code == 200,
                    'final quota ACK failed')
            total_after, pending_after = client.portal.call(db_counts)
            require((total_after, pending_after) == (args.messages + 13, 0), 'quota database mismatch')
            disconnected = (exercise_lost_response(client, sender_headers[0], receiver_headers, receiver)
                            if args.transport == 'loopback' else False)
            total_end, pending_end = client.portal.call(db_counts)
            require((total_end, pending_end) == (args.messages + 13 + int(disconnected), 0),
                    'disconnect recovery database mismatch')
            uploaded_files = exercise_uploads(client, sender_headers, devices, args.workers)
            sorted_ms = sorted(latencies)
            result = {'messages': args.messages, 'workers': args.workers, 'payload_bytes': args.payload_bytes,
                      'successful_send_requests': 2 * args.messages, 'delivered_once': len(seen),
                      'remaining_pending': pending_after, 'sync_pages': pages, 'concurrent_sync_samples': samples,
                      'quota_accepted': len(accepted), 'quota_rejected': len(rejected), 'quota_recovered': True,
                      'uploaded_and_verified_files': uploaded_files, 'dropped_response_recovered': disconnected,
                      'send_phase_seconds': round(send_seconds, 3),
                      'send_retry_pair_p95_ms': round(sorted_ms[int(.95 * (len(sorted_ms) - 1))], 1),
                      'network': ('in-process TestClient, no real sockets' if args.transport == 'in-process'
                                  else 'local HTTP over 127.0.0.1; no TLS'),
                      'rate_limit': 'disabled for this test'}
            print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
