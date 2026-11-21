"""Fail-closed preparation of a new, retryable local device identity.

The nonsecret marker is written before the private key and before network I/O.
The keyring is shared by username in this legacy client, so automatic replacement
or reuse across servers/accounts is deliberately blocked.
"""
import json
import os
import tempfile
from app.secure_storage import SecureStorage
from app.crypto_box import CryptoManager

PENDING_NAME = 'pending_identity.json'


def _scope(username, server_url, purpose):
    if not isinstance(server_url, str) or not server_url.rstrip('/') or purpose not in ('register', 'device'):
        raise ValueError('Invalid identity setup context')
    SecureStorage._get_user_dir(username)
    return {'username': username, 'server_url': server_url.rstrip('/'), 'purpose': purpose}


def _read_pending(path):
    with path.open('rb') as f:
        data = f.read(16 * 1024 + 1)
    if len(data) > 16 * 1024:
        raise ValueError('Invalid pending identity')
    record = json.loads(data)
    if not isinstance(record, dict) or set(record) != {'username', 'server_url', 'purpose', 'public_key'}:
        raise ValueError('Invalid pending identity')
    return record


def prepare_new_identity(username, server_url, purpose, crypto):
    scope = _scope(username, server_url, purpose)
    profile = SecureStorage._get_user_dir(username)
    path = profile / PENDING_NAME
    key = SecureStorage.get_private_key(username)
    if path.exists():
        record = _read_pending(path)
        if any(record.get(k) != v for k, v in scope.items()) or not key:
            raise ValueError('Existing pending identity needs recovery')
        crypto.load_private_key(key)
        if crypto.get_public_key_b64() != record['public_key']:
            raise ValueError('Pending identity does not match keyring')
        return
    if key is not None or any(profile.iterdir()):
        raise ValueError('Existing profile or private key cannot be replaced')
    state = SecureStorage.load_local_state()
    if not isinstance(state, dict) or state.get('username') == username:
        raise ValueError('Existing local account needs recovery')

    crypto.generate_new_keypair()
    record = {**scope, 'public_key': crypto.get_public_key_b64()}
    # Link without replacement: a second process must never overwrite a marker.
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=profile, delete=False) as output:
            tmp = output.name
            json.dump(record, output, separators=(',', ':'))
            output.flush()
            os.fsync(output.fileno())
        os.link(tmp, path)
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)
    # A failure here leaves a marker, blocks network and requires manual recovery.
    SecureStorage.save_private_key(username, crypto.get_private_key_b64())


def finish_identity(username, server_url, purpose, crypto):
    scope = _scope(username, server_url, purpose)
    path = SecureStorage._get_user_dir(username) / PENDING_NAME
    record = _read_pending(path)
    if any(record.get(k) != v for k, v in scope.items()) or record['public_key'] != crypto.get_public_key_b64():
        raise ValueError('Pending identity changed')
    path.unlink()


def current_identity_matches(username, crypto, expected_public):
    """Re-read keyring before associating a server response with a profile."""
    try:
        key = SecureStorage.get_private_key(username)
        if not key or not isinstance(expected_public, str):
            return False
        saved = CryptoManager()
        saved.load_private_key(key)
        return (saved.get_public_key_b64() == expected_public
                and crypto.get_public_key_b64() == expected_public)
    except Exception:
        return False
