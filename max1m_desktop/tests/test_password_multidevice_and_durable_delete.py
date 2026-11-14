"""Regression tests for Package #4 desktop features:
- APIClient.change_password / cancel_upload_reservation, ChangePasswordWorker credential scrubbing,
  and SettingsScreen password-change flow (session binding + automatic revocation UI sync)
- Multi-device contact handling in MainScreen (no IndexError on empty devices, verified-device priority
  over newly advertised unverified devices, preferred_device_id selection & persistence)
- Durable delete_msg queuing via encrypted outbox and fail-closed verification in outbox_policy
"""
import ast
import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import keyring
from keyring.backend import KeyringBackend
import pytest

from app import outbox, secure_storage
from app.client_api import APIClient
from app.contact_keys import device_key_map, fingerprint_public_key
from app.crypto_box import CryptoManager
from app.outbox_policy import OutboxRecipientError, verify_queued_recipient
from app.recipient_context import (
    RecipientContext,
    capture_recipient,
    recipient_is_verified,
    recipient_still_trusted,
    verification_scope,
)
from app.secure_storage import SecureStorage
from app.workers import ChangePasswordWorker

DESKTOP_ROOT = Path(__file__).resolve().parents[1]


def _extract_methods(rel_path: str, class_name: str, method_names: list[str], env: dict) -> dict:
    src = (DESKTOP_ROOT / rel_path).read_text(encoding="utf-8")
    tree = ast.parse(src)
    wanted = set(method_names)
    nodes = [
        node
        for cls in tree.body
        if isinstance(cls, ast.ClassDef) and cls.name == class_name
        for node in cls.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    assert {n.name for n in nodes} == wanted
    mod = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    ns = dict(env)
    exec(compile(mod, str(DESKTOP_ROOT / rel_path), "exec"), ns)
    return {name: ns[name] for name in method_names}


class _FakeResponse:
    def __init__(self, status_code: int, body: dict):
        self.status_code = status_code
        self._raw = json.dumps(body).encode("utf-8")
        self.closed = False

    def iter_content(self, _chunk_size=4096):
        yield self._raw

    def close(self):
        self.closed = True


def test_api_change_password_and_worker_scrubs_credentials(monkeypatch):
    client = APIClient()
    calls = []

    def fake_post(url, json=None, headers=None, timeout=None, stream=None, allow_redirects=None):
        calls.append((url, json, headers, allow_redirects))
        return _FakeResponse(200, {"status": "ok", "revoked_devices_count": 2})

    monkeypatch.setattr("app.client_api.requests.post", fake_post)

    # Validation before network
    assert client.change_password("https://node", "tok", "samepass12", "samepass12")[0] is False
    assert client.change_password("https://node", "tok", "old", "short")[0] is False
    assert not calls

    ok, res = client.change_password("https://node/", "tok-1", "OldPass!123", "NewPass!456", revoke_other_devices=True)
    assert ok is True
    assert res == {"status": "ok", "revoked_devices_count": 2}
    assert calls[0][0] == "https://node/auth/change-password"
    assert calls[0][3] is False  # Never follow redirects with credentials

    # ChangePasswordWorker scrubs plaintext passwords from memory after run()
    monkeypatch.setattr("app.workers.api", client)
    worker = ChangePasswordWorker("https://node", "tok-1", "OldPass!123", "NewPass!456", revoke_other_devices=True)
    emitted = []
    worker.finished.connect(lambda ok_flag, payload: emitted.append((ok_flag, payload)))
    worker.run()
    assert emitted == [(True, {"status": "ok", "revoked_devices_count": 2})]
    assert worker.current_password == ""
    assert worker.new_password == ""

    # cancel_upload_reservation validates UUIDv4 and response contract
    del_calls = []
    fid = str(uuid.uuid4())

    def fake_delete(url, headers=None, timeout=None, stream=None, allow_redirects=None):
        del_calls.append((url, allow_redirects))
        return _FakeResponse(200, {"status": "cancelled", "file_id": fid})

    monkeypatch.setattr("app.client_api.requests.delete", fake_delete)
    assert client.cancel_upload_reservation("https://node", "tok-1", "bad-id")[0] is False
    assert not del_calls
    ok_del, res_del = client.cancel_upload_reservation("https://node/", "tok-1", fid)
    assert ok_del is True and res_del["file_id"] == fid
    assert del_calls == [(f"https://node/files/upload-reliable/{fid}", False)]


def test_settings_screen_password_change_flow_and_device_revocation_sync():
    class _LineStub:
        def __init__(self, text=""):
            self._text = text

        def text(self):
            return self._text

        def setText(self, val):
            self._text = val

        def clear(self):
            self._text = ""

    class _CheckStub:
        def __init__(self, checked=False):
            self._checked = checked

        def isChecked(self):
            return self._checked

        def setChecked(self, val):
            self._checked = bool(val)

    class _BtnStub:
        def __init__(self):
            self.enabled = True

        def setEnabled(self, val):
            self.enabled = bool(val)

    state = SimpleNamespace(
        username="alice",
        server_url="https://relay.example",
        device_id="dev-current",
        device_name="Alice PC",
        token="tok-alice",
    )
    started_workers = []

    class _WorkerStub:
        def __init__(self, server_url, token, cur_pw, new_pw, revoke_other_devices=False):
            self.server_url = server_url
            self.token = token
            self.current_password = cur_pw
            self.new_password = new_pw
            self.revoke_other_devices = revoke_other_devices
            self.account_context = None
            self.finished = SimpleNamespace(connect=lambda cb, *_a: setattr(self, "_cb", cb))

        def isRunning(self):
            return True

        def start(self):
            started_workers.append(self)

        def wait(self):
            pass

    warnings = []
    env = {
        "state": state,
        "crypto": SimpleNamespace(get_fingerprint=lambda: "AA:BB"),
        "ChangePasswordWorker": _WorkerStub,
        "Qt": SimpleNamespace(QueuedConnection=0),
        "QMessageBox": SimpleNamespace(
            Yes=1,
            No=2,
            question=lambda *_a, **_kw: 1,
            warning=lambda *_a: warnings.append(_a),
        ),
    }
    methods = _extract_methods(
        "app/windows/settings_screen.py",
        "SettingsScreen",
        [
            "_current_account_context",
            "_clear_password_inputs",
            "submit_password_change",
            "_on_password_changed",
        ],
        env,
    )

    rendered = []
    status_texts = []
    dev_status = []
    screen = SimpleNamespace(
        _net_workers=[],
        _own_devices=[
            {"id": "dev-current", "device_name": "Alice PC", "is_current": True, "is_revoked": False},
            {"id": "dev-old", "device_name": "Old Phone", "is_current": False, "is_revoked": False},
        ],
        current_password_input=_LineStub("OldPass!123"),
        new_password_input=_LineStub("mismatch-1"),
        confirm_password_input=_LineStub("mismatch-2"),
        revoke_other_devices_cb=_CheckStub(True),
        change_password_btn=_BtnStub(),
        _password_status_label=SimpleNamespace(setText=lambda t: status_texts.append(t)),
        _devices_status_label=SimpleNamespace(setText=lambda t: dev_status.append(t)),
        _render_own_devices=lambda devs: rendered.append([dict(d) for d in devs]),
    )
    for name, fn in methods.items():
        setattr(screen, name, fn.__get__(screen))

    # Mismatched confirmation rejected without starting worker
    assert screen.submit_password_change() is False
    assert not started_workers

    screen.new_password_input.setText("NewPass!456")
    screen.confirm_password_input.setText("NewPass!456")
    assert screen.submit_password_change() is True
    assert len(started_workers) == 1
    # Inputs are cleared immediately upon dispatch
    assert screen.current_password_input.text() == ""
    assert screen.new_password_input.text() == ""
    assert screen.confirm_password_input.text() == ""
    assert screen.revoke_other_devices_cb.isChecked() is False

    w = started_workers[0]
    # Cross-account stale completion is ignored
    state.username = "bob"
    screen._on_password_changed(True, {"status": "ok", "revoked_devices_count": 1}, w)
    assert not rendered

    # Active account completion marks non-current devices revoked and updates status
    state.username = "alice"
    screen._net_workers.append(w)
    screen._on_password_changed(True, {"status": "ok", "revoked_devices_count": 1}, w)
    assert rendered and rendered[-1][1]["is_revoked"] is True
    assert rendered[-1][0]["is_revoked"] is False
    assert "Отозвано остальных устройств: 1" in status_texts[-1]


class _MemKeyring(KeyringBackend):
    priority = 10

    def __init__(self):
        self.data = {}

    def get_password(self, service, username):
        return self.data.get((service, username))

    def set_password(self, service, username, password):
        self.data[(service, username)] = password

    def delete_password(self, service, username):
        self.data.pop((service, username), None)


def test_multidevice_contact_selection_prevents_index_error_and_unverified_hijack(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    keyring.set_keyring(_MemKeyring())

    dev1_crypto = CryptoManager()
    dev1_crypto.generate_new_keypair()
    dev2_crypto = CryptoManager()
    dev2_crypto.generate_new_keypair()

    pub1 = dev1_crypto.get_public_key_b64()
    pub2 = dev2_crypto.get_public_key_b64()
    scope = {"username": "alice", "device_id": "alice-dev", "server_url": "https://relay.example"}

    state = SimpleNamespace(
        username="alice",
        device_id="alice-dev",
        server_url="https://relay.example/",
        token="tok-alice",
        current_chat_type=None,
        current_group_id=None,
        current_chat_username=None,
        current_chat_device_id=None,
        allies={
            "empty_contact": {"user_id": "u-empty", "devices": []},
            "bob": {
                "user_id": "u-bob",
                "devices": [
                    {
                        "device_id": "bob-laptop",
                        "device_name": "Bob Laptop",
                        "public_key": pub1,
                        "fingerprint": fingerprint_public_key(pub1),
                        "verified_fingerprint": fingerprint_public_key(pub1),
                        "verified_scope": scope,
                    },
                    {
                        "device_id": "bob-new-phone",
                        "device_name": "Bob New Phone",
                        "public_key": pub2,
                        "fingerprint": fingerprint_public_key(pub2),
                        # Newly advertised, NOT verified yet!
                    },
                ],
            },
        },
    )

    dialog_choice_idx = [1]
    env = {
        "state": state,
        "Qt": SimpleNamespace(UserRole=0x0100),
        "RecipientContext": RecipientContext,
        "recipient_is_verified": recipient_is_verified,
        "recipient_still_trusted": recipient_still_trusted,
        "capture_recipient": capture_recipient,
        "device_key_map": device_key_map,
        "fingerprint_public_key": fingerprint_public_key,
        "QInputDialog": SimpleNamespace(
            getItem=lambda _parent, _title, _label, items, _cur, _edit: (items[dialog_choice_idx[0]], True)
        ),
        "QMessageBox": SimpleNamespace(
            warning=lambda *_a: None,
            information=lambda *_a: None,
        ),
        "QTimer": SimpleNamespace(singleShot=lambda _ms, fn: fn()),
    }
    methods = _extract_methods(
        "app/windows/main_screen.py",
        "MainScreen",
        [
            "_resolve_preferred_contact_device_id",
            "_persist_preferred_contact_device",
            "_update_contact_identity_status",
            "_on_ally_selected",
            "_select_contact_target_device",
        ],
        env,
    )

    class _WidgetStub:
        def __init__(self):
            self.visible = None
            self.enabled = None
            self.text = None
            self.placeholder = None

        def setVisible(self, v):
            self.visible = bool(v)

        def setEnabled(self, v):
            self.enabled = bool(v)

        def setText(self, t):
            self.text = t

        def setPlaceholderText(self, t):
            self.placeholder = t

        def setFocus(self):
            pass

    screen = SimpleNamespace(
        allies_list=SimpleNamespace(itemWidget=lambda _it: None),
        chat_title=_WidgetStub(),
        identity_status=_WidgetStub(),
        call_btn=_WidgetStub(),
        search_btn=_WidgetStub(),
        chat_menu_btn=_WidgetStub(),
        right_stack=SimpleNamespace(setCurrentWidget=lambda _w: None),
        chat_area=object(),
        msg_input=_WidgetStub(),
        attach_btn=_WidgetStub(),
        mic_input_btn=_WidgetStub(),
        send_btn=_WidgetStub(),
        _history_offset=0,
        _history_query=None,
        _set_chat_header_icon=lambda _k: None,
        _render_history_page=lambda: None,
        _save_allies_to_storage=lambda: SecureStorage.save_allies("alice", state.allies),
        _verify_call_contact=lambda _u, _d: False,
        _try_outbox=lambda: None,
        _try_attachment_outbox=lambda: None,
    )
    for name, fn in methods.items():
        setattr(screen, name, fn.__get__(screen))

    # 1. Empty devices list must NOT raise IndexError and must disable send/call controls.
    screen._on_ally_selected(SimpleNamespace(data=lambda _role: "empty_contact"))
    assert state.current_chat_device_id is None
    assert screen.send_btn.enabled is False
    assert screen.call_btn.visible is False
    assert "нет доступных устройств" in screen.msg_input.placeholder

    # 2. Contact with [verified, unverified] selects the VERIFIED device, not devices[-1]!
    screen._on_ally_selected(SimpleNamespace(data=lambda _role: "bob"))
    assert state.current_chat_device_id == "bob-laptop"
    assert screen.send_btn.enabled is True
    assert "Устройства проверены: 1/2" in screen.identity_status.text
    assert "Bob Laptop (проверено)" in screen.identity_status.text

    # 3. Selecting unverified bob-new-phone without verifying does NOT overwrite preferred_device_id on disk.
    dialog_choice_idx[0] = 1
    assert screen._select_contact_target_device() is True
    assert state.current_chat_device_id == "bob-new-phone"
    assert "preferred_device_id" not in state.allies["bob"]

    # 4. Once bob-new-phone IS verified, selecting it persists preferred_device_id in allies.enc!
    state.allies["bob"]["devices"][1]["verified_fingerprint"] = fingerprint_public_key(pub2)
    state.allies["bob"]["devices"][1]["verified_scope"] = dict(scope)
    assert screen._select_contact_target_device() is True
    assert state.allies["bob"]["preferred_device_id"] == "bob-new-phone"
    loaded_allies = SecureStorage.load_allies("alice")
    assert loaded_allies["bob"]["preferred_device_id"] == "bob-new-phone"

    # Switching back to verified bob-laptop also persists and survives re-selection.
    dialog_choice_idx[0] = 0
    assert screen._select_contact_target_device() is True
    assert state.allies["bob"]["preferred_device_id"] == "bob-laptop"
    screen._on_ally_selected(SimpleNamespace(data=lambda _role: "bob"))
    assert state.current_chat_device_id == "bob-laptop"


def test_delete_msg_is_queued_durably_and_verified_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    keyring.set_keyring(_MemKeyring())

    alice = CryptoManager()
    alice.generate_new_keypair()
    bob = CryptoManager()
    bob.generate_new_keypair()
    bob_pub = bob.get_public_key_b64()

    state = SimpleNamespace(
        username="alice",
        device_id="alice-dev",
        server_url="https://relay.example",
        token="tok-alice",
        current_chat_type="ally",
        current_chat_username="bob",
        current_chat_device_id="bob-dev",
        allies={
            "bob": {
                "user_id": "u-bob",
                "devices": [
                    {
                        "device_id": "bob-dev",
                        "device_name": "Bob PC",
                        "public_key": bob_pub,
                        "fingerprint": fingerprint_public_key(bob_pub),
                        "verified_fingerprint": fingerprint_public_key(bob_pub),
                        "verified_scope": verification_scope(
                            RecipientContext("bob", "bob-dev", bob_pub, "alice", "alice-dev", "https://relay.example")
                        ),
                    }
                ],
            }
        },
    )

    ephemeral_workers = []

    class _EphemeralWorker:
        def __init__(self, server, token, payload):
            self.payload = payload
            self.finished = SimpleNamespace(connect=lambda *_a: None)
            ephemeral_workers.append(self)

        def start(self):
            pass

    outbox_tries = []
    env = {
        "state": state,
        "crypto": alice,
        "json": json,
        "outbox": outbox,
        "capture_recipient": capture_recipient,
        "recipient_is_verified": recipient_is_verified,
        "SendMessageWorker": _EphemeralWorker,
        "QMessageBox": SimpleNamespace(warning=lambda *_a: None),
        "Qt": SimpleNamespace(QueuedConnection=0),
    }
    methods = _extract_methods("app/windows/main_screen.py", "MainScreen", ["_send_system_payload"], env)
    screen = SimpleNamespace(
        _net_workers=[],
        _try_outbox=lambda: outbox_tries.append(True),
        _on_send_finished=lambda *_a: None,
    )
    screen._send_system_payload = methods["_send_system_payload"].__get__(screen)

    # delete_msg goes into encrypted durable outbox (NOT ephemeral SendMessageWorker)
    assert screen._send_system_payload("bob", {"type": "delete_msg", "msg_id": "msg-del-1"}) is True
    assert len(ephemeral_workers) == 0
    assert len(outbox_tries) == 1

    queued_item = outbox.next_message("alice", "https://relay.example", "alice-dev")
    assert queued_item is not None
    _qpath, record = queued_item
    assert "_local_history" not in record

    # verify_queued_recipient accepts valid delete_msg and returns verified context
    verified_ctx = verify_queued_recipient(state, alice, record)
    assert verified_ctx.username == "bob" and verified_ctx.device_id == "bob-dev"

    # Bob decrypts the exact delete_msg command
    decrypted = json.loads(bob.decrypt_message(record["encrypted_blob"], alice.get_public_key_b64()))
    assert decrypted == {"type": "delete_msg", "msg_id": "msg-del-1"}

    # Fail-closed checks: delete_msg with _local_history, attachment_file_id, or extra fields MUST fail
    with pytest.raises(OutboxRecipientError):
        verify_queued_recipient(
            state, alice, {**record, "_local_history": {"ally_username": "bob", "msg_id": "msg-del-1", "text": "x"}}
        )
    with pytest.raises(OutboxRecipientError):
        verify_queued_recipient(state, alice, record, attachment_file_id=str(uuid.uuid4()))

    bad_env = alice.encrypt_message(json.dumps({"type": "delete_msg", "msg_id": "m", "extra": 1}), bob_pub)
    with pytest.raises(OutboxRecipientError):
        verify_queued_recipient(
            state,
            alice,
            {
                "receiver_device_id": "bob-dev",
                "encrypted_blob": bad_env["encrypted_blob"],
                "signature": bad_env["signature"],
                "client_message_id": str(uuid.uuid4()),
            },
        )

    # read_ack still uses non-durable SendMessageWorker (does NOT bloat outbox)
    assert screen._send_system_payload("bob", {"type": "read_ack", "msg_ids": ["m1"]}) is True
    assert len(ephemeral_workers) == 1
