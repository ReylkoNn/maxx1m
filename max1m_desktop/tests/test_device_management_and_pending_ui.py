import ast
import importlib
import io
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import uuid
import wave

import keyring
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError
import pytest

from app import attachment_outbox, outbox, secure_storage
from app.client_api import APIClient
from app.crypto_box import CryptoManager
from app.instance_guard import acquire_instance_lock
from app.recipient_context import RecipientContext
from app.state import state
from app.voice_cache import VoiceCache, asset_scope, message_scope
from app.workers import ListOwnDevicesWorker, RevokeDeviceWorker


DESKTOP_ROOT = Path(__file__).resolve().parents[1]


def _extract_methods(rel_path: str, class_name: str, method_names: list[str], env: dict):
    path = DESKTOP_ROOT / rel_path
    tree = ast.parse(path.read_text(encoding="utf-8"))
    nodes = [
        node
        for cls in tree.body
        if isinstance(cls, ast.ClassDef) and cls.name == class_name
        for node in cls.body
        if isinstance(node, ast.FunctionDef) and node.name in method_names
    ]
    assert len(nodes) == len(method_names), (
        f"Expected {method_names} in {class_name}, found {[n.name for n in nodes]}"
    )
    compiled = compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), "exec")
    exec(compiled, env)
    return {name: env[name] for name in method_names}


class _MemKeyring(KeyringBackend):
    priority = 10

    def __init__(self):
        self.data = {}

    def get_password(self, service, username):
        return self.data.get((service, username))

    def set_password(self, service, username, password):
        self.data[(service, username)] = password

    def delete_password(self, service, username):
        if (service, username) not in self.data:
            raise PasswordDeleteError(username)
        del self.data[(service, username)]


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    kr = _MemKeyring()
    keyring.set_keyring(kr)
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path / ".max1m")
    monkeypatch.setattr(secure_storage, "CONFIG_FILE", tmp_path / ".max1m" / "local_state.json")
    old_state = (
        state.username,
        state.server_url,
        state.device_id,
        state.device_name,
        state.token,
        state.current_chat_type,
        state.current_chat_username,
        dict(state.allies),
    )
    yield tmp_path, kr
    (
        state.username,
        state.server_url,
        state.device_id,
        state.device_name,
        state.token,
        state.current_chat_type,
        state.current_chat_username,
        allies_copy,
    ) = old_state
    state.allies = allies_copy


class _StyleStub:
    def unpolish(self, _w):
        pass

    def polish(self, _w):
        pass


class _LabelStub:
    def __init__(self, text=""):
        self._text = text
        self._tooltip = ""
        self._props = {}
        self._visible = False
        self._style = _StyleStub()

    def setText(self, t):
        self._text = t

    def text(self):
        return self._text

    def setToolTip(self, tip):
        self._tooltip = tip

    def toolTip(self):
        return self._tooltip

    def setProperty(self, k, v):
        self._props[k] = v

    def property(self, k):
        return self._props.get(k)

    def setVisible(self, v):
        self._visible = bool(v)

    def isVisible(self):
        return self._visible

    def setMaximumWidth(self, _w):
        pass

    def setObjectName(self, _n):
        pass

    def setFocusPolicy(self, _p):
        pass

    def setWordWrap(self, _w):
        pass

    def setTextInteractionFlags(self, _f):
        pass

    def style(self):
        return self._style


class _FakeBubble:
    def __init__(self, text="", is_mine=False, timestamp=None, is_read=False,
                 voice_duration=0.0, reply_to_text=None, reply_to_sender=None,
                 reply_to_msg_id=None, caption=""):
        self._text = text
        self.is_mine = is_mine
        self.is_read = is_read
        self.msg_id = None
        self._caption = caption
        self.voice_duration = voice_duration
        self._voice_data = None
        self._is_playing = False
        self.image_bytes = None
        self.skeleton_shown = False
        self.msg_label = _LabelStub(text)
        self.image_label = _LabelStub()
        self.caption_label = _LabelStub()
        if self.is_mine:
            self.status_label = _LabelStub("✓✓" if self.is_read else "✓")
            self.status_label.setProperty("read", self.is_read)

    def show_skeleton(self):
        self.skeleton_shown = True

    def hide_skeleton(self):
        self.skeleton_shown = False

    def set_reply_to_msg_id(self, mid):
        self._reply_to_msg_id = mid

    def set_image(self, data: bytes, caption: str = ""):
        self.hide_skeleton()
        self.image_bytes = data
        self._caption = caption

    def set_voice_data(self, data: bytes):
        self._voice_data = data


class _LayoutStub:
    def __init__(self, with_stretch=False):
        self.items = [SimpleNamespace(widget=lambda: None)] if with_stretch else []

    def count(self):
        return len(self.items)

    def itemAt(self, idx):
        return self.items[idx]

    def takeAt(self, idx):
        return self.items.pop(idx)

    def addWidget(self, w, *_):
        self.items.append(SimpleNamespace(widget=lambda w=w: w))

    def insertWidget(self, idx, w):
        self.items.insert(idx, SimpleNamespace(widget=lambda w=w: w))

    def setContentsMargins(self, *_):
        pass

    def setSpacing(self, *_):
        pass


def _make_wav_bytes() -> bytes:
    raw = io.BytesIO()
    with wave.open(raw, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(16000)
        wf.writeframes(struct.pack("<160h", *([500, -500] * 80)))
    return raw.getvalue()


def test_message_bubble_status_pending_read_and_corrupt_image_methods():
    # Verify __init__ AST no longer hardcodes QLabel("✓✓") unconditionally.
    mb_src = (DESKTOP_ROOT / "app/windows/widgets/message_bubble.py").read_text(encoding="utf-8")
    assert 'QLabel("✓✓" if self.is_read else "✓")' in mb_src

    class _BadPixmap:
        def loadFromData(self, _b):
            return False

    env = {"QPixmap": _BadPixmap, "Qt": SimpleNamespace(KeepAspectRatio=1, SmoothTransformation=1, transparent=0)}
    methods = _extract_methods(
        "app/windows/widgets/message_bubble.py",
        "MessageBubble",
        ["set_pending", "mark_as_read", "set_image"],
        env,
    )

    bubble = _FakeBubble("hello", is_mine=True, is_read=False)
    assert bubble.status_label.text() == "✓"

    methods["set_pending"](bubble)
    assert bubble.status_label.text() == "⏳"
    assert bubble.status_label.property("read") is False

    methods["mark_as_read"](bubble)
    assert bubble.is_read is True
    assert bubble.status_label.text() == "✓✓"
    assert bubble.status_label.property("read") is True

    corrupt_img = _FakeBubble("", is_mine=False, is_read=True)
    corrupt_img.bubble = SimpleNamespace(setMaximumWidth=lambda _w: None)
    methods["set_image"](corrupt_img, b"corrupt-bytes")
    assert corrupt_img.msg_label.isVisible() is True
    assert "Не удалось отобразить изображение" in corrupt_img.msg_label.text()


def test_reopened_chat_restores_pending_clock_and_local_attachment_preview_and_voice(
    isolated_env, monkeypatch
):
    tmp_path, _ = isolated_env
    alice_crypto = CryptoManager()
    bob_crypto = CryptoManager()
    alice_crypto.generate_new_keypair()
    bob_crypto.generate_new_keypair()

    state.username = "alice"
    state.server_url = "https://relay.example"
    state.device_id = "alice-dev-1"
    state.token = "tok-alice"
    state.current_chat_type = "ally"
    state.current_chat_username = "bob"

    ctx = RecipientContext(
        username="bob",
        device_id="bob-dev-1",
        public_key=bob_crypto.get_public_key_b64(),
        owner_username="alice",
        owner_device_id="alice-dev-1",
        server_url="https://relay.example",
    )

    # 1) Queued text message in outbox
    text_msg_id = f"msg_{uuid.uuid4().hex}"
    enc_text = alice_crypto.encrypt_message(
        json.dumps({"type": "text", "text": "Offline text", "msg_id": text_msg_id}),
        ctx.public_key,
    )
    outbox.enqueue(
        "alice",
        "https://relay.example",
        "alice-dev-1",
        {
            "receiver_device_id": ctx.device_id,
            "encrypted_blob": enc_text["encrypted_blob"],
            "signature": enc_text["signature"],
        },
        local_history={"ally_username": "bob", "text": "Offline text", "msg_id": text_msg_id},
    )

    # 2) Queued image in attachment_outbox (not uploaded yet)
    png_bytes = b"\x89PNG\r\n\x1a\nfake-authenticated-png-payload"
    img_file_id = str(uuid.uuid4())
    img_job_msg_id = str(uuid.uuid4())
    img_msg_id = f"msg_{uuid.uuid4().hex}"
    img_key = alice_crypto.generate_file_key()
    enc_img = alice_crypto.encrypt_file(png_bytes, img_key)
    img_text = f"[IMAGE_META]|{img_file_id}|{img_key}|Подпись офлайн"
    enc_img_env = alice_crypto.encrypt_message(
        json.dumps({"type": "image", "file_id": img_file_id, "secret_key": img_key, "msg_id": img_msg_id}),
        ctx.public_key,
    )
    attachment_outbox.enqueue(
        ctx,
        enc_img,
        img_file_id,
        img_job_msg_id,
        {
            "receiver_device_id": ctx.device_id,
            "encrypted_blob": enc_img_env["encrypted_blob"],
            "signature": enc_img_env["signature"],
        },
        {"ally_username": "bob", "text": img_text, "msg_id": img_msg_id},
    )

    # 3) Queued voice message in attachment_outbox (not uploaded yet, not in voice_cache)
    wav_bytes = _make_wav_bytes()
    voice_file_id = str(uuid.uuid4())
    voice_job_msg_id = str(uuid.uuid4())
    voice_msg_id = f"msg_{uuid.uuid4().hex}"
    voice_key = alice_crypto.generate_file_key()
    enc_voice = alice_crypto.encrypt_file(wav_bytes, voice_key)
    voice_text = f"[VOICE_META]|{voice_file_id}|{voice_key}|2.5"
    enc_voice_env = alice_crypto.encrypt_message(
        json.dumps({"type": "voice", "file_id": voice_file_id, "secret_key": voice_key, "msg_id": voice_msg_id}),
        ctx.public_key,
    )
    attachment_outbox.enqueue(
        ctx,
        enc_voice,
        voice_file_id,
        voice_job_msg_id,
        {
            "receiver_device_id": ctx.device_id,
            "encrypted_blob": enc_voice_env["encrypted_blob"],
            "signature": enc_voice_env["signature"],
        },
        {"ally_username": "bob", "text": voice_text, "msg_id": voice_msg_id},
    )

    isolated_voice_cache = VoiceCache(tmp_path / "voice_cache")

    import math
    mb_methods = _extract_methods(
        "app/windows/widgets/message_bubble.py", "MessageBubble", ["set_pending"], {}
    )
    _FakeBubble.set_pending = mb_methods["set_pending"]

    network_downloads = []
    played_payloads = []
    ms_env = {
        "state": state,
        "outbox": outbox,
        "attachment_outbox": attachment_outbox,
        "voice_cache": isolated_voice_cache,
        "message_scope": message_scope,
        "asset_scope": asset_scope,
        "math": math,
        "MessageBubble": _FakeBubble,
        "DownloadFileWorker": lambda *a, **kw: SimpleNamespace(
            args=a, finished=SimpleNamespace(connect=lambda *_a, **_kw: None)
        ),
        "Qt": SimpleNamespace(QueuedConnection=1),
        "QTimer": SimpleNamespace(singleShot=lambda _ms, _fn: None),
    }
    ms_methods = _extract_methods(
        "app/windows/main_screen.py",
        "MainScreen",
        [
            "_media_context",
            "_media_asset_key",
            "_pending_outgoing_snapshot",
            "_load_message_history",
            "_play_voice_message",
        ],
        ms_env,
    )

    layout = _LayoutStub(with_stretch=True)
    fake_screen = SimpleNamespace(
        messages_layout=layout,
        messages_scroll=SimpleNamespace(
            verticalScrollBar=lambda: SimpleNamespace(setValue=lambda _v: None, maximum=lambda: 0)
        ),
        _image_cache={},
        _voice_request_serial=0,
        _current_playing_bubble=None,
        _connect_bubble_signals=lambda _b, _u: None,
        _prepare_voice_bubble=lambda b, fid, sk, mid: setattr(
            b,
            "_voice_descriptor",
            (("alice", "alice-dev-1", "https://relay.example", "bob"), fid, sk, mid),
        ),
        _queue_media_download=lambda w: network_downloads.append(w),
        _download_voice_for_bubble=lambda *args: network_downloads.append(args),
        _start_playback=lambda b, data, pos: played_payloads.append((b.msg_id, data, pos)),
    )
    for name, fn in ms_methods.items():
        setattr(fake_screen, name, fn.__get__(fake_screen))

    messages = [
        {"text": "Offline text", "is_mine": True, "msg_id": text_msg_id, "is_read": False},
        {"text": img_text, "is_mine": True, "msg_id": img_msg_id, "is_read": False},
        {"text": voice_text, "is_mine": True, "msg_id": voice_msg_id, "is_read": False},
        {"text": "Delivered earlier", "is_mine": True, "msg_id": "msg_sent_ok", "is_read": False},
    ]
    fake_screen._load_message_history("bob", messages)

    bubbles = [layout.itemAt(i).widget() for i in range(layout.count() - 1)]
    assert [b.status_label.text() for b in bubbles] == ["⏳", "⏳", "⏳", "✓"]
    assert network_downloads == []
    assert bubbles[1].image_bytes == png_bytes

    # Tampered key must fail authentication and return None rather than garbage plaintext.
    wrong_key = alice_crypto.generate_file_key()
    assert (
        attachment_outbox.load_pending_plaintext(
            "alice", "https://relay.example", "alice-dev-1", img_file_id, wrong_key
        )
        is None
    )

    # Playing queued voice message decrypts from local attachment_outbox with zero HTTP calls!
    fake_screen._play_voice_message(bubbles[2], b"")
    assert network_downloads == []
    assert played_payloads == [(voice_msg_id, wav_bytes, 0.0)]


def test_api_client_and_workers_own_devices_and_revoke_strict_validation(monkeypatch):
    client = APIClient()

    class _FakeResp:
        def __init__(self, status_code, body):
            self.status_code = status_code
            self._raw = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            self.closed = False

        def iter_content(self, _chunk_size):
            yield self._raw

        def close(self):
            self.closed = True

    good_list = [
        {
            "id": "dev-1",
            "device_name": "Main PC",
            "public_key": "pk1",
            "fingerprint": "fp1",
            "is_revoked": False,
            "is_current": True,
            "created_at": "2026-11-05T00:00:00Z",
        },
        {
            "id": "dev-2",
            "device_name": "Old Laptop",
            "public_key": "pk2",
            "fingerprint": "fp2",
            "is_revoked": False,
            "is_current": False,
        },
    ]
    calls = []
    monkeypatch.setattr(
        "app.client_api.requests.get",
        lambda *a, **kw: calls.append(kw) or _FakeResp(200, good_list),
    )
    w_list = ListOwnDevicesWorker("https://relay.example", "tok", expected_device_id="dev-1")
    out = []
    w_list.finished.connect(lambda *args: out.append(args))
    w_list.run()
    assert out[0][0] is True and len(out[0][1]) == 2
    assert calls[0]["stream"] is True and calls[0]["allow_redirects"] is False

    # Mismatched expected_device_id rejected
    assert client.list_own_devices("https://relay.example", "tok", expected_device_id="dev-2")[0] is False

    # Current device reported as revoked rejected
    monkeypatch.setattr(
        "app.client_api.requests.get",
        lambda *a, **kw: _FakeResp(200, [{**good_list[0], "is_revoked": True}]),
    )
    assert client.list_own_devices("https://relay.example", "tok")[0] is False

    # Oversized list rejected
    monkeypatch.setattr(
        "app.client_api.requests.get",
        lambda *a, **kw: _FakeResp(200, b"x" * (1024 * 1024 + 10)),
    )
    assert client.list_own_devices("https://relay.example", "tok")[0] is False

    # Path traversal target_device_id rejected before network call
    post_calls = []
    monkeypatch.setattr("app.client_api.requests.post", lambda *a, **kw: post_calls.append(kw))
    assert client.revoke_own_device("https://relay.example", "tok", "../admin")[0] is False
    assert post_calls == []

    monkeypatch.setattr(
        "app.client_api.requests.post",
        lambda *a, **kw: post_calls.append(kw)
        or _FakeResp(200, {"status": "ok", "device_id": "dev-2", "is_revoked": True}),
    )
    w_rev = RevokeDeviceWorker("https://relay.example", "tok", "dev-2")
    rev_out = []
    w_rev.finished.connect(lambda *args: rev_out.append(args))
    w_rev.run()
    assert rev_out[0][0] is True
    assert post_calls[0]["stream"] is True and post_calls[0]["allow_redirects"] is False


def test_settings_screen_device_revocation_flow_and_stale_account_guard(isolated_env):
    state.username = "alice"
    state.server_url = "https://relay.example"
    state.device_id = "dev-1"
    state.device_name = "Alice Desktop"
    state.token = "tok-1"

    class _FrameStub:
        def __init__(self):
            self.children_widgets = []

        def setObjectName(self, _n):
            pass

        def setParent(self, _p):
            pass

        def deleteLater(self):
            pass

    class _RowLayoutStub:
        def __init__(self, frame):
            self.frame = frame

        def setContentsMargins(self, *_):
            pass

        def setSpacing(self, *_):
            pass

        def addWidget(self, w, *_):
            self.frame.children_widgets.append(w)

    class _BtnStub(_LabelStub):
        def __init__(self, text=""):
            super().__init__(text)
            self.clicked = SimpleNamespace(connect=lambda fn: setattr(self, "_cb", fn))
            self._enabled = True

        def setEnabled(self, v):
            self._enabled = bool(v)

    warnings_shown = []
    env = {
        "state": state,
        "crypto": SimpleNamespace(get_fingerprint=lambda: "AA:BB:CC:DD"),
        "QFrame": _FrameStub,
        "QHBoxLayout": _RowLayoutStub,
        "QLabel": _LabelStub,
        "QPushButton": _BtnStub,
        "Qt": SimpleNamespace(NoFocus=0, TextSelectableByMouse=1, QueuedConnection=1),
        "QMessageBox": SimpleNamespace(
            Yes=1,
            No=2,
            question=lambda *_a, **_kw: 1,
            warning=lambda *_a: warnings_shown.append(_a),
        ),
        "ListOwnDevicesWorker": ListOwnDevicesWorker,
        "RevokeDeviceWorker": RevokeDeviceWorker,
    }
    methods = _extract_methods(
        "app/windows/settings_screen.py",
        "SettingsScreen",
        [
            "_current_account_context",
            "_clear_devices_rows",
            "_render_own_devices",
            "_on_own_devices_loaded",
            "_on_device_revoked",
            "refresh",
        ],
        env,
    )

    screen = SimpleNamespace(
        _net_workers=[],
        _devices_account_context=None,
        _own_devices=[],
        _devices_list_layout=_LayoutStub(),
        _devices_status_label=_LabelStub(),
        refresh_devices_btn=_BtnStub("Обновить список"),
        _username_value=_LabelStub(),
        _device_name_value=_LabelStub(),
        _device_id_value=_LabelStub(),
        _fp_box=_LabelStub(),
        _populate_audio_combos=lambda: None,
        request_devices_refresh=lambda: None,
    )
    for name, fn in methods.items():
        setattr(screen, name, fn.__get__(screen))

    screen.refresh()
    assert screen._devices_list_layout.count() == 1

    fake_worker = SimpleNamespace(
        account_context=("alice", "https://relay.example", "dev-1", "tok-1"),
        wait=lambda: None,
    )
    devices_payload = [
        {
            "id": "dev-1",
            "device_name": "Alice Desktop",
            "public_key": "pk1",
            "fingerprint": "AA:BB:CC",
            "is_current": True,
            "is_revoked": False,
        },
        {
            "id": "dev-2",
            "device_name": "Lost Laptop",
            "public_key": "pk2",
            "fingerprint": "DD:EE:FF",
            "is_current": False,
            "is_revoked": False,
        },
    ]
    screen._on_own_devices_loaded(True, devices_payload, fake_worker)
    assert screen._devices_list_layout.count() == 2
    row2 = screen._devices_list_layout.itemAt(1).widget()
    assert sum(isinstance(w, _BtnStub) for w in row2.children_widgets) == 1

    # Stale account callback from another user must be ignored
    stale_worker = SimpleNamespace(
        account_context=("bob", "https://relay.example", "dev-9", "tok-9"),
        target_device_id="dev-2",
        wait=lambda: None,
    )
    screen._on_device_revoked(True, {"status": "ok"}, stale_worker)
    assert screen._own_devices[1]["is_revoked"] is False

    # Matching revoke callback marks dev-2 revoked and removes the revoke button
    good_revoke_worker = SimpleNamespace(
        account_context=("alice", "https://relay.example", "dev-1", "tok-1"),
        target_device_id="dev-2",
        wait=lambda: None,
    )
    screen._on_device_revoked(True, {"status": "ok"}, good_revoke_worker)
    assert screen._own_devices[1]["is_revoked"] is True
    row2_after = screen._devices_list_layout.itemAt(1).widget()
    assert sum(isinstance(w, _BtnStub) for w in row2_after.children_widgets) == 0

    # Switching accounts clears previous account's device list on refresh()
    state.username = "carol"
    state.device_id = "dev-carol"
    state.device_name = "Carol Laptop"
    screen.refresh()
    assert screen._own_devices == []
    assert screen._devices_list_layout.count() == 1


def test_clear_script_disarmed_on_import_and_guards_running_instance_and_data(isolated_env):
    keyring.set_password("Max1m_Secure_Messenger", "YARIK_privkey", "secret1")
    keyring.set_password("Max1m_Secure_Messenger", "YARIK_local_storage_key", "secret2")

    clear_mod = importlib.import_module("clear")
    importlib.reload(clear_mod)
    assert keyring.get_password("Max1m_Secure_Messenger", "YARIK_privkey") == "secret1"

    with pytest.raises(RuntimeError):
        clear_mod.wipe_user_keys("YARIK")

    held = acquire_instance_lock(secure_storage.BASE_DIR)
    try:
        with pytest.raises(RuntimeError):
            clear_mod.wipe_user_keys("YARIK", confirm_permanent_key_loss=True)
    finally:
        held.unlock()

    user_dir = secure_storage.BASE_DIR / "YARIK"
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "groups.enc").write_bytes(b"encrypted-data")
    with pytest.raises(RuntimeError):
        clear_mod.wipe_user_keys("YARIK", confirm_permanent_key_loss=True)
    assert keyring.get_password("Max1m_Secure_Messenger", "YARIK_privkey") == "secret1"

    removed = clear_mod.wipe_user_keys(
        "YARIK",
        confirm_permanent_key_loss=True,
        allow_unrecoverable_encrypted_files=True,
    )
    assert set(removed) == {"YARIK_privkey", "YARIK_local_storage_key"}
    assert keyring.get_password("Max1m_Secure_Messenger", "YARIK_privkey") is None
