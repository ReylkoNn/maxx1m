import ast
from pathlib import Path
from types import SimpleNamespace
import time

from app.contact_keys import device_key_map, newly_advertised_devices
from app.crypto_box import CryptoManager
from app.incoming_identity import IncomingIdentityError


def extract_refresh_methods(env):
    path = Path(__file__).resolve().parents[1] / "app/windows/main_screen.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    wanted = {"_queue_sender_directory_refresh", "_on_sender_directory_refresh_finished"}
    methods = [
        node for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == "MainScreen"
        for node in cls.body if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    assert {method.name for method in methods} == wanted
    exec(compile(ast.fix_missing_locations(ast.Module(body=methods, type_ignores=[])), str(path), "exec"), env)
    return env["_queue_sender_directory_refresh"], env["_on_sender_directory_refresh_finished"]


def test_unknown_sender_refresh_adds_candidate_but_never_verifies_it():
    old_key, new_key = CryptoManager(), CryptoManager()
    old_key.generate_new_keypair()
    new_key.generate_new_keypair()
    old_device = {
        "device_id": "known-device",
        "public_key": old_key.get_public_key_b64(),
        "verified_fingerprint": "local-verification",
        "verified_scope": {"username": "alice", "device_id": "mine", "server_url": "https://node"},
    }
    state = SimpleNamespace(
        username="alice", server_url="https://node", device_id="mine", token="session",
        allies={"bob": {"user_id": "bob-user", "devices": [old_device]}},
    )
    saved = []
    notifications = []
    store = SimpleNamespace(save_allies=lambda username, allies: saved.append((username, allies)))
    created_workers = []

    class FakeSignal:
        def connect(self, callback, connection_type=None):
            self.callback = callback

    class FakeWorker:
        def __init__(self, server, token, username):
            self.server, self.token, self.target_username = server, token, username
            self.finished = FakeSignal()
            self.running = False
            created_workers.append(self)

        def isRunning(self):
            return self.running

        def start(self):
            self.running = True

        def wait(self):
            self.running = False
            return True

    env = {
        "state": state,
        "storage": store,
        "FindUserWorker": FakeWorker,
        "Qt": SimpleNamespace(QueuedConnection=0),
        "device_key_map": device_key_map,
        "newly_advertised_devices": newly_advertised_devices,
        "time": time,
    }
    queue_refresh, finish_refresh = extract_refresh_methods(env)

    class Screen:
        def __init__(self):
            self._net_workers = []
            self._identity_refresh_workers = {}
            self._identity_refresh_last_attempt = {}
            self._identity_refresh_last_global = None

        def _update_contact_identity_status(self):
            self.status_refreshed = True

        def window(self):
            return SimpleNamespace(show_notification=lambda *args: notifications.append(args))

    screen = Screen()
    screen._queue_sender_directory_refresh = queue_refresh.__get__(screen)
    screen._on_sender_directory_refresh_finished = finish_refresh.__get__(screen)
    error = IncomingIdentityError("unknown_sender_device", sender_tag="012345abcdef", match_count=0)
    envelope = {
        "sender_username": "bob", "sender_user_id": "bob-user",
        "sender_device_id": "new-device",
    }

    screen._queue_sender_directory_refresh(envelope, error)
    assert len(created_workers) == 1
    worker = created_workers[0]
    assert worker.running and worker.target_username == "bob"
    assert worker in screen._net_workers

    # The thread can finish before its queued Qt callback is delivered; do not
    # enqueue another lookup for the same contact during that interval.
    worker.running = False
    screen._queue_sender_directory_refresh(envelope, error)
    assert len(created_workers) == 1

    directory = {
        "username": "bob", "user_id": "bob-user",
        "devices": [
            {"device_id": "known-device", "public_key": old_key.get_public_key_b64()},
            {
                "device_id": "new-device", "public_key": new_key.get_public_key_b64(),
                "fingerprint": "server-claimed-fingerprint",
                "verified_fingerprint": "untrusted-server-claim",
                "verified_scope": {"untrusted": True},
            },
        ],
    }
    screen._on_sender_directory_refresh_finished(True, directory, worker)

    assert len(saved) == 1 and saved[0][0] == "alice"
    added = state.allies["bob"]["devices"][1]
    assert added["device_id"] == "new-device"
    assert "verified_fingerprint" not in added and "verified_scope" not in added
    assert screen.status_refreshed
    assert notifications and "без доверия" in notifications[0][1]
    assert worker not in screen._net_workers
    assert not screen._identity_refresh_workers
