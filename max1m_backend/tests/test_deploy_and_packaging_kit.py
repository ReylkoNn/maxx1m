"""
Tests for Package VIII:
1. Turnkey RU VPS deployment kit (`deploy/docker-compose.yml`, `max1m_backend/Dockerfile`,
   `deploy/Caddyfile`, `deploy/turnserver.conf.template`, `deploy/bootstrap_vps.sh`).
2. Bit-exact interoperability between the standalone VPS `deploy/generate_join_link.py`
   X.509 ASN.1 SPKI extractor + `max1m-join://` generator and the desktop client's
   `tls_pinning.compute_spki_pin` + `onboarding.parse_join_link`.
3. Windows `Max1m.exe` PyInstaller packaging kit (`packaging/max1m_desktop.spec`,
   `packaging/build_windows.ps1`, `packaging/build_portable.py`).
"""

import datetime
import importlib.util
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_docker_compose_caddy_coturn_and_dockerfile_security_hardening():
    dockerfile = (REPO_ROOT / "max1m_backend" / "Dockerfile").read_text(encoding="utf-8")
    assert "USER max1m" in dockerfile
    assert "--no-access-log" in dockerfile
    assert "chmod 0700 /data" in dockerfile

    compose = yaml.safe_load((REPO_ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    assert {"backend", "caddy", "coturn"} <= set(services)

    backend = services["backend"]
    assert backend["read_only"] is True
    assert "ALL" in backend["cap_drop"]
    assert "no-new-privileges:true" in backend["security_opt"]
    # Backend port 8000 must NOT be exposed directly to host network
    assert "ports" not in backend
    env = backend["environment"]
    assert env["ENABLE_API_DOCS"] == "false"
    assert env["ALLOW_LEGACY_WS_QUERY_TOKEN"] == "false"
    assert env["REQUIRE_VERIFIED_DEVICE_KEYS"] == "true"
    assert env["ENABLE_PREKEYS"] == "true"

    caddyfile = (REPO_ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    assert "protocols tls1.3" in caddyfile
    assert "output discard" in caddyfile

    turn_tpl = (REPO_ROOT / "deploy" / "turnserver.conf.template").read_text(encoding="utf-8")
    assert "use-auth-secret" in turn_tpl
    assert "no-loopback-peers" in turn_tpl
    assert "denied-peer-ip=10.0.0.0-10.255.255.255" in turn_tpl
    assert "denied-peer-ip=192.168.0.0-192.168.255.255" in turn_tpl

    bootstrap = REPO_ROOT / "deploy" / "bootstrap_vps.sh"
    assert bootstrap.exists() and "max1m-join://" in bootstrap.read_text(encoding="utf-8")


def test_vps_generate_join_link_matches_desktop_spki_pin_and_parser(tmp_path):
    gen_mod = _load_module(REPO_ROOT / "deploy" / "generate_join_link.py", "vps_gen_join")
    tls_mod = _load_module(REPO_ROOT / "max1m_desktop" / "app" / "tls_pinning.py", "desktop_tls_pin")

    # Generate a real X.509 ECDSA P-256 certificate (same curve Let's Encrypt uses by default)
    priv = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "chat.company.ru")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .sign(priv, hashes.SHA256())
    )
    pem_file = tmp_path / "cert.pem"
    pem_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    der_bytes = cert.public_bytes(serialization.Encoding.DER)

    vps_pin = gen_mod.extract_spki_pin_from_pem_file(pem_file)
    desktop_pin = tls_mod.compute_spki_pin(der_bytes)
    assert vps_pin == desktop_pin

    join_str = gen_mod.build_join_string(
        "https://chat.company.ru",
        [vps_pin],
        invite_code="MAX1M-ABCD-1234-EFGH-5678",
        node_title="Офис Москва",
    )
    assert join_str.startswith("max1m-join://")


def test_pyinstaller_windows_packaging_kit_structure():
    spec_text = (REPO_ROOT / "packaging" / "max1m_desktop.spec").read_text(encoding="utf-8")
    assert 'name="Max1m"' in spec_text
    assert "run_desktop.py" in spec_text
    assert "upx=False" in spec_text
    assert "console=False" in spec_text
    assert "nacl._sodium" in spec_text
    assert "mss.windows" in spec_text

    ps1_text = (REPO_ROOT / "packaging" / "build_windows.ps1").read_text(encoding="utf-8")
    assert "pyinstaller" in ps1_text.lower()
    assert "Max1m-Windows-x64.zip" in ps1_text
    assert (REPO_ROOT / "packaging" / "build_portable.py").is_file()
    assert (REPO_ROOT / "docs" / "DEPLOY_RU_VPS.md").is_file()

    # Guard against Windows cmd.exe / PowerShell 5.1 UTF-8 byte-offset & BOM corruption
    win_scripts = list(REPO_ROOT.glob("*.bat")) + list((REPO_ROOT / "packaging").glob("*.bat")) + list((REPO_ROOT / "packaging").glob("*.ps1")) + list((REPO_ROOT / "max1m_desktop").glob("*.bat"))
    assert len(win_scripts) >= 7
    for scr in win_scripts:
        raw = scr.read_bytes()
        assert all(b < 128 for b in raw), f"Non-ASCII byte in {scr} breaks cmd.exe / PowerShell 5.1!"
        assert b"chcp 65001" not in raw.lower()


def test_pyinstaller_spec_ast_discovers_all_app_modules_and_310_cmp_op_guard():
    import ast
    import dis

    bp_mod = _load_module(REPO_ROOT / "packaging" / "build_portable.py", "build_portable_test")
    bp_mod._patch_cpython_310_dis_bug()
    assert dis.cmp_op[999] == "<999>"

    spec_path = REPO_ROOT / "packaging" / "max1m_desktop.spec"
    spec_src = spec_path.read_text(encoding="utf-8")
    tree = ast.parse(spec_src, filename=str(spec_path))

    # Execute only the helper + constants prior to Analysis(...) so PyInstaller isn't required in backend venv
    prefix_nodes = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "a" for t in node.targets
        ):
            break
        prefix_nodes.append(node)

    ns = {
        "SPECPATH": str(spec_path.parent),
        "__file__": str(spec_path),
    }
    # Provide stub PyInstaller.utils.hooks if PyInstaller is not installed in backend test venv
    import sys
    import types

    saved_pyi = sys.modules.get("PyInstaller")
    saved_hooks = sys.modules.get("PyInstaller.utils.hooks")
    if saved_hooks is None:
        pyi_pkg = types.ModuleType("PyInstaller")
        pyi_utils = types.ModuleType("PyInstaller.utils")
        pyi_hooks = types.ModuleType("PyInstaller.utils.hooks")
        pyi_hooks.collect_data_files = lambda *_a, **_k: []
        pyi_hooks.collect_submodules = lambda *_a, **_k: []
        sys.modules["PyInstaller"] = pyi_pkg
        sys.modules["PyInstaller.utils"] = pyi_utils
        sys.modules["PyInstaller.utils.hooks"] = pyi_hooks
    try:
        exec(compile(ast.Module(body=prefix_nodes, type_ignores=[]), str(spec_path), "exec"), ns)
    finally:
        if saved_hooks is None:
            sys.modules.pop("PyInstaller.utils.hooks", None)
            sys.modules.pop("PyInstaller.utils", None)
            if saved_pyi is None:
                sys.modules.pop("PyInstaller", None)

    hidden = set(ns["hiddenimports"])
    expected_app_modules = {
        "app.double_ratchet",
        "app.media_identity",
        "app.group_voice_room",
        "app.screen_share",
        "app.ice_config",
        "app.local_vault",
        "app.onboarding",
        "app.tls_pinning",
        "app.outbox",
        "app.outbox_policy",
        "app.attachment_outbox",
        "app.secure_storage",
        "app.windows.main_screen",
        "app.windows.app_window",
        "app.windows.settings_screen",
        "app.windows.widgets.screen_share_overlay",
        "sqlite3",
        "_sqlite3",
    }
    missing = expected_app_modules - hidden
    assert not missing, f"Missing critical modules from max1m_desktop.spec hiddenimports: {missing}"


