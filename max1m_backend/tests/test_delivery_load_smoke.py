"""The optional concurrency harness must never use a user's database."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'tools' / 'delivery_load_smoke.py'


@pytest.mark.parametrize('transport', ['in-process', 'loopback'])
def test_smoke_harness_isolated_from_environment_and_cleans_up(tmp_path, transport):
    real_data = tmp_path / 'do-not-touch'
    real_data.mkdir()
    marker = real_data / 'max1m_secure.db'
    marker.write_bytes(b'not a test database')
    temp = tmp_path / 'temp'
    temp.mkdir()
    env = {**os.environ, 'MAX1M_DATA_DIR': str(real_data), 'SECRET_KEY': 'user-secret',
           'MAX_PENDING_PER_DEVICE': '1', 'MAX_PENDING_PER_SENDER': '1', 'TMPDIR': str(temp),
           'HTTP_PROXY': 'http://127.0.0.1:1', 'NO_PROXY': ''}
    result = subprocess.run([sys.executable, str(SCRIPT), '--messages', '24', '--workers', '4', '--transport', transport],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary['delivered_once'] == 24 and summary['remaining_pending'] == 0
    assert (summary['quota_accepted'], summary['quota_rejected'], summary['quota_recovered']) == (12, 18, True)
    assert ('in-process' if transport == 'in-process' else '127.0.0.1') in summary['network']
    assert summary['uploaded_and_verified_files'] == 4 and 'user-secret' not in result.stdout + result.stderr
    assert summary['dropped_response_recovered'] == (transport == 'loopback')
    assert marker.read_bytes() == b'not a test database'
    assert list(real_data.iterdir()) == [marker] and list(temp.iterdir()) == []


def test_smoke_harness_rejects_unbounded_inputs_before_creating_files(tmp_path):
    result = subprocess.run([sys.executable, str(SCRIPT), '--messages', '401'], cwd=tmp_path,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode != 0 and '1..400' in result.stderr
    assert list(tmp_path.iterdir()) == []
