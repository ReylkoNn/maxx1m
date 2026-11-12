"""Exercise a separate, killed server process without touching real data."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'tools' / 'restart_recovery_smoke.py'


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='requires Linux parent-death signals')
def test_restart_smoke_uses_temporary_profile_and_preserves_user_files(tmp_path):
    real_data=tmp_path/'real'; real_data.mkdir()
    marker=real_data/'max1m_secure.db'; marker.write_bytes(b'do-not-touch')
    temp=tmp_path/'temp'; temp.mkdir()
    env={**os.environ,'MAX1M_DATA_DIR':str(real_data),'SECRET_KEY':'user-secret',
         'TMPDIR':str(temp),'HTTP_PROXY':'http://127.0.0.1:1','NO_PROXY':'',
         'MAX_PENDING_PER_DEVICE':'1','MAX_CONCURRENT_UPLOADS_PER_PROCESS':'1'}
    result=subprocess.run([sys.executable,str(SCRIPT)],cwd=tmp_path,env=env,
                          capture_output=True,text=True,timeout=60)
    assert result.returncode==0, result.stderr
    summary=json.loads(result.stdout)
    assert summary['server_process_killed'] and summary['server_restarted']
    assert summary['offline_audit_detected_incomplete']
    assert summary['published_before_commit_recovered']
    assert summary['committed_before_response_recovered']
    assert summary['messages_recovered']==2 and summary['duplicate_messages']==0
    assert summary['pending_after_ack']==0 and summary['upload_resumed'] and summary['foreign_device_blocked']
    assert summary['orphan_staging_files_observed'] >= 1
    assert 'not power loss' in summary['crash'] and 'user-secret' not in result.stdout+result.stderr
    assert marker.read_bytes()==b'do-not-touch' and list(real_data.iterdir())==[marker]
    assert list(temp.iterdir())==[]
