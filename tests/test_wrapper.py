"""The sh wrapper must fail loudly — never exec an empty script path."""

import subprocess
from pathlib import Path

WRAPPER = Path(__file__).resolve().parent.parent / 'integrations' / 'whisper' / 'custom-whisper'


def _run(env=None):
    return subprocess.run(
        ['sh', str(WRAPPER), '/tmp/fake.alert', '', '', ''],
        capture_output=True,
        text=True,
        env=env or {},
        timeout=10,
    )


def test_missing_wazuh_python_fails_loudly():
    """From the checkout (no /var/ossec python on dev machines) the wrapper must
    error clearly and exit non-zero — not exec the alert file as Python."""
    result = _run()
    assert result.returncode == 1
    assert 'wazuh python not found' in result.stderr


def test_wazuh_path_override_still_validates_interpreter(tmp_path):
    """Even with WAZUH_PATH exported, a missing interpreter is a hard, explicit error."""
    result = _run(env={'WAZUH_PATH': str(tmp_path)})
    assert result.returncode == 1
    assert 'wazuh python not found' in result.stderr
