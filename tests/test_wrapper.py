"""The sh wrappers must fail loudly — never exec an empty script path."""

import subprocess
from pathlib import Path

_WHISPER = Path(__file__).resolve().parent.parent / 'integrations' / 'whisper'
WRAPPER = _WHISPER / 'custom-whisper'
INVESTIGATE_WRAPPER = _WHISPER / 'whisper-investigate'


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


def test_investigate_wrapper_parses():
    r = subprocess.run(['sh', '-n', str(INVESTIGATE_WRAPPER)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_investigate_wrapper_fails_loudly_without_python():
    """The whisper-investigate wrapper mirrors the connector's — no /var/ossec python on a
    dev machine → clear error, never exec the IOC arg as Python."""
    r = subprocess.run(
        ['sh', str(INVESTIGATE_WRAPPER), '8.8.8.8'], capture_output=True, text=True, env={}, timeout=10
    )
    assert r.returncode == 1
    assert 'wazuh python not found' in r.stderr
