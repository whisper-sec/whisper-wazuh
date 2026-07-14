"""#35 — whisper-logs sh wrapper: POSIX-parseable and pairs its .py loudly."""

import subprocess
from pathlib import Path

WRAPPER = Path(__file__).resolve().parent.parent / 'integrations' / 'whisper' / 'whisper-logs'


def test_wrapper_parses_as_posix_sh():
    r = subprocess.run(['sh', '-n', str(WRAPPER)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_wrapper_pairs_the_py_script():
    t = WRAPPER.read_text()
    assert 'PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"' in t
    # fails loudly (exit 1) when the interpreter or script is missing
    assert 'integration script not found' in t
    assert 'wazuh python not found' in t


def test_wrapper_execs_bundled_python():
    t = WRAPPER.read_text()
    assert 'framework/python/bin/python3' in t
    assert 'exec "${PYTHON_BIN}" "${PYTHON_SCRIPT}" "$@"' in t
