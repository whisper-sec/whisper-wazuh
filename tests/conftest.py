"""Shared fixtures: load custom-whisper.py (hyphenated filename) as a module.

The shipped script keeps Wazuh's `<name>.py` naming convention, which is not
importable directly — load it via importlib once per session.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_WHISPER_DIR = Path(__file__).resolve().parent.parent / 'integrations' / 'whisper'
_SCRIPT = _WHISPER_DIR / 'custom-whisper.py'
_LOGS_SCRIPT = _WHISPER_DIR / 'whisper-logs.py'
# The connector does `import whisper_client` (its sibling in integrations/); put that dir on
# sys.path so the importlib-loaded connector resolves it — at runtime it is sys.path[0].
if str(_WHISPER_DIR) not in sys.path:
    sys.path.insert(0, str(_WHISPER_DIR))


def _load_module():
    spec = importlib.util.spec_from_file_location('whisper_integration', _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules['whisper_integration'] = module
    spec.loader.exec_module(module)
    return module


def _load_logs_module():
    spec = importlib.util.spec_from_file_location('whisper_logs', _LOGS_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules['whisper_logs'] = module
    spec.loader.exec_module(module)  # reuses sys.modules['whisper_integration'] as its `w`
    return module


@pytest.fixture(scope='session')
def whisper_module():
    return _load_module()


@pytest.fixture()
def wi(whisper_module, tmp_path, monkeypatch):
    """The module isolated for a test: logging to tmp, debug on, no real key/env leakage.

    KEY_FILE points into tmp (resolve_api_key reads the module global at call time) and
    the WHISPER_* env vars are cleared so main()-driving tests never read a developer's
    real credentials or config.
    """
    import whisper_client

    log_file = tmp_path / 'integrations.log'
    monkeypatch.setattr(whisper_module, 'LOG_FILE', str(log_file))
    monkeypatch.setattr(whisper_module, 'DEDUP_DB', str(tmp_path / 'whisper' / 'dedup.db'))
    monkeypatch.setattr(whisper_module, 'debug_enabled', True)
    # resolve_api_key reads whisper_client.KEY_FILE at call time — isolate it into tmp so a
    # main()-driven test never reads a developer's real /var/ossec/etc/whisper.key.
    monkeypatch.setattr(whisper_client, 'KEY_FILE', str(tmp_path / 'whisper.key'))
    for var in ('WHISPER_API_KEY', 'WHISPER_API_URL', 'WHISPER_DEDUP_TTL', 'WHISPER_DEDUP_SCOPE'):
        monkeypatch.delenv(var, raising=False)

    # Hard no-network guard: the unit tier must never reach the live API. execute_query lives
    # in whisper_client and calls whisper_client._http_post, so the guard MUST land there.
    # Tests that exercise transport behavior monkeypatch it themselves (see the wc fixture).
    def _no_network(*args, **kwargs):
        raise AssertionError('unit tests must not reach the network — mock execute_query/_http_post')

    monkeypatch.setattr(whisper_client, '_http_post', _no_network)
    whisper_module._test_log_file = log_file  # convenience handle for assertions
    return whisper_module


_CLI_SCRIPT = _WHISPER_DIR / 'whisper-investigate.py'


@pytest.fixture(scope='session')
def cli_module():
    spec = importlib.util.spec_from_file_location('whisper_investigate', _CLI_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules['whisper_investigate'] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def cli(cli_module, tmp_path, monkeypatch):
    """The whisper-investigate CLI isolated: no network (its _http_post binding is guarded),
    no key/env leakage, KEY_FILE in tmp. run_workflow tests override cli._http_post."""
    import whisper_client

    def _no_network(*args, **kwargs):
        raise AssertionError('mock cli._http_post in the test')

    monkeypatch.setattr(cli_module, '_http_post', _no_network)
    monkeypatch.setattr(whisper_client, 'KEY_FILE', str(tmp_path / 'whisper.key'))
    for var in ('WHISPER_API_KEY', 'WHISPER_MCP_URL'):
        monkeypatch.delenv(var, raising=False)
    return cli_module


@pytest.fixture()
def wc(tmp_path, monkeypatch):
    """The shared whisper_client module isolated for a transport/config test: no network,
    KEY_FILE in tmp. Transport tests override wc._http_post with their own sequence mock."""
    import whisper_client

    monkeypatch.setattr(whisper_client, 'KEY_FILE', str(tmp_path / 'whisper.key'))

    def _no_network(*args, **kwargs):
        raise AssertionError('mock whisper_client._http_post in the test')

    monkeypatch.setattr(whisper_client, '_http_post', _no_network)
    monkeypatch.setattr(whisper_client, 'log_api', lambda url, ms: None)
    return whisper_client


@pytest.fixture()
def router(wi, monkeypatch):
    """Route execute_query calls to canned rows; records every (cypher, params) call."""

    class Router:
        def __init__(self):
            self.routes = []  # (substring, ioc_filter, rows)
            self.calls = []

        def add(self, substring, rows, ioc=None):
            self.routes.append((substring, ioc, rows))

        def __call__(self, api_url, api_key, cypher, params=None, timeout=10, retries=3):
            self.calls.append((cypher, params))
            for substring, ioc, rows in self.routes:
                if substring in cypher and (
                    ioc is None or (params or {}).get('ioc', (params or {}).get('v')) == ioc
                ):
                    return rows if not callable(rows) else rows()
            return []

    r = Router()
    monkeypatch.setattr(wi, 'execute_query', r)
    return r


@pytest.fixture()
def log_lines(wi):
    """Callable returning the vocabulary lines written so far."""

    def _read():
        path = wi._test_log_file
        return path.read_text().splitlines() if path.exists() else []

    return _read


@pytest.fixture()
def wl(wi, tmp_path, monkeypatch):
    """The whisper-logs poller isolated for a test.

    Depends on `wi` so the SAME enrichment module (`whisper_integration`) is loaded, isolated
    (KEY_FILE/DEDUP_DB in tmp, no network) FIRST — the logs module reuses it as its `w`, so the
    existing `router` fixture (which patches `wi.execute_query`) also routes the poller's calls.
    All logs paths point into tmp; WHISPER_LOGS_* env is cleared.
    """
    module = _load_logs_module()
    monkeypatch.setattr(module, 'LOG_FILE', str(tmp_path / 'whisper-logs.log'))
    monkeypatch.setattr(module, 'SPOOL_DEFAULT', str(tmp_path / 'whisper-agent-activity.json'))
    monkeypatch.setattr(module, 'CURSOR_DEFAULT', str(tmp_path / 'whisper' / 'logs-cursor'))
    for var in (
        'WHISPER_LOGS_SINK',
        'WHISPER_LOGS_SPOOL',
        'WHISPER_LOGS_CURSOR',
        'WHISPER_LOGS_LIMIT',
        'WHISPER_LOGS_AGENT',
        'WHISPER_LOGS_KINDS',
    ):
        monkeypatch.delenv(var, raising=False)
    module._test_log_file = tmp_path / 'whisper-logs.log'
    module._tmp_path = tmp_path
    return module


@pytest.fixture()
def load_fixture():
    """Load a tests/fixtures/<name> JSON file."""
    fixtures = Path(__file__).resolve().parent / 'fixtures'

    def _load(name):
        return json.loads((fixtures / name).read_text())

    return _load


def _make_alert(**overrides):
    """A minimal realistic 4.14.5 alert; override nested parts per test."""
    alert = {
        'timestamp': '2026-07-05T10:00:00.000+0000',
        'id': '1751709600.123456',
        'rule': {'id': '5710', 'level': 5, 'groups': ['syslog', 'sshd', 'authentication_failed']},
        'agent': {'id': '001', 'name': 'dev-agent', 'ip': '172.19.0.5'},
        'manager': {'name': 'wazuh.manager'},
        'location': '/var/log/wazuh-demo.log',
        'full_log': 'Jul  5 10:00:00 server sshd[1234]: Failed password ...',
        'data': {},
    }
    alert.update(overrides)
    return alert


@pytest.fixture()
def make_alert():
    """Factory fixture — avoids importing conftest as a module (fragile across
    pytest import modes)."""
    return _make_alert


@pytest.fixture()
def write_alert(tmp_path):
    """Write a make_alert(...) dict to disk and return the path (for main()-driving tests)."""

    def _write(**overrides):
        path = tmp_path / 'test.alert'
        path.write_text(json.dumps(_make_alert(**overrides)))
        return str(path)

    return _write
