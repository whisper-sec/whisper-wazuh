"""#35 — whisper-logs: outer proxy-envelope unwrap + error taxonomy (never a traceback)."""

import pytest


def _env(**over):
    base = {'op': 'logs', 'ok': True, 'status': 200, 'result': {'columns': [], 'rows': []}, 'error': None}
    base.update(over)
    return [base]


class TestUnwrapSuccess:
    def test_unwrap_columnar_result(self, wl, load_fixture):
        outer = load_fixture('agent_logs_envelope.json')['rows']
        columns, rows = wl._unwrap(outer, 'logs')
        assert columns[0] == 'ts' and columns[1] == 'kind'
        assert len(rows) == 5

    def test_empty_result_ok(self, wl):
        columns, rows = wl._unwrap(_env(), 'logs')
        assert rows == []


class TestErrorTaxonomy:
    def test_bad_args_is_query_error(self, wl):
        with pytest.raises(wl.w.WhisperQueryError):
            wl._unwrap(_env(ok=False, status=400, error='BAD_ARGS'), 'logs')

    def test_auth_401_terminal(self, wl):
        with pytest.raises(wl.w.WhisperAuthError):
            wl._unwrap(_env(ok=False, status=401, error='unauthorized'), 'logs')

    def test_auth_403_terminal(self, wl):
        with pytest.raises(wl.w.WhisperAuthError):
            wl._unwrap(_env(ok=False, status=403, error='forbidden'), 'logs')

    def test_429_transport(self, wl):
        with pytest.raises(wl.w.WhisperTransportError):
            wl._unwrap(_env(ok=False, status=429, error='slow down'), 'logs')

    def test_5xx_transport(self, wl):
        with pytest.raises(wl.w.WhisperTransportError):
            wl._unwrap(_env(ok=False, status=503, error='unavailable'), 'logs')

    def test_error_field_without_status(self, wl):
        with pytest.raises(wl.w.WhisperQueryError):
            wl._unwrap(_env(status=200, error='surprise'), 'logs')


class TestMalformed:
    def test_empty_envelope(self, wl):
        with pytest.raises(wl.w.WhisperQueryError):
            wl._unwrap([], 'logs')

    def test_result_not_columnar(self, wl):
        with pytest.raises(wl.w.WhisperQueryError):
            wl._unwrap(_env(result={'not': 'columnar'}), 'logs')

    def test_result_none(self, wl):
        with pytest.raises(wl.w.WhisperQueryError):
            wl._unwrap(_env(result=None), 'logs')
