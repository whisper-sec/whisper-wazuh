"""Wall-clock budget + IOC cap for the synchronous integratord callout (upstream review, #107).

integratord runs integrations serially, one alert at a time, so one slow or blackholed API
call must cost seconds, not minutes: a per-invocation deadline bounds every query (threaded
through the execute_query wrapper) and is re-checked before each IOC, and an IOC cap bounds
the worst case for a single alert.
"""

import json


def _opts(tmp_path, **kv):
    path = tmp_path / 'options.json'
    path.write_text(json.dumps(kv))
    return str(path)


def _emitting_enrich(wi, seen):
    def fake(ioc, *a, **k):
        seen.append(ioc)
        return {'integration': wi.INTEGRATION_NAME, 'whisper': {'ioc': ioc}}

    return fake


class TestResolvers:
    def test_deadline_options_env_default(self, wi):
        assert wi.resolve_deadline({'deadline': 7}, {}) == 7
        assert wi.resolve_deadline({}, {'WHISPER_DEADLINE': '9'}) == 9
        assert wi.resolve_deadline({'deadline': 7}, {'WHISPER_DEADLINE': '9'}) == 7  # options win
        for bad in (0, -3, 'nope', True, None):
            assert wi.resolve_deadline({'deadline': bad}, {}) == wi.DEFAULT_DEADLINE
        assert 1 <= wi.DEFAULT_DEADLINE <= 30  # seconds, not minutes

    def test_max_iocs_options_env_default(self, wi):
        assert wi.resolve_max_iocs({'max_iocs': 2}, {}) == 2
        assert wi.resolve_max_iocs({}, {'WHISPER_MAX_IOCS': '3'}) == 3
        for bad in (0, -1, 'x', False):
            assert wi.resolve_max_iocs({'max_iocs': bad}, {}) == wi.DEFAULT_MAX_IOCS


class TestIocCap:
    def test_extra_iocs_are_skipped_not_enriched(self, wi, write_alert, log_lines, monkeypatch, tmp_path):
        enriched = []
        monkeypatch.setattr(wi, 'enrich', _emitting_enrich(wi, enriched))
        monkeypatch.setattr(wi, 'send_event', lambda payload, agent: 100)
        monkeypatch.setattr(wi, 'record_dedup', lambda key, ttl=0: None)
        alert_file = write_alert(data={'srcip': '185.220.101.1', 'dns': {'rrname': 'evil.example'}})
        rc = wi.main(['s', alert_file, '', '', 'debug', _opts(tmp_path, max_iocs=1)])
        assert rc == 0
        assert enriched == ['185.220.101.1']  # only the first candidate
        assert any('whisper: skip reason=max-iocs ioc=evil.example limit=1' in line for line in log_lines())


class TestDeadline:
    def test_remaining_iocs_skipped_once_budget_is_spent(self, wi, write_alert, log_lines, monkeypatch):
        """IOC #1 enriches, but 'took forever'; IOC #2 is then skipped without touching the API."""
        enriched = []
        clock = {'t': 0.0}
        monkeypatch.setattr(wi.time, 'monotonic', lambda: clock['t'])

        def slow_enrich(ioc, *a, **k):
            enriched.append(ioc)
            clock['t'] = 999.0  # well past DEFAULT_DEADLINE
            return {'integration': wi.INTEGRATION_NAME, 'whisper': {'ioc': ioc}}

        monkeypatch.setattr(wi, 'enrich', slow_enrich)
        monkeypatch.setattr(wi, 'send_event', lambda payload, agent: 100)
        monkeypatch.setattr(wi, 'record_dedup', lambda key, ttl=0: None)
        alert_file = write_alert(data={'srcip': '185.220.101.1', 'dns': {'rrname': 'evil.example'}})
        rc = wi.main(['s', alert_file, '', '', 'debug'])
        assert rc == 0  # one emit landed → success (TC-15)
        assert enriched == ['185.220.101.1']
        assert any('whisper: skip reason=deadline ioc=evil.example' in line for line in log_lines())

    def test_budget_already_spent_skips_everything_and_exits_nonzero(
        self, wi, write_alert, log_lines, monkeypatch
    ):
        """Clock jumps past the deadline right after the stamp: no IOC enriched, no API call, exit 1."""
        calls = []
        monkeypatch.setattr(wi, 'enrich', lambda *a, **k: calls.append(a))
        ticks = iter([0.0] + [999.0] * 50)  # first read = the stamp; every later read = expired
        monkeypatch.setattr(wi.time, 'monotonic', lambda: next(ticks))
        alert_file = write_alert(data={'srcip': '185.220.101.1', 'dns': {'rrname': 'evil.example'}})
        assert wi.main(['s', alert_file, '', '', 'debug']) == 1
        assert calls == []
        assert sum('skip reason=deadline' in line for line in log_lines()) == 2

    def test_deadline_is_threaded_into_every_query(self, wi, monkeypatch):
        """The connector's execute_query wrapper hands the invocation deadline to the client."""
        seen = {}

        def fake_client_eq(api_url, api_key, cypher, params=None, timeout=10, retries=3, deadline=None):
            seen['deadline'] = deadline
            return []

        monkeypatch.setattr(wi, '_client_execute_query', fake_client_eq)
        monkeypatch.setattr(wi, '_INVOCATION_DEADLINE', 12345.0)
        wi.execute_query('u', 'k', 'RETURN 1', None, 10, 3)
        assert seen['deadline'] == 12345.0
