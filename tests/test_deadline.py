"""Wall-clock budget + IOC cap for the synchronous integratord callout (upstream review, #107).

integratord runs integrations serially, one alert at a time, so one slow or blackholed API
call must cost seconds, not minutes: a per-invocation deadline bounds every query (threaded
through the execute_query wrapper) and is re-checked before each IOC, and an IOC cap bounds
the worst case for a single alert.
"""

import json

import pytest


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

    def test_global_is_reset_after_main(self, wi, write_alert, monkeypatch):
        """The stamp lives in a module global; main() must never leak it into a later caller
        (the poller imports this module and must get deadline=None)."""
        monkeypatch.setattr(wi, 'enrich', lambda *a, **k: {'integration': wi.INTEGRATION_NAME, 'whisper': {}})
        monkeypatch.setattr(wi, 'send_event', lambda payload, agent: 1)
        monkeypatch.setattr(wi, 'record_dedup', lambda key, ttl=0: None)
        wi.main(['s', write_alert(data={'srcip': '185.220.101.1'}), '', '', 'debug'])
        assert wi._INVOCATION_DEADLINE is None


# --- the cap bounds enrichment WORK, not candidates --------------------------------------
class TestIocCapCountsWork:
    def test_dedup_hits_do_not_consume_a_slot(self, wi, write_alert, log_lines, monkeypatch, tmp_path):
        enriched = []
        monkeypatch.setattr(wi, 'enrich', _emitting_enrich(wi, enriched))
        monkeypatch.setattr(wi, 'send_event', lambda payload, agent: 100)
        monkeypatch.setattr(wi, 'record_dedup', lambda key, ttl=0: None)
        monkeypatch.setattr(wi, 'check_dedup', lambda key, ttl: key.startswith('ipv4|'))  # the IP is cached
        alert_file = write_alert(data={'srcip': '185.220.101.1', 'dns': {'rrname': 'evil.example'}})
        assert wi.main(['s', alert_file, '', '', 'debug', _opts(tmp_path, max_iocs=1)]) == 0
        assert enriched == ['evil.example']  # the free cache hit did not use up the single slot
        assert not any('skip reason=max-iocs' in ln for ln in log_lines())


# --- the SIGALRM hard ceiling -------------------------------------------------------------
def _fake_timer(wi, monkeypatch):
    """Capture the itimer instead of arming a real one (deterministic: no timers, no sleeps)."""
    armed = []
    monkeypatch.setattr(wi.signal, 'signal', lambda signum, handler: 'PREVIOUS')
    monkeypatch.setattr(wi.signal, 'setitimer', lambda which, seconds: armed.append(seconds))
    return armed


class TestHardCeiling:
    """A socket operation that stalls past the deadline (a server dripping one byte at a time, a hung
    resolver) never trips a per-request timeout, so the alarm is what cuts it. The handler is
    invoked directly, exactly as SIGALRM would mid-read."""

    def test_armed_with_grace_and_disarmed_in_finally(self, wi, write_alert, monkeypatch):
        armed = _fake_timer(wi, monkeypatch)
        monkeypatch.setattr(wi, 'enrich', lambda *a, **k: {'integration': wi.INTEGRATION_NAME, 'whisper': {}})
        monkeypatch.setattr(wi, 'send_event', lambda payload, agent: 1)
        monkeypatch.setattr(wi, 'record_dedup', lambda key, ttl=0: None)
        assert wi.main(['s', write_alert(data={'srcip': '185.220.101.1'}), '', '', 'debug']) == 0
        assert armed == [wi.DEFAULT_DEADLINE + 1.0, 0]  # +1 s grace so the precise path wins; cleared after

    def test_alarm_inside_a_query_cuts_that_ioc(self, wi, write_alert, log_lines, monkeypatch):
        armed = _fake_timer(wi, monkeypatch)

        def stalled_enrich(ioc, *a, **k):
            wi._hard_ceiling_handler(14, None)  # SIGALRM firing inside a blocked read

        monkeypatch.setattr(wi, 'enrich', stalled_enrich)
        alert_file = write_alert(data={'srcip': '185.220.101.1', 'dns': {'rrname': 'evil.example'}})
        assert wi.main(['s', alert_file, '', '', 'debug']) == 1  # nothing emitted → non-zero (TC-13)
        assert sum('error class=transport detail=hard ceiling' in ln for ln in log_lines()) == 2
        assert armed[-1] == 0 and wi._INVOCATION_DEADLINE is None

    def test_alarm_outside_a_query_stops_the_run(self, wi, write_alert, log_lines, monkeypatch):
        _fake_timer(wi, monkeypatch)
        calls = []
        monkeypatch.setattr(wi, 'enrich', lambda *a, **k: calls.append(a))

        def stalled_dedup(key, ttl):
            wi._hard_ceiling_handler(14, None)

        monkeypatch.setattr(wi, 'check_dedup', stalled_dedup)
        alert_file = write_alert(data={'srcip': '185.220.101.1', 'dns': {'rrname': 'evil.example'}})
        assert wi.main(['s', alert_file, '', '', 'debug']) == 1
        assert calls == []  # stopped outright, no further IOC started
        assert sum('hard ceiling' in ln for ln in log_lines()) == 1

    def test_auth_return_still_disarms(self, wi, write_alert, monkeypatch):
        armed = _fake_timer(wi, monkeypatch)

        def dead_key(*a, **k):
            raise wi.WhisperAuthError('401')

        monkeypatch.setattr(wi, 'enrich', dead_key)
        assert wi.main(['s', write_alert(data={'srcip': '185.220.101.1'}), '', '', 'debug']) == wi.ERR_AUTH
        assert armed[-1] == 0 and wi._INVOCATION_DEADLINE is None

    def test_unsupported_platform_is_a_noop(self, wi, monkeypatch):
        monkeypatch.delattr(wi.signal, 'setitimer', raising=False)
        assert wi._arm_hard_ceiling(21.0) is None
        wi._disarm_hard_ceiling(None)  # must not raise


# --- the deadline is a typed transport error, not a substring ----------------------------
class TestDeadlineTaxonomy:
    def test_typed_and_classified_as_transport(self, wc):
        with pytest.raises(wc.WhisperDeadlineError) as e:
            wc._effective_timeout(wc.time.monotonic() - 1, 10)
        assert isinstance(e.value, wc.WhisperTransportError) and e.value.log_class == 'transport'

    def test_backoff_error_keeps_its_cause(self, wc):
        with pytest.raises(wc.WhisperDeadlineError, match='after HTTP 429'):
            wc._sleep_within(5.0, wc.time.monotonic() + 1.0, 'HTTP 429')

    def test_context_note_keys_on_the_type_not_the_message(self, wi, monkeypatch):
        """An API error whose TEXT mentions a deadline is still 'degraded (query)'; only the typed
        WhisperDeadlineError is reported as 'context skipped (deadline)'."""
        notes_seen = {}
        base = {
            'available': True,
            'found': True,
            'score': 50.0,
            'level': 'HIGH',
            'sources': [],
            'factors': [],
        }
        monkeypatch.setattr(wi, 'call_explain', lambda cfg, ioc: dict(base))
        monkeypatch.setattr(wi, 'fetch_flags', lambda cfg, ioc, t: {})  # node exists, no flags

        def fragments_raising(exc):
            def _f(cfg, ioc, ioc_type, flags, notes):
                raise exc

            return _f

        for exc, expected in (
            (
                wi.WhisperQueryError('HTTP 400: query deadline exceeded'),
                'context enrichment degraded (query)',
            ),
            (wi.WhisperDeadlineError('deadline exceeded before request'), 'context skipped (deadline)'),
        ):
            monkeypatch.setattr(wi, 'build_ip_fragments', fragments_raising(exc))
            payload = wi.enrich('185.220.101.1', 'ipv4', 'k', {}, 'u', None, 10, 3)
            notes_seen[expected] = payload['whisper'].get('unmapped_summary', '')
        assert 'context enrichment degraded (query)' in notes_seen['context enrichment degraded (query)']
        assert 'context skipped (deadline)' not in notes_seen['context enrichment degraded (query)']
        assert 'context skipped (deadline)' in notes_seen['context skipped (deadline)']
