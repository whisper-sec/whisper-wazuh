"""#36 review follow-up — whisper-logs hardening.

Covers the fixes for the review findings: crash-safety against malformed control-plane
responses (a bad batch must never wedge the poller), the limit-hit telemetry-gap alert,
config resolution, main() exit codes, dedup composite-key distinctness, and identity
auth propagation.
"""

import pytest

_COLS = ['ts', 'kind', 'decision', 'qname', 'agent']


def _cfg(tmp_path, **over):
    cfg = {
        'api_url': 'https://graph.whisper.online',
        'api_key': 'k',
        'timeout': 10,
        'retries': 3,
        'sink': 'logcollector',
        'spool': str(tmp_path / 'spool.json'),
        'cursor_path': str(tmp_path / 'whisper' / 'logs-cursor'),
        'limit': 1000,
        'agent': '',
        'kinds': {'dns', 'conn', 'alloc'},
    }
    cfg.update(over)
    return cfg


def _ok(rows, columns=_COLS, op='logs'):
    """An OK outer proxy envelope wrapping a columnar inner result."""
    return [
        {
            'op': op,
            'ok': True,
            'status': 200,
            'result': {'columns': columns, 'rows': rows},
            'error': None,
            'retry_after': None,
        }
    ]


def _err(status, op='logs'):
    return [{'op': op, 'ok': False, 'status': status, 'result': None, 'error': 'boom', 'retry_after': None}]


# --- crash-safety: a malformed batch must degrade, never wedge the poll --------------------
class TestMalformedRowsDoNotCrash:
    def test_non_iterable_rows_skipped(self, wl, router, tmp_path):
        # a null cell-row and a bare scalar must be skipped, the good row survives (no TypeError)
        router.add("op:'logs'", _ok([[100, 'dns', 'allow', 'a.com', None], None, 42]))
        recs = wl.fetch_logs(_cfg(tmp_path), None)
        assert len(recs) == 1 and recs[0]['kind'] == 'dns'

    def test_short_and_long_rows_degrade(self, wl, router, tmp_path):
        router.add("op:'logs'", _ok([[100, 'dns'], [101, 'dns', 'allow', 'b.com', 'a1', 'EXTRA']]))
        recs = wl.fetch_logs(_cfg(tmp_path), None)
        assert recs[0] == {'ts': 100, 'kind': 'dns'}  # short: missing keys, no crash
        assert recs[1]['agent'] == 'a1' and 'EXTRA' not in recs[1].values()  # long: extra dropped

    def test_non_string_column_rejected(self, wl, router, tmp_path):
        router.add("op:'logs'", _ok([[100, 'dns']], columns=[['bad'], 'kind']))
        with pytest.raises(wl.w.WhisperQueryError):
            wl.fetch_logs(_cfg(tmp_path), None)


class TestNonFiniteTs:
    def test_advance_cursor_ignores_nan_inf_bool(self, wl):
        recs = [{'ts': float('nan')}, {'ts': float('inf')}, {'ts': True}, {'ts': 1784002495932}]
        assert wl.advance_cursor(recs) == 1784002495932 + 1  # only the real ts counts

    def test_advance_cursor_all_bad_is_none(self, wl):
        assert wl.advance_cursor([{'ts': float('nan')}, {'ts': True}]) is None

    def test_project_rejects_bool_and_nonfinite_ts(self, wl):
        assert wl.project({'ts': True, 'kind': 'dns'}, {}) is None
        assert wl.project({'ts': float('nan'), 'kind': 'dns'}, {}) is None
        assert wl.project({'ts': float('inf'), 'kind': 'conn'}, {}) is None
        # a real ts still projects
        assert wl.project({'ts': 1784002495932, 'kind': 'alloc', 'agent': 'a1'}, {}) is not None


class TestNonStringAgentId:
    def test_resolve_identity_guards_non_str(self, wl, tmp_path):
        cfg = _cfg(tmp_path)
        assert wl.resolve_identity(cfg, 123, {}) == {}
        assert wl.resolve_identity(cfg, ['x'], {}) == {}
        assert wl.resolve_identity(cfg, '', {}) == {}

    def test_poll_survives_int_agent(self, wl, router, tmp_path):
        router.add("op:'logs'", _ok([[100, 'dns', 'allow', 'a.com', 42]]))  # agent is an int
        assert wl.poll(_cfg(tmp_path)) == 1  # no crash; the row still emits


class TestPerRecordIsolation:
    def test_one_bad_row_does_not_sink_the_batch(self, wl, router, tmp_path, monkeypatch):
        router.add(
            "op:'logs'", _ok([[100, 'dns', 'allow', 'a.com', None], [101, 'dns', 'allow', 'b.com', None]])
        )
        real = wl.project

        def flaky(rec, identity):
            if rec.get('qname') == 'a.com':
                raise ValueError('boom')
            return real(rec, identity)

        monkeypatch.setattr(wl, 'project', flaky)
        assert wl.poll(_cfg(tmp_path)) == 1  # the good row still emits


# --- limit-hit → telemetry-gap alert (no silent loss) --------------------------------------
class TestGapAlert:
    def test_limit_hit_emits_gap_event(self, wl, router, tmp_path):
        router.add(
            "op:'logs'", _ok([[100, 'dns', 'allow', 'a.com', None], [101, 'dns', 'allow', 'b.com', None]])
        )
        cfg = _cfg(tmp_path, limit=2)
        emitted = wl.poll(cfg)
        assert emitted == 2  # the gap alert is NOT counted as an activity event
        spool = (tmp_path / 'spool.json').read_text()
        assert '"kind":"gap"' in spool and '"limit":2' in spool
        assert wl.load_cursor(cfg['cursor_path']) == 101 + 1  # cursor still advances

    def test_no_gap_below_limit(self, wl, router, tmp_path):
        router.add("op:'logs'", _ok([[100, 'dns', 'allow', 'a.com', None]]))
        wl.poll(_cfg(tmp_path, limit=1000))
        assert '"kind":"gap"' not in (tmp_path / 'spool.json').read_text()


# --- cursor loss is loud, not silent -------------------------------------------------------
class TestCursorObservability:
    def test_corrupt_cursor_logs_and_resets(self, wl, tmp_path):
        path = tmp_path / 'whisper' / 'logs-cursor'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{ this is not json')
        assert wl.load_cursor(str(path)) is None
        assert any('unreadable' in ln for ln in wl._test_log_file.read_text().splitlines())

    def test_missing_cursor_is_silent_first_run(self, wl, tmp_path):
        assert wl.load_cursor(str(tmp_path / 'nope')) is None
        assert not wl._test_log_file.exists() or 'unreadable' not in wl._test_log_file.read_text()


# --- config resolution ---------------------------------------------------------------------
class TestResolveConfig:
    def test_sink_fallback(self, wl):
        cfg = wl.resolve_config(['whisper-logs'], {'WHISPER_API_KEY': 'k', 'WHISPER_LOGS_SINK': 'bogus'})
        assert cfg['sink'] == 'logcollector'

    def test_invalid_agent_rejected_and_logged(self, wl):
        cfg = wl.resolve_config(['whisper-logs'], {'WHISPER_API_KEY': 'k', 'WHISPER_LOGS_AGENT': "a'; DROP"})
        assert cfg['agent'] == ''
        assert any('WHISPER_LOGS_AGENT' in ln for ln in wl._test_log_file.read_text().splitlines())

    def test_kinds_parsing(self, wl):
        good = wl.resolve_config(['x'], {'WHISPER_API_KEY': 'k', 'WHISPER_LOGS_KINDS': 'dns,bogus'})
        assert good['kinds'] == {'dns'}
        junk = wl.resolve_config(['x'], {'WHISPER_API_KEY': 'k', 'WHISPER_LOGS_KINDS': 'junk'})
        assert junk['kinds'] == set(wl.ALL_KINDS)

    def test_limit_clamped(self, wl):
        hi = wl.resolve_config(['x'], {'WHISPER_API_KEY': 'k', 'WHISPER_LOGS_LIMIT': '99999'})
        assert hi['limit'] == wl.MAX_LIMIT  # above the cap → clamped down
        mid = wl.resolve_config(['x'], {'WHISPER_API_KEY': 'k', 'WHISPER_LOGS_LIMIT': '50'})
        assert mid['limit'] == 50  # in range → passthrough
        # non-positive / invalid falls back to the default (never below 1)
        for bad in ('0', '-5', 'nope', ''):
            cfg = wl.resolve_config(['x'], {'WHISPER_API_KEY': 'k', 'WHISPER_LOGS_LIMIT': bad})
            assert cfg['limit'] == wl.DEFAULT_LIMIT and cfg['limit'] >= 1


# --- main() exit-code taxonomy -------------------------------------------------------------
class TestMainExitCodes:
    def test_no_key_returns_2(self, wl):
        assert wl.main(['whisper-logs']) == 2  # wl fixture clears the key + points KEY_FILE at tmp

    def test_auth_returns_8(self, wl, router, monkeypatch):
        monkeypatch.setenv('WHISPER_API_KEY', 'k')
        router.add("op:'logs'", _err(401))
        assert wl.main(['whisper-logs']) == 8

    def test_query_error_returns_1(self, wl, router, monkeypatch):
        monkeypatch.setenv('WHISPER_API_KEY', 'k')
        router.add("op:'logs'", _err(400))
        assert wl.main(['whisper-logs']) == 1

    def test_success_returns_0(self, wl, router, monkeypatch):
        monkeypatch.setenv('WHISPER_API_KEY', 'k')
        router.add("op:'logs'", _ok([[100, 'dns', 'allow', 'a.com', None]]))
        assert wl.main(['whisper-logs']) == 0


# --- dedup composite key + identity auth propagation ---------------------------------------
class TestDedupCompositeKey:
    def test_same_ms_distinct_who_why_are_distinct_keys(self, wl):
        base = {'agent': 'a1', 'ts': 100, 'kind': 'dns'}
        allow = wl.dedup_key({**base, 'qname': 'x.com', 'decision': 'allow'})
        refused = wl.dedup_key({**base, 'qname': 'x.com', 'decision': 'refused'})
        other_q = wl.dedup_key({**base, 'qname': 'y.com', 'decision': 'allow'})
        assert len({allow, refused, other_q}) == 3  # who/why both discriminate

    def test_filter_new_keeps_both_same_ms_events(self, wl):
        a = {'agent': 'a1', 'ts': 100, 'kind': 'dns', 'qname': 'x.com', 'decision': 'allow'}
        b = {'agent': 'a1', 'ts': 100, 'kind': 'dns', 'qname': 'x.com', 'decision': 'refused'}
        fresh, conn = wl.filter_new([a, b])
        try:
            assert len(fresh) == 2  # same ms, different decision → both survive dedup
        finally:
            if conn is not None:
                conn.close()


class TestIdentityAuthPropagation:
    def test_identity_401_aborts_the_poll(self, wl, router, tmp_path):
        router.add("op:'logs'", _ok([[100, 'dns', 'allow', 'a.com', 'a98874349306a52c8']]))
        router.add("op:'identity'", _err(401, op='identity'))
        with pytest.raises(wl.w.WhisperAuthError):
            wl.poll(_cfg(tmp_path))


# --- CALL-arg injection hardening ----------------------------------------------------------
class TestArgSafety:
    def test_unsafe_string_arg_rejected(self, wl):
        with pytest.raises(wl.w.WhisperQueryError):
            wl._args_literal({'agent': "x'; MATCH (n) DETACH DELETE n //"})

    def test_safe_args_render(self, wl):
        out = wl._args_literal({'agent': 'a98874349306a52c8', 'limit': 10, 'from': 5})
        assert "agent:'a98874349306a52c8'" in out and 'limit:10' in out and 'from:5' in out


# --- socket sink: per-event dedup so a mid-batch failure re-delivers only the suffix -------
class TestSocketSink:
    def test_socket_records_per_event(self, wl, router, tmp_path, monkeypatch):
        sent = []
        monkeypatch.setattr(wl.w, 'send_event', lambda payload, loc: sent.append(payload))
        router.add(
            "op:'logs'", _ok([[100, 'dns', 'allow', 'a.com', None], [101, 'dns', 'allow', 'b.com', None]])
        )
        cfg = _cfg(tmp_path, sink='socket')
        assert wl.poll(cfg) == 2 and len(sent) == 2  # the socket branch actually ran
        sent.clear()
        assert wl.poll(cfg) == 0 and sent == []  # both recorded → a re-poll dedups to nothing

    def test_socket_mid_batch_failure_records_prefix(self, wl, router, tmp_path, monkeypatch):
        """Per-event record_seen: a send failure on row 2 leaves row 1 recorded, so recovery
        re-delivers only the un-sent suffix — NOT the whole batch (the old post-loop record did)."""
        sent = []

        def flaky_send(payload, loc):
            sent.append(payload)
            if len(sent) == 2:
                raise RuntimeError('socket down')

        monkeypatch.setattr(wl.w, 'send_event', flaky_send)
        router.add(
            "op:'logs'", _ok([[100, 'dns', 'allow', 'a.com', None], [101, 'dns', 'allow', 'b.com', None]])
        )
        cfg = _cfg(tmp_path, sink='socket')
        with pytest.raises(RuntimeError):
            wl.poll(cfg)  # row 1 sent+recorded, row 2 send raises before its record

        good = []
        monkeypatch.setattr(wl.w, 'send_event', lambda payload, loc: good.append(payload))
        assert wl.poll(cfg) == 1 and len(good) == 1  # only the suffix (row 1 was deduped)


class TestMainCatchAll:
    def test_unexpected_error_returns_1(self, wl, monkeypatch):
        """A non-Whisper/non-OSError from poll must degrade to exit 1 + a log line, never a bare
        traceback out of the scheduled wodle."""
        monkeypatch.setenv('WHISPER_API_KEY', 'k')

        def boom(cfg, cursor):
            raise RuntimeError('unexpected')

        monkeypatch.setattr(wl, 'fetch_logs', boom)
        assert wl.main(['whisper-logs']) == 1
        assert any('unexpected error' in ln for ln in wl._test_log_file.read_text().splitlines())
