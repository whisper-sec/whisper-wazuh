"""#35 — whisper-logs: the `from` watermark, cursor advance/persist, and logs_seen dedup."""

import json


def _cfg(wl, tmp_path, **over):
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


def _outer_rows(load_fixture):
    return load_fixture('agent_logs_envelope.json')['rows']


class TestWatermark:
    def test_request_uses_from_not_since(self, wl, router, load_fixture, tmp_path):
        router.add("op:'logs'", _outer_rows(load_fixture))
        wl.fetch_logs(_cfg(wl, tmp_path), 1784002000000)
        cypher = router.calls[-1][0]
        assert 'from:1784002000000' in cypher
        assert 'limit:1000' in cypher
        assert 'since' not in cypher  # the assumed `since` arg is silently ignored — never sent

    def test_first_run_omits_from(self, wl, router, load_fixture, tmp_path):
        router.add("op:'logs'", _outer_rows(load_fixture))
        wl.fetch_logs(_cfg(wl, tmp_path), None)
        cypher = router.calls[-1][0]
        assert 'from:' not in cypher and 'limit:1000' in cypher

    def test_agent_filter_inlined_when_valid(self, wl, router, load_fixture, tmp_path):
        router.add("op:'logs'", _outer_rows(load_fixture))
        wl.fetch_logs(_cfg(wl, tmp_path, agent='a98874349306a52c8'), 100)
        assert "agent:'a98874349306a52c8'" in router.calls[-1][0]


class TestCursorAdvance:
    def test_advance_to_max_plus_one(self, wl, load_fixture):
        result = load_fixture('agent_logs_envelope.json')['rows'][0]['result']
        recs = [dict(zip(result['columns'], row, strict=False)) for row in result['rows']]
        # max ts in the fixture is the closed-conn row
        assert wl.advance_cursor(recs) == 1784002496119 + 1

    def test_advance_empty(self, wl):
        assert wl.advance_cursor([]) is None


class TestCursorPersistence:
    def test_round_trip(self, wl, tmp_path):
        path = str(tmp_path / 'whisper' / 'logs-cursor')
        wl.save_cursor(path, 1784002496120)
        assert wl.load_cursor(path) == 1784002496120
        assert json.loads(open(path).read()) == {'from': 1784002496120}

    def test_missing_cursor_is_none(self, wl, tmp_path):
        assert wl.load_cursor(str(tmp_path / 'nope')) is None

    def test_corrupt_cursor_is_none(self, wl, tmp_path):
        p = tmp_path / 'bad'
        p.write_text('{not json')
        assert wl.load_cursor(str(p)) is None


class TestDedup:
    def _recs(self, load_fixture):
        result = load_fixture('agent_logs_envelope.json')['rows'][0]['result']
        return [dict(zip(result['columns'], row, strict=False)) for row in result['rows']]

    def test_composite_key_distinguishes_open_closed(self, wl, load_fixture):
        recs = self._recs(load_fixture)
        conns = [r for r in recs if r['kind'] == 'conn']
        # same agent+peer but different ts + reason → distinct keys (both conns must survive)
        assert wl.dedup_key(conns[0]) != wl.dedup_key(conns[1])

    def test_filter_new_then_seen_suppresses(self, wl, load_fixture):
        recs = self._recs(load_fixture)
        fresh, conn = wl.filter_new(recs)
        assert len(fresh) == len(recs)  # first sight: all new
        for r in fresh:
            wl.record_seen(conn, r)
        conn.close()
        # second poll re-fetches the same rows (inclusive `from`) → all suppressed
        fresh2, conn2 = wl.filter_new(recs)
        assert fresh2 == []
        if conn2:
            conn2.close()

    def test_boundary_ts_no_duplicate(self, wl, load_fixture):
        recs = self._recs(load_fixture)
        # emit just the newest (boundary) record, then re-present the whole batch
        boundary = max(recs, key=lambda r: r['ts'])
        _, conn = wl.filter_new([boundary])
        wl.record_seen(conn, boundary)
        conn.close()
        fresh, conn2 = wl.filter_new(recs)
        assert boundary not in fresh and len(fresh) == len(recs) - 1
        if conn2:
            conn2.close()

    def test_fail_open_on_cache_error(self, wl, monkeypatch, load_fixture):
        monkeypatch.setattr(wl.w, '_dedup_connect', lambda: None)
        recs = self._recs(load_fixture)
        fresh, conn = wl.filter_new(recs)
        assert fresh == recs and conn is None  # cache down → every record treated as new


class TestPollIntegration:
    def test_poll_emits_advances_and_dedups(self, wl, router, load_fixture, tmp_path):
        router.add("op:'logs'", _outer_rows(load_fixture))
        cfg = _cfg(wl, tmp_path)
        emitted = wl.poll(cfg)
        assert emitted == 5  # 2 conn + 2 dns + 1 alloc
        lines = open(cfg['spool']).read().splitlines()
        assert len(lines) == 5
        first = json.loads(lines[0])
        assert first['integration'] == 'whisper-logs' and 'whisper_agent' in first
        # cursor advanced to max+1
        assert wl.load_cursor(cfg['cursor_path']) == 1784002496119 + 1
        # second poll: same rows re-fetched, all deduped → nothing new appended
        emitted2 = wl.poll(cfg)
        assert emitted2 == 0
        assert len(open(cfg['spool']).read().splitlines()) == 5

    def test_poll_kind_filter(self, wl, router, load_fixture, tmp_path):
        router.add("op:'logs'", _outer_rows(load_fixture))
        cfg = _cfg(wl, tmp_path, kinds={'alloc'})
        assert wl.poll(cfg) == 1  # only the single alloc row
