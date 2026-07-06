"""#15 — persistent SQLite dedup cache (mapping §7; TC-09/TC-10/TC-17)."""


class TestDedupBasics:
    def test_empty_cache_does_not_suppress(self, wi):
        assert wi.check_dedup('ipv4|1.2.3.4|001', 3600) is False

    def test_record_then_check_suppresses(self, wi):
        wi.record_dedup('ipv4|1.2.3.4|001')
        assert wi.check_dedup('ipv4|1.2.3.4|001', 3600) is True

    def test_different_key_not_suppressed(self, wi):
        wi.record_dedup('ipv4|1.2.3.4|001')
        assert wi.check_dedup('ipv4|1.2.3.4|002', 3600) is False
        assert wi.check_dedup('domain|evil.example|001', 3600) is False

    def test_ttl_zero_disables_dedup(self, wi):
        wi.record_dedup('ipv4|1.2.3.4|001')
        assert wi.check_dedup('ipv4|1.2.3.4|001', 0) is False
        assert wi.check_dedup('ipv4|1.2.3.4|001', -5) is False


class TestDedupExpiry:
    def test_expired_entry_not_suppressed(self, wi, monkeypatch):
        clock = {'t': 1_000_000.0}
        monkeypatch.setattr(wi.time, 'time', lambda: clock['t'])
        wi.record_dedup('ipv4|1.2.3.4|001')
        clock['t'] += 3601  # just past a 3600s TTL
        assert wi.check_dedup('ipv4|1.2.3.4|001', 3600) is False

    def test_within_ttl_still_suppressed(self, wi, monkeypatch):
        clock = {'t': 1_000_000.0}
        monkeypatch.setattr(wi.time, 'time', lambda: clock['t'])
        wi.record_dedup('ipv4|1.2.3.4|001')
        clock['t'] += 3599
        assert wi.check_dedup('ipv4|1.2.3.4|001', 3600) is True

    def test_boundary_exactly_at_ttl_not_suppressed(self, wi, monkeypatch):
        """Age == ttl exactly → not suppressed (strict `< ttl`)."""
        clock = {'t': 1_000_000.0}
        monkeypatch.setattr(wi.time, 'time', lambda: clock['t'])
        wi.record_dedup('ipv4|1.2.3.4|001', 3600)
        clock['t'] += 3600  # exactly the TTL
        assert wi.check_dedup('ipv4|1.2.3.4|001', 3600) is False

    def test_future_timestamp_not_suppressed(self, wi, monkeypatch):
        """A clock step-back (stored ts in the future) must NOT hold back enrichment."""
        clock = {'t': 1_000_000.0}
        monkeypatch.setattr(wi.time, 'time', lambda: clock['t'])
        wi.record_dedup('ipv4|1.2.3.4|001', 3600)
        clock['t'] -= 500  # clock stepped backward → stored ts is now in the "future"
        assert wi.check_dedup('ipv4|1.2.3.4|001', 3600) is False

    def test_prune_happens_in_record_not_check(self, wi, monkeypatch):
        """Pruning moved off the hot read path: check never deletes; a later record prunes."""
        import sqlite3

        clock = {'t': 1_000_000.0}
        monkeypatch.setattr(wi.time, 'time', lambda: clock['t'])
        wi.record_dedup('old|x|001', 3600)
        clock['t'] += 7200

        def rowcount():
            conn = sqlite3.connect(wi.DEDUP_DB)
            try:
                return conn.execute('SELECT count(*) FROM dedup').fetchone()[0]
            finally:
                conn.close()

        wi.check_dedup('anything', 3600)  # read-only — must NOT prune
        assert rowcount() == 1  # stale row still present after a check
        wi.record_dedup('new|y|001', 3600)  # this prunes expired rows
        assert rowcount() == 1  # 'old' pruned, 'new' inserted → net 1

    def test_sliding_window_resets_on_re_record(self, wi, monkeypatch):
        """Re-recording (a genuine post-expiry re-emit) resets the suppression window."""
        clock = {'t': 1_000_000.0}
        monkeypatch.setattr(wi.time, 'time', lambda: clock['t'])
        wi.record_dedup('ipv4|1.2.3.4|001', 3600)
        clock['t'] += 3601  # expired
        assert wi.check_dedup('ipv4|1.2.3.4|001', 3600) is False  # would re-emit
        wi.record_dedup('ipv4|1.2.3.4|001', 3600)  # re-emit records anew
        clock['t'] += 1
        assert wi.check_dedup('ipv4|1.2.3.4|001', 3600) is True  # window slid forward


class TestDedupPersistenceAndFlush:
    def test_persists_across_connections(self, wi):
        """Each call opens a fresh connection — the on-disk DB is what makes it survive the
        per-alert process spawn (mapping §7.5)."""
        wi.record_dedup('ipv4|9.9.9.9|001')
        # a brand-new check() (new connection, as a new invocation would) still sees it
        assert wi.check_dedup('ipv4|9.9.9.9|001', 3600) is True

    def test_flush_by_file_delete_resets(self, wi):
        import os

        wi.record_dedup('ipv4|9.9.9.9|001')
        assert wi.check_dedup('ipv4|9.9.9.9|001', 3600) is True
        os.remove(wi.DEDUP_DB)  # the documented flush: rm dedup.db
        assert wi.check_dedup('ipv4|9.9.9.9|001', 3600) is False

    def test_creates_parent_directory(self, wi):
        import os

        assert not os.path.exists(os.path.dirname(wi.DEDUP_DB))  # fixture points at a fresh subdir
        wi.record_dedup('k')
        assert os.path.exists(wi.DEDUP_DB)


class TestDedupFailOpen:
    def test_unwritable_path_fails_open(self, wi, tmp_path, monkeypatch):
        """A broken cache must never suppress (fail-open) or raise. Portable unwritable
        path: a regular file stands where a directory component is expected."""
        blocker = tmp_path / 'blocker'
        blocker.write_text('not a dir')
        monkeypatch.setattr(wi, 'DEDUP_DB', str(blocker / 'dedup.db'))
        assert wi.check_dedup('k', 3600) is False  # no raise, no suppression
        wi.record_dedup('k')  # silent no-op, no raise

    def test_record_failure_is_silent(self, wi, monkeypatch):
        monkeypatch.setattr(wi, '_dedup_connect', lambda: None)
        wi.record_dedup('k')  # must not raise
        assert wi.check_dedup('k', 3600) is False


class TestDedupInMain:
    """End-to-end dedup behavior through main() (TC-09)."""

    def test_second_run_suppressed_without_api_call(self, wi, write_alert, log_lines, monkeypatch):
        """TC-09: run 2 suppresses BEFORE enrich() — no Whisper API budget spent on a dupe."""
        enrich_calls = []

        def spy_enrich(*a, **k):
            enrich_calls.append(a)
            return {'integration': 'custom-whisper', 'whisper': {}}

        monkeypatch.setattr(wi, 'enrich', spy_enrich)
        monkeypatch.setattr(wi, 'send_event', lambda payload, agent: 512)
        alert_file = write_alert(data={'srcip': '185.220.101.1'})

        assert wi.main(['s', alert_file, '', '', 'debug']) == 0  # run 1: emits + records
        assert wi.main(['s', alert_file, '', '', 'debug']) == 0  # run 2: suppressed
        lines = log_lines()
        assert sum('whisper: emit' in ln for ln in lines) == 1
        assert 'whisper: skip reason=dedup dedup_key=ipv4|185.220.101.1|001' in lines
        assert len(enrich_calls) == 1  # enrich (and thus the API) never ran on run 2

    def test_failed_emit_is_not_cached(self, wi, write_alert, log_lines, monkeypatch):
        """record_dedup runs only after a successful emit — a transport failure stays
        retryable within the TTL (TC-12 interaction)."""
        monkeypatch.setattr(wi, 'enrich', lambda *a, **k: {'integration': 'custom-whisper', 'whisper': {}})

        def boom(payload, agent):
            raise wi.WhisperSocketError('send failed')

        monkeypatch.setattr(wi, 'send_event', boom)
        alert_file = write_alert(data={'srcip': '185.220.101.1'})
        wi.main(['s', alert_file, '', '', 'debug'])
        # nothing cached → a later check would NOT suppress
        assert wi.check_dedup('ipv4|185.220.101.1|001', 3600) is False
