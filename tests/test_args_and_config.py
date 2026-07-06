"""argv contract (mapping §2.3), configuration resolution, and exit-code semantics."""

import json
import os


class TestArgs:
    def test_too_few_args_exits_2(self, wi, log_lines):
        assert wi.main(['custom-whisper.py']) == wi.ERR_BAD_ARGUMENTS
        assert any('# Error: Wrong arguments' in line for line in log_lines())

    def test_wrong_arguments_logged_even_with_debug_off(self, wi, log_lines, monkeypatch):
        monkeypatch.setattr(wi, 'debug_enabled', False)
        wi.main(['custom-whisper.py', 'x'])
        assert any('# Error: Wrong arguments' in line for line in log_lines())

    def test_missing_alert_file_exits_6(self, wi, tmp_path):
        """Stock convention: ERR_FILE_NOT_FOUND = 6 (virustotal.py)."""
        rc = wi.main(['s', str(tmp_path / 'missing.alert'), '', '', 'debug'])
        assert rc == wi.ERR_FILE_NOT_FOUND == 6

    def test_corrupt_alert_json_exits_7(self, wi, tmp_path):
        """Stock convention: ERR_INVALID_JSON = 7 — distinct from file-not-found."""
        bad = tmp_path / 'bad.alert'
        bad.write_text('{not json')
        assert wi.main(['s', str(bad), '', '', 'debug']) == wi.ERR_INVALID_JSON == 7

    def test_trailing_redirect_argument_is_harmless(self, wi, write_alert):
        """integratord appends a literal '> /dev/null 2>&1' argument when debug is off."""
        alert_file = write_alert(data={})
        rc = wi.main(['s', alert_file, '', '', '', '', '10', '3', '> /dev/null 2>&1'])
        assert rc == 0  # no IOC → clean exit; the extra argv must not crash positional reads

    def test_argv_int_parsing(self, wi):
        assert wi._argv_int(['s', 'a', 'b', 'c', 'd', 'e', '30'], 6, 10) == 30
        assert wi._argv_int(['s'], 6, 10) == 10  # slot absent
        assert wi._argv_int(['s', 'a', 'b', 'c', 'd', 'e', ''], 6, 10) == 10  # empty
        assert wi._argv_int(['s', 'a', 'b', 'c', 'd', 'e', '-5'], 6, 10) == 10  # negative
        assert wi._argv_int(['s', 'a', 'b', 'c', 'd', 'e', 'soon'], 6, 10) == 10


class TestOptionsResolution:
    def test_options_file_beats_env(self, wi, tmp_path, monkeypatch):
        opts = tmp_path / 'opts.json'
        opts.write_text(json.dumps({'api_url': 'https://opt.example/', 'dedup_ttl': 60}))
        monkeypatch.setenv('WHISPER_API_URL', 'https://env.example')
        monkeypatch.setenv('WHISPER_DEDUP_TTL', '120')
        loaded = wi.load_options(str(opts))
        assert wi.resolve_api_url(loaded, os.environ) == 'https://opt.example'  # trailing / stripped
        assert wi.resolve_dedup_ttl(loaded, os.environ) == 60

    def test_env_beats_default(self, wi, monkeypatch):
        monkeypatch.setenv('WHISPER_API_URL', 'https://env.example')
        monkeypatch.setenv('WHISPER_DEDUP_TTL', '120')
        assert wi.resolve_api_url({}, os.environ) == 'https://env.example'
        assert wi.resolve_dedup_ttl({}, os.environ) == 120

    def test_defaults(self, wi):
        assert wi.resolve_api_url({}, {}) == wi.DEFAULT_API_URL
        assert wi.resolve_dedup_ttl({}, {}) == wi.DEFAULT_DEDUP_TTL

    def test_bad_values_fall_through(self, wi):
        assert (
            wi.resolve_dedup_ttl({'dedup_ttl': 'soon'}, {'WHISPER_DEDUP_TTL': '-5'}) == wi.DEFAULT_DEDUP_TTL
        )
        assert wi.resolve_api_url({'api_url': '   '}, {}) == wi.DEFAULT_API_URL

    def test_json_boolean_ttl_never_becomes_one_second(self, wi):
        """int(True) == 1 — a well-meant '"dedup_ttl": true' must fall back to default."""
        assert wi.resolve_dedup_ttl({'dedup_ttl': True}, {}) == wi.DEFAULT_DEDUP_TTL
        assert wi.resolve_dedup_ttl({'dedup_ttl': False}, {}) == wi.DEFAULT_DEDUP_TTL

    def test_missing_or_invalid_options_file(self, wi, tmp_path):
        assert wi.load_options('') == {}
        assert wi.load_options(str(tmp_path / 'nope.json')) == {}
        bad = tmp_path / 'bad.json'
        bad.write_text('[1,2,3]')
        assert wi.load_options(str(bad)) == {}


class TestApiKeyResolution:
    """env → key file → argv; the placeholder never counts (scope §3.8, TC-19)."""

    def test_env_wins(self, wi, tmp_path):
        key_file = tmp_path / 'whisper.key'
        key_file.write_text('file-key\n')
        assert wi.resolve_api_key('argv-key', {'WHISPER_API_KEY': 'env-key'}, str(key_file)) == 'env-key'

    def test_file_beats_argv(self, wi, tmp_path):
        key_file = tmp_path / 'whisper.key'
        key_file.write_text('  file-key \n')
        assert wi.resolve_api_key('argv-key', {}, str(key_file)) == 'file-key'

    def test_argv_fallback(self, wi, tmp_path):
        assert wi.resolve_api_key('argv-key', {}, str(tmp_path / 'missing')) == 'argv-key'

    def test_placeholder_is_never_a_key(self, wi, tmp_path):
        key_file = tmp_path / 'whisper.key'
        key_file.write_text(wi.API_KEY_PLACEHOLDER)
        resolved = wi.resolve_api_key(
            wi.API_KEY_PLACEHOLDER, {'WHISPER_API_KEY': wi.API_KEY_PLACEHOLDER}, str(key_file)
        )
        assert resolved is None

    def test_default_key_file_is_module_global_at_call_time(self, wi, tmp_path, monkeypatch):
        """Monkeypatching wi.KEY_FILE must take effect (no def-time binding)."""
        key_file = tmp_path / 'patched.key'
        key_file.write_text('patched-key')
        monkeypatch.setattr(wi, 'KEY_FILE', str(key_file))
        assert wi.resolve_api_key('', {}) == 'patched-key'


class TestMainErrorSemantics:
    """Exit-code and taxonomy behavior of the per-candidate loop (TC-12/13/15)."""

    def test_auth_error_is_terminal(self, wi, write_alert, log_lines, monkeypatch):
        """A dead key must stop the run — no doomed calls for remaining candidates."""
        calls = []

        def fake_enrich(ioc, *a, **k):
            calls.append(ioc)
            raise wi.WhisperAuthError('401 from api')

        monkeypatch.setattr(wi, 'enrich', fake_enrich)
        alert_file = write_alert(data={'srcip': '185.220.101.1', 'dns': {'rrname': 'evil.example'}})
        rc = wi.main(['s', alert_file, '', '', 'debug'])
        assert rc == wi.ERR_AUTH
        assert calls == ['185.220.101.1']  # second candidate never attempted
        assert any('whisper: error class=auth' in line for line in log_lines())

    def test_transport_errors_continue_and_exit_nonzero_when_nothing_emitted(
        self, wi, write_alert, log_lines, monkeypatch
    ):
        def fake_enrich(*a, **k):
            raise wi.WhisperTransportError('connection refused')

        monkeypatch.setattr(wi, 'enrich', fake_enrich)
        alert_file = write_alert(data={'srcip': '185.220.101.1', 'dns': {'rrname': 'evil.example'}})
        rc = wi.main(['s', alert_file, '', '', 'debug'])
        assert rc == 1
        assert sum('whisper: error class=transport' in line for line in log_lines()) == 2

    def test_partial_success_exits_zero(self, wi, write_alert, log_lines, monkeypatch):
        """TC-15: a successful emit must not produce an 'Exit status was:' line."""
        recorded = []

        def fake_enrich(ioc, *a, **k):
            if ioc == '185.220.101.1':
                raise wi.WhisperTransportError('flaky')
            return {'integration': wi.INTEGRATION_NAME, 'whisper': {'ioc': ioc}}

        monkeypatch.setattr(wi, 'enrich', fake_enrich)
        monkeypatch.setattr(wi, 'send_event', lambda payload, agent: 512)
        monkeypatch.setattr(wi, 'record_dedup', lambda key, ttl=0: recorded.append(key))
        alert_file = write_alert(data={'srcip': '185.220.101.1', 'dns': {'rrname': 'evil.example'}})
        rc = wi.main(['s', alert_file, '', '', 'debug'])
        assert rc == 0
        assert recorded == ['domain|evil.example|001']  # recorded only after successful emit
        assert any(
            'whisper: emit dedup_key=domain|evil.example|001 payload_bytes=512' in line
            for line in log_lines()
        )

    def test_dedup_suppression_skips_api_and_emit(self, wi, write_alert, log_lines, monkeypatch):
        monkeypatch.setattr(wi, 'check_dedup', lambda key, ttl: True)
        api_calls = []
        monkeypatch.setattr(wi, 'enrich', lambda *a, **k: api_calls.append(a))
        alert_file = write_alert(data={'srcip': '185.220.101.1'})
        assert wi.main(['s', alert_file, '', '', 'debug']) == 0
        assert api_calls == []
        assert 'whisper: skip reason=dedup dedup_key=ipv4|185.220.101.1|001' in log_lines()

    def test_remaining_send_seam_exits_10(self, wi, write_alert, monkeypatch):
        """enrich() is real (#14); send_event is still the #16 seam → exit 10."""
        monkeypatch.setattr(wi, 'enrich', lambda *a, **k: {'integration': 'custom-whisper', 'whisper': {}})
        alert_file = write_alert(data={'srcip': '185.220.101.1'})
        assert wi.main(['s', alert_file, '', '', 'debug']) == wi.ERR_NOT_IMPLEMENTED == 10
