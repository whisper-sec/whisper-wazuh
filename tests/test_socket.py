"""#16 — analysisd socket write-back: framing (mapping §2.3) + send behavior."""

import json

import pytest

PAYLOAD = {'integration': 'custom-whisper', 'whisper': {'ioc': '185.220.101.1', 'verdict': 'suspicious'}}


class TestFraming:
    def test_form_a_no_agent(self, wi):
        s = wi.frame_event(PAYLOAD, None)
        assert s.startswith('1:custom-whisper:')
        assert json.loads(s[len('1:custom-whisper:') :]) == PAYLOAD

    def test_form_a_manager_agent_000(self, wi):
        s = wi.frame_event(PAYLOAD, {'id': '000', 'name': 'wazuh.manager'})
        assert s.startswith('1:custom-whisper:')

    def test_form_b_real_agent(self, wi):
        s = wi.frame_event(PAYLOAD, {'id': '001', 'name': 'web01', 'ip': '10.0.0.5'})
        assert s.startswith('1:[001] (web01) 10.0.0.5->custom-whisper:')

    def test_form_b_missing_ip_is_any(self, wi):
        s = wi.frame_event(PAYLOAD, {'id': '002', 'name': 'db01'})
        assert s.startswith('1:[002] (db01) any->custom-whisper:')

    def test_form_b_escapes_colons_and_pipes(self, wi):
        """Colons/pipes in the location must be escaped so they don't collide with the
        `1:...:` framing delimiters."""
        s = wi.frame_event(PAYLOAD, {'id': '003', 'name': 'host:a|b', 'ip': 'fe80::1'})
        loc = s[len('1:') : s.index('->custom-whisper:')]
        assert '|:' in loc  # a literal ':' became '|:'
        assert '||' in loc  # a literal '|' became '||'
        # and the real framing delimiter (the ':' before the json) is still unambiguous
        assert s.split('->custom-whisper:', 1)[1].startswith('{')

    def test_compact_json_no_spaces(self, wi):
        s = wi.frame_event(PAYLOAD, None)
        assert ', ' not in s and '": ' not in s  # compact separators

    def test_empty_agent_dict_is_form_a(self, wi):
        assert wi.frame_event(PAYLOAD, {}).startswith('1:custom-whisper:')


class FakeSock:
    def __init__(self):
        self.connected = None
        self.sent = None
        self.closed = False

    def connect(self, addr):
        self.connected = addr

    def send(self, data):
        self.sent = data
        return len(data)

    def close(self):
        self.closed = True


class TestSend:
    def test_send_connects_and_sends(self, wi, monkeypatch):
        fake = FakeSock()
        monkeypatch.setattr(wi.socket, 'socket', lambda *a, **k: fake)
        monkeypatch.setattr(wi, 'SOCKET_ADDR', '/tmp/whisper-test.sock')
        n = wi.send_event(PAYLOAD, {'id': '001', 'name': 'web01', 'ip': '10.0.0.5'})
        assert fake.connected == '/tmp/whisper-test.sock'
        assert fake.sent.startswith(b'1:[001] (web01) 10.0.0.5->custom-whisper:')
        assert fake.closed is True
        assert n == len(fake.sent)

    def test_oversize_raises_socket_error(self, wi, monkeypatch):
        fake = FakeSock()
        monkeypatch.setattr(wi.socket, 'socket', lambda *a, **k: fake)
        big = {'integration': 'custom-whisper', 'whisper': {'x': 'a' * (wi.MAX_EVENT_SIZE + 100)}}
        with pytest.raises(wi.WhisperSocketError, match='errno 90'):
            wi.send_event(big, None)
        assert fake.connected is None  # never opened the socket for an oversize event

    def test_connect_failure_raises_socket_error(self, wi, monkeypatch):
        class Boom(FakeSock):
            def connect(self, addr):
                raise FileNotFoundError(2, 'No such file or directory')

        fake = Boom()
        monkeypatch.setattr(wi.socket, 'socket', lambda *a, **k: fake)
        with pytest.raises(wi.WhisperSocketError, match='socket send failed'):
            wi.send_event(PAYLOAD, None)
        assert fake.closed is True  # closed even on failure (finally)

    def test_send_error_maps_to_socket_class(self, wi):
        assert wi.WhisperSocketError('x').log_class == 'socket'


class TestSendInMain:
    def test_socket_failure_exits_one_with_socket_class(self, wi, write_alert, log_lines, monkeypatch):
        """A real send failure surfaces as error class=socket and a non-zero exit (no crash)."""
        monkeypatch.setattr(wi, 'enrich', lambda *a, **k: PAYLOAD)
        monkeypatch.setattr(wi, 'SOCKET_ADDR', '/nonexistent/queue/sock')
        alert_file = write_alert(data={'srcip': '185.220.101.1'})
        rc = wi.main(['s', alert_file, '', '', 'debug'])
        assert rc == 1
        assert any('whisper: error class=socket' in ln for ln in log_lines())

    def test_happy_path_emits_and_records(self, wi, write_alert, log_lines, monkeypatch):
        monkeypatch.setattr(wi, 'enrich', lambda *a, **k: PAYLOAD)
        fake = FakeSock()
        monkeypatch.setattr(wi.socket, 'socket', lambda *a, **k: fake)
        monkeypatch.setattr(wi, 'SOCKET_ADDR', '/tmp/whisper-test.sock')
        alert_file = write_alert(data={'srcip': '185.220.101.1'})
        assert wi.main(['s', alert_file, '', '', 'debug']) == 0
        assert fake.sent is not None
        assert any('whisper: emit dedup_key=ipv4|185.220.101.1|001' in ln for ln in log_lines())
        assert wi.check_dedup('ipv4|185.220.101.1|001', 3600) is True  # recorded after emit
