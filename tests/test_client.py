"""whisper_client — the shared stdlib HTTP/TLS client (extracted for #33).

execute_query transport behaviour + the CA-bundle-resolving SSL context, exercised via the
_http_post seam. These moved out of test_enrichment when the client was extracted so the
connector and the whisper-investigate CLI share one implementation.
"""

import json

import pytest


class TestHttpClient:
    """execute_query transport behavior via the _http_post seam."""

    def _client(self, wc, monkeypatch, responses, sleeps=None):
        seq = iter(responses)
        monkeypatch.setattr(wc, '_http_post', lambda *a, **k: next(seq))
        if sleeps is not None:
            monkeypatch.setattr(wc.time, 'sleep', lambda s: sleeps.append(s))

    def test_success_returns_rows(self, wc, monkeypatch):
        body = json.dumps({'columns': ['x'], 'rows': [{'x': 1}]}).encode()
        self._client(wc, monkeypatch, [(200, body, {})])
        assert wc.execute_query('u', 'k', 'RETURN 1') == [{'x': 1}]

    def test_auth_error_never_retried(self, wc, monkeypatch):
        sleeps = []
        self._client(wc, monkeypatch, [(401, b'', {})], sleeps)
        with pytest.raises(wc.WhisperAuthError):
            wc.execute_query('u', 'k', 'RETURN 1')
        assert sleeps == []

    def test_5xx_retried_then_transport_error(self, wc, monkeypatch):
        sleeps = []
        self._client(wc, monkeypatch, [(500, b'', {})] * 4, sleeps)
        with pytest.raises(wc.WhisperTransportError):
            wc.execute_query('u', 'k', 'RETURN 1', retries=3)
        assert len(sleeps) == 3  # backoff between each retry

    def test_429_honours_retry_after(self, wc, monkeypatch):
        sleeps = []
        ok = json.dumps({'rows': []}).encode()
        self._client(wc, monkeypatch, [(429, b'', {'retry-after': '7'}), (200, ok, {})], sleeps)
        assert wc.execute_query('u', 'k', 'RETURN 1') == []
        assert sleeps == [7.0]

    def test_other_4xx_is_query_error(self, wc, monkeypatch):
        self._client(wc, monkeypatch, [(400, b'bad cypher', {})])
        with pytest.raises(wc.WhisperQueryError):
            wc.execute_query('u', 'k', 'RETURN 1')

    def test_success_false_body_is_query_error(self, wc, monkeypatch):
        body = json.dumps({'success': False, 'error': 'nope'}).encode()
        self._client(wc, monkeypatch, [(200, body, {})])
        with pytest.raises(wc.WhisperQueryError):
            wc.execute_query('u', 'k', 'RETURN 1')

    def test_bound_parameters_sent(self, wc, monkeypatch):
        captured = {}

        def fake_post(url, body, headers, timeout):
            captured.update(body)
            return 200, json.dumps({'rows': []}).encode(), {}

        monkeypatch.setattr(wc, '_http_post', fake_post)
        wc.execute_query('u', 'k', 'MATCH (n {name: $v}) RETURN n', {'v': 'x'})
        assert captured['parameters'] == {'v': 'x'}

    def test_explicit_user_agent_sent(self, wc, monkeypatch):
        """The Whisper WAF 403s urllib's default 'Python-urllib' UA — we must send our own."""
        captured = {}

        def fake_post(url, body, headers, timeout):
            captured.update(headers)
            return 200, json.dumps({'rows': []}).encode(), {}

        monkeypatch.setattr(wc, '_http_post', fake_post)
        wc.execute_query('u', 'k', 'RETURN 1')
        assert captured.get('User-Agent') == wc.USER_AGENT
        assert not captured['User-Agent'].lower().startswith('python-urllib')

    def test_ssl_context_uses_interpreter_default_when_populated(self, wc, monkeypatch):
        class FakeCtx:
            def get_ca_certs(self):
                return [{'x': 1}]  # non-empty → default is fine, no fallback

        monkeypatch.setattr(wc.ssl, 'create_default_context', lambda: FakeCtx())
        assert isinstance(wc._ssl_context(), FakeCtx)

    def test_ssl_context_loads_bundle_when_default_empty(self, wc, tmp_path, monkeypatch):
        """Wazuh framework Python: default context has zero CAs → load a real bundle,
        keeping verification ON (scope §3.8)."""
        bundle = tmp_path / 'ca.crt'
        bundle.write_text('-----BEGIN CERTIFICATE-----')
        loaded = []

        class FakeCtx:
            def get_ca_certs(self):
                return loaded  # empty until a bundle is loaded, then non-empty (real behavior)

            def load_verify_locations(self, path):
                loaded.append(path)

        monkeypatch.setattr(wc.ssl, 'create_default_context', lambda: FakeCtx())
        monkeypatch.setattr(wc, '_CA_BUNDLE_CANDIDATES', (str(bundle),))
        monkeypatch.delenv('SSL_CERT_FILE', raising=False)
        wc._ssl_context()
        assert loaded == [str(bundle)]  # located and loaded the bundle

    def test_ssl_context_prefers_ssl_cert_file_env(self, wc, tmp_path, monkeypatch):
        env_bundle = tmp_path / 'env-ca.crt'
        env_bundle.write_text('x')
        loaded = []

        class FakeCtx:
            def get_ca_certs(self):
                return loaded

            def load_verify_locations(self, path):
                loaded.append(path)

        monkeypatch.setattr(wc.ssl, 'create_default_context', lambda: FakeCtx())
        monkeypatch.setattr(wc, '_CA_BUNDLE_CANDIDATES', ('/nonexistent/ca.crt',))
        monkeypatch.setenv('SSL_CERT_FILE', str(env_bundle))
        wc._ssl_context()
        assert loaded == [str(env_bundle)]  # SSL_CERT_FILE wins over the well-known paths

    def test_http_exception_stays_in_taxonomy(self, wc, monkeypatch):
        """BadStatusLine/IncompleteRead are not OSError — must not escape as a raw crash."""
        import http.client

        sleeps = []

        def boom(*a, **k):
            raise http.client.BadStatusLine('garbage')

        monkeypatch.setattr(wc, '_http_post', boom)
        monkeypatch.setattr(wc.time, 'sleep', lambda s: sleeps.append(s))
        with pytest.raises(wc.WhisperTransportError):
            wc.execute_query('u', 'k', 'RETURN 1', retries=2)
        assert len(sleeps) == 2  # retried within budget, not crashed

    def test_first_backoff_is_base(self, wc, monkeypatch):
        sleeps = []
        seq = iter([(500, b'', {}), (200, json.dumps({'rows': []}).encode(), {})])
        monkeypatch.setattr(wc, '_http_post', lambda *a, **k: next(seq))
        monkeypatch.setattr(wc.time, 'sleep', lambda s: sleeps.append(s))
        wc.execute_query('u', 'k', 'RETURN 1')
        assert sleeps == [wc.BACKOFF_BASE]  # 0.5s, not 1.0s


class TestNoRedirect:
    def test_redirects_never_followed(self, wc):
        """urllib's default handler re-sends X-API-Key across a redirect (incl. https->http);
        _NoRedirect must refuse to follow so the key can never travel to a redirect target."""
        assert wc._NoRedirect().redirect_request(None, None, 302, 'Found', {}, 'http://evil/') is None


class TestConfigResolution:
    """resolve_api_key / resolve_api_url live in whisper_client now."""

    def test_default_key_file_is_module_global_at_call_time(self, wc, tmp_path, monkeypatch):
        """Monkeypatching whisper_client.KEY_FILE must take effect (no def-time binding)."""
        key_file = tmp_path / 'patched.key'
        key_file.write_text('patched-key')
        monkeypatch.setattr(wc, 'KEY_FILE', str(key_file))
        assert wc.resolve_api_key('', {}) == 'patched-key'
