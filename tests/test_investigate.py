"""whisper-investigate — the on-demand investigation CLI (#33): MCP client, renderer, main()."""

import json

import pytest


def _sse(obj):
    return ('event: message\ndata: ' + json.dumps(obj) + '\n\n').encode()


# A minimal-but-realistic run envelope (results[0]) covering every renderer branch.
RUN = {
    'slug': 'indicator',
    'input': 'evil.example',
    'success': True,
    'complete': True,
    'totalLatencyMs': 1234,
    'coverage': {'stepsTotal': 5, 'stepsWithData': 3, 'stepsEmpty': 1, 'stepsSkipped': 1, 'stepsError': 0},
    'derived': {
        'verdict': {
            'score': 8.5,
            'level': 'HIGH',
            'factors': [{'label': 'Listed in 3 feeds'}],
            'sources': ['openphish'],
        },
        'summary': [
            {
                'id': 'sf-1',
                'text': 'Malicious: listed in phishing feeds',
                'severity': 'error',
                'evidence': ['ev-1'],
            }
        ],
        'details': [
            {
                'id': 'd1',
                'title': 'Threat',
                'group': 'Threat',
                'order': 1,
                'views': [
                    {'kind': 'stats', 'items': [{'label': 'Score', 'value': 8.5, 'hint': 'high'}]},
                    {
                        'kind': 'findings',
                        'items': [
                            {
                                'id': 'f1',
                                'title': 'Phishing',
                                'detail': 'openphish',
                                'fix': 'block',
                                'severity': 'error',
                            }
                        ],
                    },
                ],
            },
            {
                'id': 'd2',
                'title': 'DNS',
                'group': 'DNS',
                'order': 2,
                'views': [
                    {
                        'kind': 'coverage',
                        'checks': [
                            {'label': 'A record', 'state': 'present'},
                            {'label': 'SPF', 'state': 'absent', 'note': 'none'},
                        ],
                    },
                    {'kind': 'table', 'columns': ['host', 'ip'], 'rows': [['evil.example', '1.2.3.4']]},
                    {'kind': 'weird_future_kind', 'blob': 1},  # unknown kind must not crash the renderer
                ],
            },
        ],
        'evidence': [
            {
                'id': 'ev-1',
                'fact': 'listed',
                'severity': 'error',
                'provenance': {'query': 'MATCH ...', 'rowCount': 3, 'status': 'data'},
            }
        ],
    },
}
ENVELOPE = {'results': [RUN], 'references': {'schema': 'x'}, 'quota': {'plan': 'internal'}}


def _mcp_responses(tools_obj):
    """The 3-step handshake: initialize (session header) → 202 initialized → tools/call (SSE)."""
    return [
        (
            200,
            json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'serverInfo': {'name': 'whisper'}}}).encode(),
            {'content-type': 'application/json', 'mcp-session-id': 'sess-1'},
        ),
        (202, b'', {}),
        (200, _sse(tools_obj), {'content-type': 'text/event-stream'}),
    ]


class TestDetectIoc:
    def test_ipv4(self, cli):
        assert cli.detect_ioc_type('8.8.8.8') == ('8.8.8.8', 'ipv4')

    def test_ipv4_strips_port(self, cli):
        assert cli.detect_ioc_type('8.8.8.8:443') == ('8.8.8.8', 'ipv4')

    def test_ipv6(self, cli):
        got = cli.detect_ioc_type('2001:4860:4860::8888')
        assert got is not None and got[1] == 'ipv6'

    def test_domain_normalized(self, cli):
        assert cli.detect_ioc_type('Evil.Example.COM.') == ('evil.example.com', 'domain')

    def test_private_ip_accepted(self, cli):
        """Analyst may deliberately investigate a private IP — NOT rejected (unlike the
        connector's is_global extraction guard)."""
        assert cli.detect_ioc_type('10.0.0.5') == ('10.0.0.5', 'ipv4')

    def test_garbage_is_none(self, cli):
        assert cli.detect_ioc_type('not an ioc!!') is None


class TestMcpClient:
    def _wire(self, cli, monkeypatch, responses):
        seq = iter(responses)
        monkeypatch.setattr(cli, '_http_post', lambda *a, **k: next(seq))

    def test_happy_path(self, cli, monkeypatch):
        self._wire(
            cli,
            monkeypatch,
            _mcp_responses({'jsonrpc': '2.0', 'id': 2, 'result': {'structuredContent': ENVELOPE}}),
        )
        payload = cli.run_workflow('https://mcp/', 'k', 'indicator', 'evil.example', 90)
        assert payload['run']['derived']['verdict']['level'] == 'HIGH'

    def test_session_id_and_headers(self, cli, monkeypatch):
        calls = []
        seq = iter(_mcp_responses({'jsonrpc': '2.0', 'id': 2, 'result': {'structuredContent': ENVELOPE}}))

        def fake(url, body, headers, timeout):
            calls.append(dict(headers))
            return next(seq)

        monkeypatch.setattr(cli, '_http_post', fake)
        cli.run_workflow('https://mcp/', 'k', 'indicator', 'x', 90)
        assert calls[0].get('Mcp-Session-Id') is None  # none until initialize returns one
        assert calls[1]['Mcp-Session-Id'] == 'sess-1' and calls[2]['Mcp-Session-Id'] == 'sess-1'
        assert all(c['X-API-Key'] == 'k' for c in calls)
        assert all(not c['User-Agent'].lower().startswith('python-urllib') for c in calls)

    def test_auth_401(self, cli, monkeypatch):
        self._wire(cli, monkeypatch, [(401, b'{}', {})])
        with pytest.raises(cli.WhisperAuthError):
            cli.run_workflow('https://mcp/', 'k', 'indicator', 'x', 90)

    def test_jsonrpc_error(self, cli, monkeypatch):
        self._wire(
            cli,
            monkeypatch,
            _mcp_responses({'jsonrpc': '2.0', 'id': 2, 'error': {'code': -32602, 'message': 'bad params'}}),
        )
        with pytest.raises(cli.WhisperQueryError):
            cli.run_workflow('https://mcp/', 'k', 'indicator', 'x', 90)

    def test_tool_iserror(self, cli, monkeypatch):
        self._wire(
            cli,
            monkeypatch,
            _mcp_responses(
                {
                    'jsonrpc': '2.0',
                    'id': 2,
                    'result': {'isError': True, 'content': [{'type': 'text', 'text': 'nope'}]},
                }
            ),
        )
        with pytest.raises(cli.WhisperQueryError):
            cli.run_workflow('https://mcp/', 'k', 'indicator', 'x', 90)

    def test_no_results(self, cli, monkeypatch):
        self._wire(
            cli,
            monkeypatch,
            _mcp_responses({'jsonrpc': '2.0', 'id': 2, 'result': {'structuredContent': {'results': []}}}),
        )
        with pytest.raises(cli.WhisperQueryError):
            cli.run_workflow('https://mcp/', 'k', 'indicator', 'x', 90)

    def test_content_text_fallback(self, cli, monkeypatch):
        """No structuredContent → parse the stringified envelope in content[0].text."""
        self._wire(
            cli,
            monkeypatch,
            _mcp_responses(
                {
                    'jsonrpc': '2.0',
                    'id': 2,
                    'result': {'content': [{'type': 'text', 'text': json.dumps(ENVELOPE)}]},
                }
            ),
        )
        payload = cli.run_workflow('https://mcp/', 'k', 'indicator', 'x', 90)
        assert payload['run']['slug'] == 'indicator'

    def test_network_error_is_transport(self, cli, monkeypatch):
        import urllib.error

        def boom(*a, **k):
            raise urllib.error.URLError('down')

        monkeypatch.setattr(cli, '_http_post', boom)
        with pytest.raises(cli.WhisperTransportError):
            cli.run_workflow('https://mcp/', 'k', 'indicator', 'x', 90)

    def test_5xx_on_toolscall_is_transport(self, cli, monkeypatch):
        """run_workflow re-implements the status taxonomy independently of execute_query —
        pin its 5xx -> transport branch (handshake OK, tools/call returns 500)."""
        self._wire(
            cli,
            monkeypatch,
            _mcp_responses({'jsonrpc': '2.0', 'id': 2, 'result': {}})[:2] + [(500, b'upstream', {})],
        )
        with pytest.raises(cli.WhisperTransportError):
            cli.run_workflow('https://mcp/', 'k', 'indicator', 'x', 90)

    def test_4xx_on_toolscall_is_query(self, cli, monkeypatch):
        """...and its non-auth 4xx -> query branch (tools/call returns 404)."""
        self._wire(
            cli,
            monkeypatch,
            _mcp_responses({'jsonrpc': '2.0', 'id': 2, 'result': {}})[:2] + [(404, b'not found', {})],
        )
        with pytest.raises(cli.WhisperQueryError):
            cli.run_workflow('https://mcp/', 'k', 'indicator', 'x', 90)

    def test_non_dict_envelope_is_query_error(self, cli, monkeypatch):
        """A structuredContent / content-text that is a JSON array or scalar → clean
        WhisperQueryError, never a raw AttributeError escaping main() as a traceback."""
        self._wire(
            cli,
            monkeypatch,
            _mcp_responses(
                {'jsonrpc': '2.0', 'id': 2, 'result': {'content': [{'type': 'text', 'text': '[1,2,3]'}]}}
            ),
        )
        with pytest.raises(cli.WhisperQueryError):
            cli.run_workflow('https://mcp/', 'k', 'indicator', 'x', 90)

    def test_non_dict_run_is_query_error(self, cli, monkeypatch):
        self._wire(
            cli,
            monkeypatch,
            _mcp_responses(
                {'jsonrpc': '2.0', 'id': 2, 'result': {'structuredContent': {'results': ['a string']}}}
            ),
        )
        with pytest.raises(cli.WhisperQueryError):
            cli.run_workflow('https://mcp/', 'k', 'indicator', 'x', 90)

    def test_non_https_mcp_url_refused(self, cli):
        """The API key must never be sent over plain HTTP — refuse before any network call."""
        with pytest.raises(cli.WhisperError):
            cli.run_workflow('http://mcp.example/', 'k', 'indicator', 'x', 90)


class TestParseJsonRpc:
    def test_json_body(self, cli):
        obj = cli._parse_jsonrpc(b'{"id":1,"x":2}', {'content-type': 'application/json'}, 1)
        assert obj['x'] == 2

    def test_sse_picks_matching_id(self, cli):
        body = _sse({'id': 1, 'a': 1}) + _sse({'id': 2, 'a': 2})
        assert cli._parse_jsonrpc(body, {'content-type': 'text/event-stream'}, 2)['a'] == 2

    def test_sse_picks_matching_id_not_last(self, cli):
        """The match is NOT the last frame — pins the id-match loop against the objs[-1]
        fallback (a trailing notification frame must not shadow the real result)."""
        body = _sse({'id': 2, 'a': 2}) + _sse({'id': 1, 'a': 1})  # match first, noise last
        assert cli._parse_jsonrpc(body, {'content-type': 'text/event-stream'}, 2)['a'] == 2

    def test_sse_no_match_falls_back_to_last(self, cli):
        """No frame matches want_id → the last frame is the best-effort fallback."""
        body = _sse({'id': 1, 'a': 1}) + _sse({'id': 9, 'a': 9})
        assert cli._parse_jsonrpc(body, {'content-type': 'text/event-stream'}, 2)['a'] == 9

    def test_empty_body(self, cli):
        assert cli._parse_jsonrpc(b'', {}, None) == {}

    def test_json_body_with_data_substring_not_misrouted(self, cli):
        """A JSON (not event-stream) body containing the substring 'data:' must parse as JSON,
        not be misrouted to the SSE parser and discarded (regression: substring dispatch)."""
        body = json.dumps({'id': 2, 'result': {'summary': 'Metadata: present, no data: gap'}}).encode()
        obj = cli._parse_jsonrpc(body, {'content-type': 'application/json'}, 2)
        assert obj['result']['summary'] == 'Metadata: present, no data: gap'

    def test_sse_without_header_still_parsed(self, cli):
        """If a server sends SSE but not the event-stream content-type, the JSON parse fails and
        we fall back to SSE framing (belt-and-braces)."""
        body = _sse({'id': 2, 'a': 2})
        assert cli._parse_jsonrpc(body, {'content-type': ''}, 2)['a'] == 2


class TestRender:
    def test_markdown_has_key_sections(self, cli):
        md = cli.render_markdown({'run': RUN, 'references': {}}, 'evil.example', 'indicator')
        assert '# Whisper Investigation: evil.example' in md
        assert 'Threat Investigation' in md  # slug -> title
        assert '## Verdict: HIGH (score 8.50)' in md  # score rounded to 2dp
        assert 'Malicious' in md
        assert '## Threat' in md and '## DNS' in md
        assert 'Score:' in md  # stats view
        assert '✓ A record' in md  # coverage present
        assert '✗ SPF' in md  # coverage absent
        assert '| host | ip |' in md  # table view
        assert 'Fix:' in md  # findings fix line
        assert 'MATCH ...' in md  # evidence cypher
        assert 'No-data is not proof of benign' in md

    def test_markdown_unknown_view_kind_survives(self, cli):
        md = cli.render_markdown({'run': RUN}, 'x', 'indicator')
        assert 'weird_future_kind' in md  # dumped defensively, not a crash

    def test_markdown_no_verdict_ok(self, cli):
        run = {'derived': {'summary': [], 'details': []}, 'coverage': {}}
        md = cli.render_markdown({'run': run}, 'x', 'subdomain-takeover')
        assert '## Verdict' not in md  # optional verdict absent → no verdict section

    def test_markdown_dict_lede(self, cli):
        """indicator returns lede as {text, evidence} (not a bare string) — render its text,
        never crash on the join (regression: a dict in the output list)."""
        run = {
            'derived': {'lede': {'text': 'critical listing', 'evidence': []}, 'summary': [], 'details': []},
            'coverage': {},
        }
        md = cli.render_markdown({'run': run}, 'x', 'indicator')
        assert 'critical listing' in md

    def test_markdown_string_lede_still_works(self, cli):
        run = {'derived': {'lede': 'a plain lede', 'summary': [], 'details': []}, 'coverage': {}}
        assert 'a plain lede' in cli.render_markdown({'run': run}, 'x', 'indicator')

    def test_json_format(self, cli):
        out = json.loads(cli.render_json({'run': RUN, 'references': {}}, 'evil.example', 'indicator'))
        assert out['ioc'] == 'evil.example'
        assert out['workflow'] == 'indicator'
        assert out['derived']['verdict']['level'] == 'HIGH'

    def test_null_fields_do_not_crash(self, cli):
        """A server may emit JSON null for empty list/coverage fields — the render must not
        crash (regression: coverage:null, views:null, items:null)."""
        run = {
            'coverage': None,
            'complete': True,
            'derived': {
                'verdict': None,
                'lede': None,
                'summary': None,
                'evidence': None,
                'details': [
                    {'title': 'S', 'group': 'G', 'order': 0, 'views': None},
                    {
                        'title': 'T',
                        'group': 'G',
                        'order': 1,
                        'views': [
                            {'kind': 'stats', 'items': None},
                            {'kind': 'coverage', 'checks': None},
                            {'kind': 'table', 'columns': ['a'], 'rows': None},
                        ],
                    },
                ],
            },
        }
        assert '# Whisper Investigation: x' in cli.render_markdown({'run': run}, 'x', 'indicator')

    def test_non_dict_elements_skipped(self, cli):
        """Non-dict elements in summary/details/evidence/factors must be skipped or coerced,
        not crash the render."""
        run = {
            'coverage': {},
            'derived': {
                'summary': ['not a dict', {'text': 'ok fact', 'severity': 'info'}],
                'details': ['nope', {'title': 'Real', 'group': 'G', 'order': 0, 'views': []}],
                'evidence': ['x', {'id': 'ev-1', 'fact': 'f'}],
                'verdict': {'factors': ['plainstr', {'label': 'L'}]},
            },
        }
        md = cli.render_markdown({'run': run}, 'x', 'indicator')
        assert all(s in md for s in ('ok fact', 'Real', 'ev-1', 'L', 'plainstr'))

    def test_table_truncation_noted(self, cli):
        rows = [[i] for i in range(60)]
        run = {
            'coverage': {},
            'derived': {
                'details': [
                    {
                        'title': 'T',
                        'group': 'G',
                        'order': 0,
                        'views': [{'kind': 'table', 'columns': ['n'], 'rows': rows}],
                    }
                ]
            },
        }
        assert '10 more row(s) not shown' in cli.render_markdown({'run': run}, 'x', 'indicator')


class TestKeyResolution:
    def test_flag_wins(self, cli):
        assert cli.resolve_cli_key('flag-key', {'WHISPER_API_KEY': 'env-key'}) == 'flag-key'

    def test_env_when_no_flag(self, cli):
        assert cli.resolve_cli_key(None, {'WHISPER_API_KEY': 'env-key'}) == 'env-key'

    def test_placeholder_flag_ignored(self, cli):
        assert cli.resolve_cli_key(cli.API_KEY_PLACEHOLDER, {}) is None


class TestMain:
    def _wire_run(self, cli, monkeypatch, payload=None, exc=None):
        def fake(*a, **k):
            if exc:
                raise exc
            return payload or {'run': RUN, 'references': {}}

        monkeypatch.setattr(cli, 'run_workflow', fake)

    def test_bad_ioc(self, cli):
        assert cli.main(['not!!an!!ioc']) == cli.ERR_BAD_IOC

    def test_no_key(self, cli):
        """Valid IOC but no key anywhere → ERR_AUTH before any network call."""
        assert cli.main(['8.8.8.8']) == cli.ERR_AUTH

    def test_happy_path_stdout(self, cli, monkeypatch, capsys):
        self._wire_run(cli, monkeypatch)
        rc = cli.main(['evil.example', '--api-key', 'k'])
        assert rc == 0 and '# Whisper Investigation: evil.example' in capsys.readouterr().out

    def test_json_out_file(self, cli, monkeypatch, tmp_path):
        self._wire_run(cli, monkeypatch)
        f = tmp_path / 'r.json'
        rc = cli.main(['evil.example', '--api-key', 'k', '--format', 'json', '--out', str(f)])
        assert rc == 0 and json.loads(f.read_text())['workflow'] == 'indicator'

    def test_auth_error_exit(self, cli, monkeypatch):
        self._wire_run(cli, monkeypatch, exc=cli.WhisperAuthError('401'))
        assert cli.main(['evil.example', '--api-key', 'k']) == cli.ERR_AUTH

    def test_transport_error_exit(self, cli, monkeypatch):
        self._wire_run(cli, monkeypatch, exc=cli.WhisperTransportError('down'))
        assert cli.main(['evil.example', '--api-key', 'k']) == cli.ERR_GENERAL
