"""#35 — whisper-logs: columnar-record reconstruction, per-kind projection, identity enrich."""


def _records(wl, envelope):
    """Reconstruct dict records from the columnar inner result (as the poller does)."""
    result = envelope['rows'][0]['result']
    return [dict(zip(result['columns'], row, strict=False)) for row in result['rows']]


def _cfg(wl):
    return {'api_url': 'https://graph.whisper.online', 'api_key': 'k', 'timeout': 10, 'retries': 3}


class TestReconstruction:
    def test_dict_zip_per_kind(self, wl, load_fixture):
        recs = _records(wl, load_fixture('agent_logs_envelope.json'))
        kinds = [r['kind'] for r in recs]
        assert kinds == ['conn', 'conn', 'dns', 'dns', 'alloc']
        dns = next(r for r in recs if r['kind'] == 'dns' and r['decision'] == 'allow')
        assert dns['qname'] == 'rdap.whisper.online' and dns['qtype'] == 'AAAA'
        assert dns['peer'] is None  # unused column for dns is null

    def test_epoch_ms_to_iso(self, wl):
        # 1784002495932 ms → 2026-07-14T... UTC, millisecond precision, Z suffix
        iso = wl._iso(1784002495932)
        assert iso.startswith('2026-07-14T') and iso.endswith('Z')
        assert iso == '2026-07-14T04:14:55.932Z'

    def test_iso_bad_input(self, wl):
        assert wl._iso('not-a-number') is None

    def test_peer_hostport_split(self, wl):
        assert wl._split_hostport('rdap.whisper.online:443') == ('rdap.whisper.online', 443)
        assert wl._split_hostport('[2001:db8::1]:443') == ('2001:db8::1', 443)
        assert wl._split_hostport('bare-host') == ('bare-host', None)
        assert wl._split_hostport('2001:db8::1') == ('2001:db8::1', None)  # bare IPv6, no port
        assert wl._split_hostport(None) == (None, None)


class TestProjection:
    def test_dns_projection(self, wl, load_fixture):
        recs = _records(wl, load_fixture('agent_logs_envelope.json'))
        dns = next(r for r in recs if r['kind'] == 'dns' and r['decision'] == 'allow')
        p = wl.project(dns, {})
        assert p['integration'] == 'whisper-logs'
        body = p['whisper_agent']
        assert body['kind'] == 'dns' and body['decision'] == 'allow'
        assert body['ts_ms'] == 1784002495932 and body['ts'].startswith('2026-07-14T')
        assert body['agent_id'] == 'a98874349306a52c8'
        assert body['dns']['qname'] == 'rdap.whisper.online'
        assert body['dns']['answer'] == '2001:19f0:5000:15f6:5400:6ff:fe45:110'
        # no /128 or fqdn without identity enrichment; nulls stripped → no conn block
        assert 'address' not in body and 'fqdn' not in body and 'conn' not in body

    def test_dns_refused_projection(self, wl, load_fixture):
        recs = _records(wl, load_fixture('agent_logs_envelope.json'))
        ref = next(r for r in recs if r['kind'] == 'dns' and r['decision'] == 'refused')
        body = wl.project(ref, {})['whisper_agent']
        assert body['decision'] == 'refused' and body['dns']['rcode'] == 'REFUSED'

    def test_conn_projection_splits_peer(self, wl, load_fixture):
        recs = _records(wl, load_fixture('agent_logs_envelope.json'))
        closed = next(r for r in recs if r['kind'] == 'conn' and r['reason'] == 'closed')
        body = wl.project(closed, {})['whisper_agent']
        conn = body['conn']
        assert conn['dst'] == 'rdap.whisper.online:443'
        assert conn['dst_host'] == 'rdap.whisper.online' and conn['dst_port'] == 443
        assert conn['state'] == 'closed'
        assert conn['bytes_up'] == 1715 and conn['bytes_down'] == 4086
        assert conn['packets_up'] == 3 and conn['packets_down'] == 4
        assert conn['duration_ms'] == 185 and conn['client_src'] == '145.224.65.0/24'
        assert 'dns' not in body  # dns block absent for conn

    def test_conn_open_zero_values_kept(self, wl, load_fixture):
        # zero is a real value, not null — must NOT be stripped
        recs = _records(wl, load_fixture('agent_logs_envelope.json'))
        opened = next(r for r in recs if r['kind'] == 'conn' and r['reason'] == 'open')
        conn = wl.project(opened, {})['whisper_agent']['conn']
        assert conn['bytes_up'] == 0 and conn['duration_ms'] == 0 and conn['packets_down'] == 0

    def test_alloc_projection_id_only(self, wl, load_fixture):
        recs = _records(wl, load_fixture('agent_logs_envelope.json'))
        alloc = next(r for r in recs if r['kind'] == 'alloc')
        body = wl.project(
            alloc, {'address': '2a04:2a01:f3c6:4261:9887:4349:306a:52c8', 'fqdn': 'x.botboss.app'}
        )['whisper_agent']
        assert body['kind'] == 'alloc' and body['agent_id'] == 'a98874349306a52c8'
        assert body['address'] == '2a04:2a01:f3c6:4261:9887:4349:306a:52c8'
        assert body['fqdn'] == 'x.botboss.app'
        assert 'dns' not in body and 'conn' not in body

    def test_project_rejects_bad_record(self, wl):
        assert wl.project({'ts': None, 'kind': 'dns'}, {}) is None
        assert wl.project({'ts': 1, 'kind': 'bogus'}, {}) is None


class TestIdentityEnrichment:
    def test_identity_resolved_and_cached(self, wl, router, load_fixture):
        ident_env = load_fixture('agent_identity_envelope.json')
        router.add("op:'identity'", ident_env['rows'])
        cache = {}
        got = wl.resolve_identity(_cfg(wl), 'a98874349306a52c8', cache)
        assert got['address'] == '2a04:2a01:f3c6:4261:9887:4349:306a:52c8'
        assert got['fqdn'] == 'a98874349306a52c8.botboss.app'  # trailing dot stripped
        # cached: a second call makes no further execute_query call
        calls_before = len(router.calls)
        again = wl.resolve_identity(_cfg(wl), 'a98874349306a52c8', cache)
        assert again == got and len(router.calls) == calls_before

    def test_identity_failure_degrades(self, wl, router):
        # no identity route → empty result rows → id-only, no exception
        got = wl.resolve_identity(_cfg(wl), 'a98874349306a52c8', {})
        assert got == {}

    def test_agent_filter_regex(self, wl):
        assert wl._AGENT_RE.match('a98874349306a52c8')
        assert wl._AGENT_RE.match('agent-a98874349306a52c8')
        assert not wl._AGENT_RE.match("a98'; DROP")
        assert not wl._AGENT_RE.match('../etc/passwd')
