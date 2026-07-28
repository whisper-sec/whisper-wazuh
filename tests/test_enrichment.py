"""#14 — Whisper client, builders, verdict derivation, envelope, payload guard (mocked HTTP)."""

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent / 'fixtures'

TOR_EXPLAIN = {
    'indicator': '185.220.101.1',
    'type': 'ip',
    'available': True,
    'cached': False,
    'found': True,
    'score': 7.46,
    'level': 'HIGH',
    'explanation': '185.220.101.1 is listed in 4 threat feed(s).',
    'factors': [],
    'sources': [
        {
            'feedId': 'dan-tor-exit',
            'weight': 0.5,
            'firstSeen': '2026-06-23T01:26:36Z',
            'lastSeen': '2026-06-29T12:11:13Z',
        },
        {
            'feedId': 'stamparm-ipsum',
            'weight': 1.2,
            'firstSeen': '2026-06-22T19:25:54Z',
            'lastSeen': '2026-07-02T19:35:16Z',
        },
        {
            'feedId': 'tor-exit-nodes',
            'weight': 0.5,
            'firstSeen': '2026-06-22T19:25:52Z',
            'lastSeen': '2026-06-29T12:11:02Z',
        },
    ],
    'breakdown': None,
    'advisory': None,
}
TOR_FLAGS = {'isThreat': True, 'isTor': True, 'isSpam': True, 'isAnonymizer': True}
GOOGLE_DNS_EXPLAIN = {
    'indicator': '8.8.8.8',
    'type': 'ip',
    'available': True,
    'found': True,
    'score': 8.56,
    'level': 'INFO',
    'sources': [
        {
            'feedId': 'hagezi-dns-light-ip',
            'weight': 0.7,
            'firstSeen': '2026-06-25T12:18:06Z',
            'lastSeen': '2026-07-02T21:11:14Z',
        }
    ],
    'advisory': 'allowlist-vouched',
}


def make_cfg_args():
    """(api_url, api_key, timeout, retries) for enrich()."""
    return ('https://graph.whisper.security', 'test-key', 10, 3)


class TestCallExplain:
    def test_genuine_400_raises_original_not_fallback(self, wi, monkeypatch):
        """Both shapes fail → surface the RICH query's error, not the fallback's."""
        calls = []

        def fake_eq(api_url, api_key, cypher, params=None, timeout=10, retries=3):
            calls.append(cypher)
            raise wi.WhisperQueryError('rich-shape error' if 'sources' in cypher else 'fallback error')

        monkeypatch.setattr(wi, 'execute_query', fake_eq)
        with pytest.raises(wi.WhisperQueryError, match='rich-shape error'):
            wi.call_explain({'api_url': 'u', 'api_key': 'k', 'timeout': 10, 'retries': 3}, 'x')
        assert len(calls) == 2  # tried both shapes

    def test_degraded_shape_returns_retry_after(self, wi, monkeypatch):
        def fake_eq(api_url, api_key, cypher, params=None, timeout=10, retries=3):
            if 'sources' in cypher:
                raise wi.WhisperQueryError('no such column sources')
            return [{'available': False, 'retryAfter': 60}]

        monkeypatch.setattr(wi, 'execute_query', fake_eq)
        row = wi.call_explain({'api_url': 'u', 'api_key': 'k', 'timeout': 10, 'retries': 3}, 'x')
        assert row['available'] is False and row['retryAfter'] == 60


class TestFragmentDegradation:
    def test_aux_query_failure_keeps_verdict(self, wi, router):
        """A transport blip in an auxiliary query degrades with a note — the explain()
        verdict is never discarded (mapping §8)."""
        router.add('CALL explain', [TOR_EXPLAIN], ioc='185.220.101.1')

        # fetch_flags (first aux call after explain) blows up transiently
        def boom(*a, **k):
            raise wi.WhisperTransportError('flaky')

        import pytest as _pytest

        monkeypatch = _pytest.MonkeyPatch()
        monkeypatch.setattr(wi, 'fetch_flags', boom)
        try:
            payload = wi.enrich('185.220.101.1', 'ipv4', 'k', {}, *make_cfg_args())
        finally:
            monkeypatch.undo()
        w = payload['whisper']
        assert w['verdict'] == 'suspicious'  # verdict from explain() survived
        assert w['known'] is True  # a feed listing proves the node exists
        assert 'flags unavailable' in w['unmapped_summary']
        # threat_feed still built from explain sources[]; flags[] empty (fetch_flags failed)
        assert w['threat_feed']['feeds'] == ['dan-tor-exit', 'stamparm-ipsum', 'tor-exit-nodes']
        assert w['threat_feed']['flags'] == []

    def test_aux_auth_error_still_terminates(self, wi, router, monkeypatch):
        """Auth is terminal even from an auxiliary query — must propagate, not degrade."""
        router.add('CALL explain', [TOR_EXPLAIN], ioc='185.220.101.1')

        def boom(*a, **k):
            raise wi.WhisperAuthError('403')

        monkeypatch.setattr(wi, 'fetch_flags', boom)
        with pytest.raises(wi.WhisperAuthError):
            wi.enrich('185.220.101.1', 'ipv4', 'k', {}, *make_cfg_args())

    def _wire_tor_ip(self, router, belongs):
        router.add('CALL explain', [TOR_EXPLAIN], ioc='185.220.101.1')
        router.add('CALL explain', [{'available': True, 'found': True, 'breakdown': None}], ioc='AS60729')
        router.add('RETURN n.isThreat', [TOR_FLAGS])
        router.add('BELONGS_TO', [belongs])

    def test_tls_failure_keeps_core_fragments(self, wi, router, monkeypatch):
        """#32: an opt-in TLS query failure degrades with a note and NEVER drops the core
        asn/prefix/geo fragments or the verdict (its own try, after the core is built)."""
        self._wire_tor_ip(
            router,
            {
                'prefix': '185.220.101.0/24',
                'asn': 'AS60729',
                'asn_name': None,
                'asn_country': 'DE',
                'country': 'DE',
                'city': None,
                'prefix_threat_level': 'CRITICAL',
                'prefix_threat_score': 14,
                'prefix_is_threat': True,
                'prefix_threat_neighbors': 3,
            },
        )
        monkeypatch.setattr(
            wi, 'build_tls_fragment', lambda *a, **k: (_ for _ in ()).throw(wi.WhisperTransportError('flaky'))
        )
        w = wi.enrich('185.220.101.1', 'ipv4', 'k', {}, *make_cfg_args(), frozenset({'tls_fingerprint'}))[
            'whisper'
        ]
        assert w['verdict'] == 'suspicious'  # verdict survived
        assert w['asn']['number'] == 60729  # core asn survived
        assert w['prefix_threat']['level'] == 'CRITICAL'  # core prefix survived
        assert 'tls' not in w  # only tls dropped
        assert 'tls fingerprint lookup failed' in w['unmapped_summary']

    def test_tls_auth_error_terminates(self, wi, router, monkeypatch):
        """An auth error from the opt-in TLS query is terminal — it propagates, never degraded."""
        self._wire_tor_ip(
            router,
            {
                'prefix': '185.220.101.0/24',
                'asn': 'AS60729',
                'asn_name': None,
                'asn_country': 'DE',
                'country': 'DE',
                'city': None,
                'prefix_threat_level': 'NONE',
                'prefix_threat_score': 0,
                'prefix_is_threat': False,
                'prefix_threat_neighbors': 0,
            },
        )
        monkeypatch.setattr(
            wi, 'build_tls_fragment', lambda *a, **k: (_ for _ in ()).throw(wi.WhisperAuthError('403'))
        )
        with pytest.raises(wi.WhisperAuthError):
            wi.enrich('185.220.101.1', 'ipv4', 'k', {}, *make_cfg_args(), frozenset({'tls_fingerprint'}))


class TestFeedPolarity:
    def test_exact_slug(self, wi):
        assert wi.feed_category('tranco-top1m') == 'Popularity/Trust'
        assert wi.feed_category('openphish') == 'Phishing'
        assert wi.feed_category('dan-tor-exit') == 'TOR Network'

    def test_prefix_fallback_for_evolved_slugs(self, wi):
        assert wi.feed_category('hagezi-dns-pro-ip') == 'Ad/Tracking Blocklists'
        assert wi.feed_category('stopforumspam-listed-ip-7d') == 'Spam'

    def test_unknown_is_neutral(self, wi):
        assert wi.feed_category('some-new-feed') is None


class TestVerdictDerivation:
    """Mapping §6 ordered gates — TC-08's cross-artifact assertions live here."""

    def test_unavailable_is_unknown(self, wi):
        assert wi.derive_verdict({'available': False}, {}) == 'unknown'

    def test_absent_node_is_unknown(self, wi):
        """known=False (no graph node) → unknown, regardless of explain().found."""
        assert wi.derive_verdict({'available': True}, {}, known=False) == 'unknown'

    def test_tor_high_without_confirmed_bad_is_suspicious(self, wi):
        """TC-01/TC-08: level HIGH + Tor/blacklist categories → suspicious, NOT known_bad."""
        assert wi.derive_verdict(TOR_EXPLAIN, TOR_FLAGS) == 'suspicious'

    def test_allowlist_vouched_is_known_good_despite_listings(self, wi):
        """TC-07: 8.8.8.8 — listed in DNS-filter feeds but advisory-vouched."""
        assert wi.derive_verdict(GOOGLE_DNS_EXPLAIN, {}) == 'known_good'

    def test_trust_feeds_only_is_known_good(self, wi):
        row = {
            'available': True,
            'found': True,
            'level': 'NONE',
            'sources': [{'feedId': 'tranco-top1m'}, {'feedId': 'cloudflare-radar-top1m'}],
        }
        assert wi.derive_verdict(row, {}) == 'known_good'

    def test_high_with_confirmed_bad_category_is_known_bad(self, wi):
        row = {'available': True, 'found': True, 'level': 'HIGH', 'sources': [{'feedId': 'openphish'}]}
        assert wi.derive_verdict(row, {}) == 'known_bad'

    def test_low_level_is_suspicious(self, wi):
        row = {'available': True, 'found': True, 'level': 'LOW', 'sources': [{'feedId': 'stamparm-ipsum'}]}
        assert wi.derive_verdict(row, {}) == 'suspicious'

    def test_found_with_zero_evidence_is_unknown_not_good(self, wi):
        """No data ≠ benign: a clean, unlisted node earns unknown, never known_good."""
        row = {'available': True, 'found': True, 'level': 'NONE', 'sources': []}
        assert wi.derive_verdict(row, {}) == 'unknown'

    def test_weak_bad_flags_alone_are_suspicious(self, wi):
        """Annoyance-level flags (bruteforce/scanner/spam) are threat evidence but NOT
        confirmed-malicious on their own → suspicious, not known_bad (#30)."""
        row = {'available': True, 'found': True, 'level': 'NONE', 'sources': []}
        assert wi.derive_verdict(row, {'isBruteforce': True}) == 'suspicious'
        assert wi.derive_verdict(row, {'isScanner': True}) == 'suspicious'

    def test_hard_bad_flag_alone_is_known_bad(self, wi):
        """#30: a confirmed-malicious node flag is known_bad on its own — no HIGH level or
        confirmed-bad feed CATEGORY required (the node IS bad infrastructure)."""
        row = {'available': True, 'found': True, 'level': 'NONE', 'sources': []}
        for flag in (
            'isC2',
            'isMalware',
            'isPhishing',
            'isBotnet',
            'isExfilDestination',
            'isOfacSanctioned',
            'isStateActor',
        ):
            assert wi.derive_verdict(row, {flag: True}) == 'known_bad', flag

    def test_generic_threat_flag_stays_suspicious(self, wi):
        """isThreat is a generic aggregate, not a confirmed-bad classification → suspicious."""
        row = {'available': True, 'found': True, 'level': 'NONE', 'sources': []}
        assert wi.derive_verdict(row, {'isThreat': True}) == 'suspicious'

    def test_whitelist_flag_cannot_override_confirmed_bad(self, wi):
        """A compromised whitelisted host: isWhitelist must NOT force known_good."""
        row = {'available': True, 'found': True, 'level': 'HIGH', 'sources': [{'feedId': 'openphish'}]}
        assert wi.derive_verdict(row, {'isWhitelist': True, 'isPhishing': True}) == 'known_bad'

    def test_trust_signal_with_high_severity_is_not_known_good(self, wi):
        """Trust feeds + a HIGH level → severity blocks the known_good gate."""
        row = {'available': True, 'found': True, 'level': 'HIGH', 'sources': [{'feedId': 'tranco-top1m'}]}
        assert wi.derive_verdict(row, {}) != 'known_good'

    def test_neutral_category_only_is_unknown(self, wi):
        """A listing only in DNS-filter/reputation (neutral) feeds, level NONE, no flags
        → unknown, not suspicious (None ≠ threat signal)."""
        row = {
            'available': True,
            'found': True,
            'level': 'NONE',
            'sources': [{'feedId': 'hagezi-dns-light-ip'}, {'feedId': 'alienvault-reputation'}],
        }
        assert wi.derive_verdict(row, {}) == 'unknown'

    def test_general_blacklist_only_is_suspicious(self, wi):
        row = {'available': True, 'found': True, 'level': 'NONE', 'sources': [{'feedId': 'spamhaus-drop'}]}
        assert wi.derive_verdict(row, {}) == 'suspicious'


class TestIpEnrichment:
    def _wire_tor(self, router):
        router.add('CALL explain', [TOR_EXPLAIN], ioc='185.220.101.1')
        router.add(
            'CALL explain',
            [{'available': True, 'found': True, 'breakdown': {'threatDensityScore': 30}}],
            ioc='AS60729',
        )
        router.add('RETURN n.isThreat', [TOR_FLAGS])
        router.add(
            'BELONGS_TO',
            [
                {
                    'prefix': '185.220.101.0/24',
                    'asn': 'AS60729',
                    'asn_name': None,
                    'asn_country': 'DE',
                    'country': 'DE',
                    'city': None,
                }
            ],
        )

    def test_envelope_matches_mapping_contract(self, wi, router):
        self._wire_tor(router)
        payload = wi.enrich(
            '185.220.101.1', 'ipv4', 'ipv4|185.220.101.1|001', {'rule_id': '5710'}, *make_cfg_args()
        )
        assert payload['integration'] == 'custom-whisper'
        w = payload['whisper']
        assert w['verdict'] == 'suspicious'  # evidence rules, not the raw HIGH level
        assert w['known'] is True and w['available'] is True
        assert w['level'] == 'HIGH' and w['risk_score'] == pytest.approx(7.46)
        # null values are STRIPPED before send (analysisd would index literal "null" strings):
        # asn.name (AS60729 has no HAS_NAME) and the always-null coverage sub-fields are absent
        assert w['asn'] == {
            'number': 60729,
            'country': 'DE',
            'reputation': {'threatDensityScore': 30},
        }
        assert w['prefix'] == '185.220.101.0/24'
        assert w['geo'] == {'country': 'DE'}
        assert w['threat_feed']['feeds'] == ['dan-tor-exit', 'stamparm-ipsum', 'tor-exit-nodes']
        assert w['threat_feed']['categories'] == ['General Blacklists', 'TOR Network']
        assert w['threat_feed']['sources_count'] == 3
        assert w['threat_feed']['first_seen'] == '2026-06-22T19:25:52Z'
        assert w['threat_feed']['last_seen'] == '2026-07-02T19:35:16Z'
        assert set(w['threat_feed']['flags']) == {'isThreat', 'isTor', 'isSpam', 'isAnonymizer'}
        assert 'tor' in w['tags'] and 'anonymizer' in w['tags']
        assert w['coverage'] == {'granularity': 'ipv4'}
        assert 'advisory' not in w and 'unmapped_summary' not in w  # nulls stripped
        assert w['graph_node_id'] == 'ipv4/185.220.101.1'
        assert w['permalink'].endswith('/ip/185.220.101.1')
        assert w['dedup_key'] == 'ipv4|185.220.101.1|001'
        assert w['source_ref'] == {'rule_id': '5710'}
        assert wi._payload_size(payload) < wi.MAX_PAYLOAD_BYTES

    def test_absent_node_minimal_envelope(self, wi, router):
        """explain() available but no node (no sources, flags query returns nothing) →
        known:false even though explain().found is unreliable."""
        router.add('CALL explain', [{'available': True, 'found': True, 'type': 'ip', 'sources': []}])
        # no 'RETURN n.isThreat' route → fetch_flags returns None → node absent
        payload = wi.enrich('203.0.114.9', 'ipv4', 'k', {}, *make_cfg_args())
        w = payload['whisper']
        assert w['verdict'] == 'unknown' and w['known'] is False
        assert 'graph_node_id' not in w  # null → stripped (would index as the string "null")
        assert 'threat_feed' not in w and 'asn' not in w  # no fragment queries for absent node
        # exactly the explain probe + the node-existence check, nothing more
        assert any('n.isThreat' in c for c, _ in router.calls)
        assert not any('BELONGS_TO' in c for c, _ in router.calls)

    def test_degraded_backend_fixture(self, wi, router):
        """TC-14: available:false + retryAfter → unknown verdict, note recorded, no crash."""
        fixture = json.loads((FIXTURES / 'explain_unavailable.json').read_text())
        router.add('CALL explain', [fixture])
        payload = wi.enrich('185.220.101.1', 'ipv4', 'k', {}, *make_cfg_args())
        w = payload['whisper']
        assert w['available'] is False and w['verdict'] == 'unknown'
        assert 'retryAfter=60' in w['unmapped_summary']

    def _wire_threat_ip(self, router, belongs_row):
        """Listed IP with a caller-supplied BELONGS_TO row so #29 prefix threat props can vary."""
        router.add('CALL explain', [TOR_EXPLAIN], ioc='185.220.101.1')
        router.add('CALL explain', [{'available': True, 'found': True, 'breakdown': None}], ioc='AS60729')
        router.add('CALL explain', [{'available': True, 'found': True, 'breakdown': None}], ioc='AS15169')
        router.add('RETURN n.isThreat', [TOR_FLAGS])
        router.add('BELONGS_TO', [belongs_row])

    def test_prefix_threat_emitted(self, wi, router):
        """#29: registered-PREFIX threat props ride the existing BELONGS_TO traversal (no extra
        round-trip). Verified live 2026-07-11: the /24 reads CRITICAL while its ASN aggregate
        reads NONE — the granular prefix signal is the actionable one (ASN aggregate dropped as
        noise: only 2/116k ASNs carry a non-NONE level)."""
        self._wire_threat_ip(
            router,
            {
                'prefix': '185.220.101.0/24',
                'asn': 'AS60729',
                'asn_name': None,
                'asn_country': 'DE',
                'country': 'DE',
                'city': None,
                'prefix_threat_level': 'CRITICAL',
                'prefix_threat_score': 14,
                'prefix_is_threat': True,
                'prefix_threat_neighbors': 151,
            },
        )
        w = wi.enrich('185.220.101.1', 'ipv4', 'k', {}, *make_cfg_args())['whisper']
        assert w['prefix_threat'] == {
            'level': 'CRITICAL',
            'score': 14,
            'is_threat': True,
            'threat_neighbor_count': 151,
        }
        assert 'threat' not in w['asn']  # ASN-level aggregate deliberately not emitted

    def test_benign_prefix_stays_quiet(self, wi, router):
        """A listed IP whose registered prefix carries no threat signal must NOT sprout an
        empty prefix_threat block (the quiet-level gate)."""
        self._wire_threat_ip(
            router,
            {
                'prefix': '8.8.8.0/24',
                'asn': 'AS15169',
                'asn_name': 'GOOGLE',
                'asn_country': 'US',
                'country': 'US',
                'city': None,
                'prefix_threat_level': 'NONE',
                'prefix_threat_score': 0,
                'prefix_is_threat': False,
                'prefix_threat_neighbors': 0,
            },
        )
        w = wi.enrich('185.220.101.1', 'ipv4', 'k', {}, *make_cfg_args())['whisper']
        assert 'prefix_threat' not in w

    _BENIGN_BELONGS = {
        'prefix': '198.51.100.0/24',
        'asn': 'AS64500',
        'asn_name': None,
        'asn_country': None,
        'country': None,
        'city': None,
        'prefix_threat_level': 'NONE',
        'prefix_threat_score': 0,
        'prefix_is_threat': False,
        'prefix_threat_neighbors': 0,
    }
    _CS_JARM = {
        'fingerprint': 'jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1',
        'kind': 'jarm',
        'family': 'cobalt-strike-default',
        'cluster_size': 139,
    }

    def test_tls_fingerprint_opt_in_emitted(self, wi, router):
        """#32: with tls_fingerprint enabled, a CS-JARM edge surfaces as data.whisper.tls.*
        (the actionable field is family='cobalt-strike-default')."""
        self._wire_threat_ip(router, dict(self._BENIGN_BELONGS))
        router.add('EMITS_TLS_FINGERPRINT', [dict(self._CS_JARM)])
        w = wi.enrich('185.220.101.1', 'ipv4', 'k', {}, *make_cfg_args(), frozenset({'tls_fingerprint'}))[
            'whisper'
        ]
        assert w['tls'] == self._CS_JARM

    def test_tls_fingerprint_off_by_default(self, wi, router):
        """No opt-in → the TLS query never runs and no tls field is emitted."""
        self._wire_threat_ip(router, dict(self._BENIGN_BELONGS))
        router.add('EMITS_TLS_FINGERPRINT', [dict(self._CS_JARM)])
        w = wi.enrich('185.220.101.1', 'ipv4', 'k', {}, *make_cfg_args())['whisper']
        assert 'tls' not in w
        assert not any('EMITS_TLS_FINGERPRINT' in c for c, _ in router.calls)

    def test_tls_fingerprint_absent_when_no_edge(self, wi, router):
        """Enabled but the IP emits no fingerprint → field omitted (absence never rendered)."""
        self._wire_threat_ip(router, dict(self._BENIGN_BELONGS))
        # no EMITS_TLS_FINGERPRINT route → query returns [] → build_tls_fragment None
        w = wi.enrich('185.220.101.1', 'ipv4', 'k', {}, *make_cfg_args(), frozenset({'tls_fingerprint'}))[
            'whisper'
        ]
        assert 'tls' not in w

    def test_tls_fingerprint_multiple_adds_count(self, wi, router):
        """An IP emitting >1 fingerprint surfaces the top (highest cluster_size) + a count."""
        self._wire_threat_ip(router, dict(self._BENIGN_BELONGS))
        router.add(
            'EMITS_TLS_FINGERPRINT',
            [
                dict(self._CS_JARM),
                {
                    'fingerprint': 'jarm:other',
                    'kind': 'jarm',
                    'family': 'cobalt-strike-default',
                    'cluster_size': 3,
                },
            ],
        )
        w = wi.enrich('185.220.101.1', 'ipv4', 'k', {}, *make_cfg_args(), frozenset({'tls_fingerprint'}))[
            'whisper'
        ]
        assert w['tls']['fingerprint'] == self._CS_JARM['fingerprint'] and w['tls']['count'] == 2

    def test_tls_fingerprint_ipv4_only(self, wi, router):
        """EMITS_TLS_FINGERPRINT lives on IPV4 — the query must not run for an IPv6 IOC."""
        router.add('IPV6', [{}])  # ipv6 context query → empty ctx
        cfg = {
            'api_url': 'u',
            'api_key': 'k',
            'timeout': 10,
            'retries': 3,
            'extra': frozenset({'tls_fingerprint'}),
        }
        wi.build_ip_fragments(cfg, '2001:db8::1', 'ipv6', {}, [])
        assert not any('EMITS_TLS_FINGERPRINT' in c for c, _ in router.calls)


class TestDomainEnrichment:
    def _wire_domain(self, router, links_count=2, suspicious_count=0):
        router.add(
            'CALL explain',
            [
                {
                    'indicator': 'evil.example',
                    'type': 'domain',
                    'available': True,
                    'found': True,
                    'score': 62.4,
                    'level': 'HIGH',
                    'sources': [
                        {
                            'feedId': 'openphish',
                            'weight': 1.0,
                            'firstSeen': '2026-06-30T08:14:00Z',
                            'lastSeen': '2026-07-01T22:40:00Z',
                        }
                    ],
                    'advisory': None,
                }
            ],
            ioc='evil.example',
        )
        router.add('RETURN n.isThreat', [{'isThreat': True, 'isPhishing': True}])
        router.add('RESOLVES_TO]->(m:IPV4', [{'name': '203.0.113.77'}])
        router.add('RESOLVES_TO]->(m:IPV6', [])
        router.add('ALIAS_OF', [{'name': 'cdn.hosting.example'}])
        router.add('NAMESERVER_FOR', [{'name': 'ns1.cheap-dns.example'}])
        router.add('MAIL_FOR', [{'name': 'mail.cheap-dns.example'}])
        router.add('HAS_REGISTRAR', [{'registrar': 'NameCheap, Inc.', 'previous': 'NameCheap, Inc.'}])
        router.add('REGISTERED_BY', [{'name': 'WhoisGuard Protected'}, {'name': 'Second Org'}])
        router.add('HAS_EMAIL', [{'name': 'abuse@whoisguard.example'}])
        router.add('HAS_PHONE', [])
        router.add('SPF_INCLUDE', [{'name': '_spf.cheap-dns.example'}])
        for edge in ('SPF_A', 'SPF_MX', 'SPF_IP', 'SPF_REDIRECT', 'SPF_EXISTS'):
            router.add(edge, [])
        router.add('-[:LINKS_TO]->(o:HOSTNAME) WITH o LIMIT 26 RETURN o.name', [{'name': 'paypal.com'}])
        router.add('<-[:LINKS_TO]-(o:HOSTNAME) WITH o LIMIT 26 RETURN o.name', [])
        router.add('-[:LINKS_TO]->(o:HOSTNAME) WITH o LIMIT 500 RETURN count', [{'c': links_count}])
        router.add('<-[:LINKS_TO]-(o:HOSTNAME) WITH o LIMIT 500 RETURN count', [{'c': 0}])
        router.add('WHERE o.isThreat WITH o LIMIT 500 RETURN count', [{'c': suspicious_count}])
        router.add('UNWIND $cands', [{'name': '3vil.example'}])

    def test_domain_envelope(self, wi, router):
        self._wire_domain(router)
        payload = wi.enrich(
            'evil.example', 'domain', 'domain|evil.example|004', {'rule_id': '100290'}, *make_cfg_args()
        )
        w = payload['whisper']
        assert w['verdict'] == 'known_bad'  # HIGH + Phishing (confirmed-bad category)
        assert w['dns'] == {
            'a': ['203.0.113.77'],
            'aaaa': [],
            'cname': ['cdn.hosting.example'],
            'ns': ['ns1.cheap-dns.example'],
            'mx': ['mail.cheap-dns.example'],
        }
        assert w['whois']['registrar'] == 'NameCheap, Inc.'
        # first-writer-wins nulled previous_registrar → stripped from the payload
        assert 'previous_registrar' not in w['whois']
        assert w['whois']['registered_by'] == 'WhoisGuard Protected'
        assert 'additional registrant org' in w['unmapped_summary']
        assert w['spf']['include'] == ['_spf.cheap-dns.example']
        assert 'redirect' not in w['spf']  # null → stripped
        assert w['links'] == {
            'outbound': ['paypal.com'],
            'outbound_total': 2,
            'inbound': [],
            'inbound_total': 0,
        }
        assert w['variants'] == [{'variant': '3vil.example', 'method': 'homoglyph', 'confidence': 0.9}]
        assert w['threat_feed']['categories'] == ['Phishing']
        assert w['coverage']['granularity'] == 'hostname'
        assert w['graph_node_id'] == 'hostname/evil.example'
        assert w['permalink'].endswith('/domain/evil.example')

    def test_suspicious_link_count_emitted(self, wi, router):
        """#30: outbound links to threat-listed domains surface as links.suspicious_count."""
        self._wire_domain(router, suspicious_count=3)
        w = wi.enrich('evil.example', 'domain', 'k', {}, *make_cfg_args())['whisper']
        assert w['links']['suspicious_count'] == 3

    def test_no_suspicious_links_stays_quiet(self, wi, router):
        """Zero threat-linked targets → the field is omitted (a clean domain stays quiet)."""
        self._wire_domain(router, suspicious_count=0)
        w = wi.enrich('evil.example', 'domain', 'k', {}, *make_cfg_args())['whisper']
        assert 'suspicious_count' not in w['links']

    def test_ns_mx_query_directions(self, wi, router):
        """The seed's OWN NS/MX are matched with `<-` (neighbour→seed edges)."""
        self._wire_domain(router)
        wi.enrich('evil.example', 'domain', 'k', {}, *make_cfg_args())
        ns_calls = [c for c, _ in router.calls if 'NAMESERVER_FOR' in c]
        mx_calls = [c for c, _ in router.calls if 'MAIL_FOR' in c]
        assert all('<-[:NAMESERVER_FOR]-' in c for c in ns_calls)
        assert all('<-[:MAIL_FOR]-' in c for c in mx_calls)


class TestVariants:
    def test_generator_bounded_and_original_excluded(self, wi):
        variants = wi.generate_domain_variants('paypal.com')
        names = [v for v, _, _ in variants]
        assert 'paypal.com' not in names
        assert len(variants) <= wi.MAX_VARIANT_CANDIDATES
        assert any(m == 'homoglyph' for _, m, _ in variants)

    def test_single_label_yields_nothing(self, wi):
        assert wi.generate_domain_variants('localhost') == []

    def test_subdomain_reduces_to_registrable(self, wi):
        """www.evil-site.com must squat 'evil-site', never the 'www' subdomain label."""
        variants = [v for v, _, _ in wi.generate_domain_variants('www.evil-site.com')]
        assert all(v.endswith('evil-site.com') or v.split('.')[0] != 'www' for v in variants)
        assert 'www.net' not in variants and 'www.io' not in variants
        # a homoglyph of the registrable label is present
        assert any(v.startswith('3vil-site') or v.startswith('ev1l-site') for v in variants)

    def test_registrable_domain(self, wi):
        assert wi.registrable_domain('a.b.evil.com') == 'evil.com'
        assert wi.registrable_domain('evil.com') == 'evil.com'
        assert wi.registrable_domain('localhost') is None


class TestPayloadGuard:
    def test_oversized_lists_dropped_with_notes(self, wi):
        notes = []
        whisper = {
            'schema_version': '1.0',
            'ioc': 'x.example',
            'truncated': False,
            'links': {
                'outbound': ['a' * 100] * 700,
                'inbound': ['b' * 100] * 700,
                'outbound_total': 700,
                'inbound_total': 700,
            },
            'variants': [],
            'dns': {'a': []},
            'whois': {'email': [], 'phone': []},
            'threat_feed': {'feeds': []},
        }
        payload = {'integration': wi.INTEGRATION_NAME, 'whisper': whisper}
        fitted = wi.fit_payload(payload, notes)
        assert wi._payload_size(fitted) + wi.FRAMING_MARGIN <= wi.MAX_PAYLOAD_BYTES
        assert fitted['whisper']['truncated'] is True
        assert any('payload budget' in n for n in notes)
        assert fitted['whisper']['links']['outbound_total'] == 700  # totals survive the drop

    def test_last_resort_core_reduction(self, wi):
        """When list drops aren't enough, everything non-core is stripped but the verdict
        core (and unmapped_summary) survives — never a failed send."""
        notes = []
        whisper = {
            'schema_version': '1.0',
            'ioc': 'x.example',
            'verdict': 'known_bad',
            'source_ref': {'rule_id': '1'},
            'truncated': False,
            'unmapped_summary': None,
            'note_field': 'x' * 70000,  # non-core bloat, not a droppable list
        }
        payload = {'integration': wi.INTEGRATION_NAME, 'whisper': whisper}
        fitted = wi.fit_payload(payload, notes)['whisper']
        assert fitted['verdict'] == 'known_bad' and fitted['ioc'] == 'x.example'
        assert 'note_field' not in fitted  # non-core stripped
        assert fitted['truncated'] is True
        assert any('reduced to core' in n for n in notes)

    def test_small_payload_untouched(self, wi):
        notes = []
        whisper = {'ioc': 'x', 'links': {'outbound': ['a'], 'inbound': []}, 'truncated': False}
        payload = {'integration': wi.INTEGRATION_NAME, 'whisper': whisper}
        assert wi.fit_payload(payload, notes)['whisper']['links']['outbound'] == ['a']
        assert notes == []
