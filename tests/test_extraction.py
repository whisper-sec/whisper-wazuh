"""IOC extraction, guards and the normative log vocabulary (acceptance §3, TC-04/05/21/22)."""


class TestPublicIpGuard:
    def test_public_ipv4_extracted(self, wi, make_alert):
        alert = make_alert(data={'srcip': '185.220.101.1'})
        assert wi.extract_iocs(alert) == [('185.220.101.1', 'ipv4', 'data.srcip')]

    def test_private_ip_skipped_with_line(self, wi, make_alert, log_lines):
        assert wi.extract_iocs(make_alert(data={'srcip': '10.0.0.5'})) == []
        assert 'whisper: skip reason=non-global ioc=10.0.0.5' in log_lines()

    def test_testnet_ip_skipped(self, wi, make_alert, log_lines):
        """TC-05: the stock dev-agent-demo IOC is TEST-NET-3 → not global."""
        assert wi.extract_iocs(make_alert(data={'srcip': '203.0.113.45'})) == []
        assert 'whisper: skip reason=non-global ioc=203.0.113.45' in log_lines()

    def test_global_ipv6_extracted(self, wi, make_alert):
        alert = make_alert(data={'srcip': '2001:4860:4860::8888'})
        assert wi.extract_iocs(alert) == [('2001:4860:4860::8888', 'ipv6', 'data.srcip')]

    def test_loopback_and_linklocal_skipped(self, wi, make_alert):
        assert wi.extract_iocs(make_alert(data={'srcip': '127.0.0.1'})) == []
        assert wi.extract_iocs(make_alert(data={'srcip': 'fe80::1'})) == []

    def test_ipv4_mapped_ipv6_unwrapped_to_global_ipv4(self, wi, make_alert):
        """Dual-stack listeners log peers as ::ffff:a.b.c.d — the embedded IPv4 is the IOC."""
        alert = make_alert(data={'srcip': '::ffff:185.220.101.1'})
        assert wi.extract_iocs(alert) == [('185.220.101.1', 'ipv4', 'data.srcip')]

    def test_ipv4_mapped_private_still_guarded(self, wi, make_alert, log_lines):
        assert wi.extract_iocs(make_alert(data={'srcip': '::ffff:10.0.0.5'})) == []
        assert any('skip reason=non-global' in line for line in log_lines())

    def test_ip_port_suffix_stripped(self, wi, make_alert):
        """O365-style ClientIP values arrive as ip:port."""
        alert = make_alert(data={'office365': {'ClientIP': '40.94.31.15:44916'}})
        assert wi.extract_iocs(alert) == [('40.94.31.15', 'ipv4', 'data.office365.ClientIP')]

    def test_bracketed_ipv6_port_stripped(self, wi, make_alert):
        alert = make_alert(data={'office365': {'ClientIP': '[2a00:1450:4009:80f::200e]:443'}})
        assert wi.extract_iocs(alert) == [('2a00:1450:4009:80f::200e', 'ipv6', 'data.office365.ClientIP')]

    def test_agent_ip_is_not_a_trigger(self, wi, make_alert, log_lines):
        """agent.ip is present on every agent alert — deliberately not extracted."""
        alert = make_alert(data={})  # agent.ip = 172.19.0.5 in the fixture
        assert wi.extract_iocs(alert) == []
        assert 'whisper: skip reason=non-global ioc=172.19.0.5' not in log_lines()
        assert 'whisper: skip reason=no-ioc' in log_lines()


class TestDomainExtraction:
    def test_domain_extracted_lowercased(self, wi, make_alert):
        alert = make_alert(data={'dns': {'rrname': 'Google.COM.'}})
        assert wi.extract_iocs(alert) == [('google.com', 'domain', 'data.dns.rrname')]

    def test_punycode_tld_accepted(self, wi, make_alert):
        """IDN domains render as A-labels in DNS logs — xn-- TLDs are real IOCs."""
        alert = make_alert(data={'dns': {'rrname': 'example.xn--p1ai'}})
        assert wi.extract_iocs(alert) == [('example.xn--p1ai', 'domain', 'data.dns.rrname')]

    def test_ip_in_domain_path_is_an_ip(self, wi, make_alert):
        """mapping §9: an IP arriving via a domain path is still an IP."""
        alert = make_alert(data={'dns': {'rrname': '8.8.8.8'}})
        assert wi.extract_iocs(alert) == [('8.8.8.8', 'ipv4', 'data.dns.rrname')]

    def test_private_ip_in_domain_path_guarded(self, wi, make_alert, log_lines):
        alert = make_alert(data={'dns': {'rrname': '192.168.1.10'}})
        assert wi.extract_iocs(alert) == []
        assert 'whisper: skip reason=non-global ioc=192.168.1.10' in log_lines()

    def test_garbage_domain_ignored_quietly(self, wi, make_alert, log_lines):
        alert = make_alert(data={'dns': {'rrname': 'not a domain!!'}})
        assert wi.extract_iocs(alert) == []
        lines = log_lines()
        # a value existed on a supported path → not a no-ioc case; no guard line either —
        # just the quiet debug note
        assert 'whisper: skip reason=no-ioc' not in lines
        assert not any('skip reason=non-global' in line for line in lines)
        assert any('ignoring value at data.dns.rrname' in line for line in lines)

    def test_single_label_not_a_domain(self, wi, make_alert):
        assert wi.extract_iocs(make_alert(data={'dns': {'rrname': 'localhost'}})) == []


class TestUrlHostExtraction:
    """data.url is an active url_host path — host component of ABSOLUTE URLs only."""

    def test_absolute_url_host_extracted_as_domain(self, wi, make_alert):
        alert = make_alert(data={'url': 'https://evil.example/login.php'})
        assert wi.extract_iocs(alert) == [('evil.example', 'domain', 'data.url')]

    def test_absolute_url_with_ip_host(self, wi, make_alert):
        alert = make_alert(data={'url': 'http://185.220.101.1:8080/x'})
        assert wi.extract_iocs(alert) == [('185.220.101.1', 'ipv4', 'data.url')]

    def test_absolute_url_with_private_ip_guarded(self, wi, make_alert, log_lines):
        assert wi.extract_iocs(make_alert(data={'url': 'http://10.0.0.5/x'})) == []
        assert any('skip reason=non-global' in line for line in log_lines())

    def test_path_only_url_yields_nothing(self, wi, make_alert, log_lines):
        """nginx/apache access-log url values are path-only (Q1 live evidence)."""
        alert = make_alert(data={'url': '/q1test/suspicious.php'})
        assert wi.extract_iocs(alert) == []
        lines = log_lines()
        assert 'whisper: skip reason=no-ioc' not in lines  # present, just not an IOC
        assert not any('unsupported-type' in line for line in lines)  # data.url is active


class TestExtractionEdges:
    def test_no_supported_path_logs_no_ioc(self, wi, make_alert, log_lines):
        """TC-21."""
        assert wi.extract_iocs(make_alert(data={'something': 'else'})) == []
        assert 'whisper: skip reason=no-ioc' in log_lines()

    def test_unsupported_type_logged_not_extracted(self, wi, make_alert, log_lines):
        """TC-22: hash/path candidates are documented-but-inactive."""
        alert = make_alert(data={}, syscheck={'sha256_after': 'ab' * 32, 'path': '/etc/passwd'})
        assert wi.extract_iocs(alert) == []
        lines = log_lines()
        assert 'whisper: skip reason=unsupported-type field=syscheck.sha256_after' in lines
        assert 'whisper: skip reason=unsupported-type field=syscheck.path' in lines
        assert 'whisper: skip reason=no-ioc' not in lines  # values existed — not a no-ioc case

    def test_multiple_paths_deduplicated(self, wi, make_alert):
        alert = make_alert(data={'srcip': '185.220.101.1', 'src_ip': '185.220.101.1'})
        assert wi.extract_iocs(alert) == [('185.220.101.1', 'ipv4', 'data.srcip')]

    def test_multiple_distinct_iocs_ordered(self, wi, make_alert):
        alert = make_alert(data={'srcip': '185.220.101.1', 'dns': {'rrname': 'example.com'}})
        assert wi.extract_iocs(alert) == [
            ('185.220.101.1', 'ipv4', 'data.srcip'),
            ('example.com', 'domain', 'data.dns.rrname'),
        ]

    def test_list_valued_field_extracts_each(self, wi, make_alert):
        """JSON decoders can aggregate repeated fields into arrays."""
        alert = make_alert(data={'srcip': ['185.220.101.1', '185.220.101.2']})
        assert wi.extract_iocs(alert) == [
            ('185.220.101.1', 'ipv4', 'data.srcip'),
            ('185.220.101.2', 'ipv4', 'data.srcip'),
        ]

    def test_non_string_value_is_present_not_false_no_ioc(self, wi, make_alert, log_lines):
        """A numeric/dict value at a supported path must NOT produce the no-ioc line —
        the path was present; the value just isn't extractable."""
        assert wi.extract_iocs(make_alert(data={'srcip': 1234})) == []
        assert 'whisper: skip reason=no-ioc' not in log_lines()
        assert any('ignoring non-string value at data.srcip' in line for line in log_lines())

    def test_suricata_dest_ip_path(self, wi, make_alert):
        """Suricata uses dest_ip — NOT dst_ip (Q1 source audit)."""
        alert = make_alert(data={'dest_ip': '185.220.101.1'})
        assert wi.extract_iocs(alert) == [('185.220.101.1', 'ipv4', 'data.dest_ip')]

    def test_deep_guardduty_path(self, wi, make_alert):
        alert = make_alert(
            data={
                'aws': {
                    'service': {
                        'action': {
                            'networkConnectionAction': {'remoteIpDetails': {'ipAddressV4': '185.220.101.1'}}
                        }
                    }
                }
            }
        )
        assert wi.extract_iocs(alert) == [
            (
                '185.220.101.1',
                'ipv4',
                'data.aws.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4',
            )
        ]


class TestSelfAlertGuard:
    def test_self_alert_detected(self, wi, make_alert):
        alert = make_alert(data={'integration': 'custom-whisper', 'whisper': {'ioc': 'x'}})
        assert wi.is_self_alert(alert) is True

    def test_normal_alert_not_self(self, wi, make_alert):
        assert wi.is_self_alert(make_alert(data={'srcip': '1.2.3.4'})) is False

    def test_main_exits_zero_on_self_alert(self, wi, write_alert, log_lines):
        alert_file = write_alert(data={'integration': 'custom-whisper'})
        assert wi.main(['s', alert_file, '', '', 'debug']) == 0
        assert 'whisper: skip reason=self-alert' in log_lines()


class TestDedupKey:
    def test_format_with_agent(self, wi):
        assert wi.make_dedup_key('ipv4', '185.220.101.1', '001') == 'ipv4|185.220.101.1|001'

    def test_format_without_agent(self, wi):
        assert wi.make_dedup_key('domain', 'example.com', '001', include_agent=False) == 'domain|example.com'

    def test_scope_resolution(self, wi):
        assert wi.resolve_dedup_scope({'dedup_scope': 'org'}, {}) is False
        assert wi.resolve_dedup_scope({'dedup_scope': 'endpoint'}, {}) is True
        assert wi.resolve_dedup_scope({}, {'WHISPER_DEDUP_SCOPE': 'org'}) is False
        assert wi.resolve_dedup_scope({}, {}) is True  # default: per-endpoint


class TestSourceRef:
    def test_built_from_alert(self, wi, make_alert):
        ref = wi.build_source_ref(make_alert(data={'srcip': '1.2.3.4'}), 'data.srcip')
        assert ref == {
            'rule_id': '5710',
            'alert_id': '1751709600.123456',
            'agent_id': '001',
            'field_path': 'data.srcip',
            'original_full_log': 'Jul  5 10:00:00 server sshd[1234]: Failed password ...',
        }

    def test_full_log_truncated(self, wi, make_alert):
        ref = wi.build_source_ref(make_alert(full_log='x' * 2000), 'data.srcip')
        assert len(ref['original_full_log']) == wi.ORIGINAL_LOG_MAX


class TestVocabularyFormats:
    """The exact grep tokens the acceptance plan asserts on — do not drift."""

    def test_all_lines(self, wi, log_lines):
        wi.log_invoke('1.2.3.4', 'ipv4', 'ipv4|1.2.3.4|001')
        wi.log_skip('dedup', dedup_key='ipv4|1.2.3.4|001')
        wi.log_api('https://graph.whisper.online', 42)
        wi.log_error(wi.WhisperAuthError('401 from api'))
        wi.log_emit('ipv4|1.2.3.4|001', 2048)
        assert log_lines() == [
            'whisper: invoke ioc=1.2.3.4 type=ipv4 dedup_key=ipv4|1.2.3.4|001',
            'whisper: skip reason=dedup dedup_key=ipv4|1.2.3.4|001',
            'whisper: api url=https://graph.whisper.online ms=42',
            'whisper: error class=auth detail=401 from api',
            'whisper: emit dedup_key=ipv4|1.2.3.4|001 payload_bytes=2048',
        ]

    def test_error_taxonomy_classes(self, wi):
        assert wi.WhisperAuthError('x').log_class == 'auth'
        assert wi.WhisperTransportError('x').log_class == 'transport'
        assert wi.WhisperQueryError('x').log_class == 'query'
        assert wi.WhisperSocketError('x').log_class == 'socket'
