"""#16 — whisper_rules.xml / whisper_test_rules.xml: well-formed + correct structure."""

import xml.etree.ElementTree as ET
from pathlib import Path

RULES = Path(__file__).resolve().parent.parent / 'integrations' / 'whisper'


def _rules(filename):
    """Parse a Wazuh rules file → {rule_id: element}. (Each ships a single <group> root,
    so it is also well-formed XML — a leading comment is allowed.)"""
    root = ET.parse(RULES / filename).getroot()
    assert root.tag == 'group'
    return {r.get('id'): r for r in root.findall('rule')}


class TestWhisperRules:
    def test_well_formed_and_ids(self):
        rules = _rules('whisper_rules.xml')
        assert set(rules) == {'100200', '100201', '100202', '100203', '100204', '100205', '100206'}

    def test_tls_c2_rule(self):
        """#32: the opt-in TLS-fingerprint rule escalates a Cobalt Strike JARM to level 12
        INDEPENDENT of verdict (chains off the base classifier, not off a verdict rule)."""
        r = _rules('whisper_rules.xml')['100206']
        assert r.get('level') == '12'
        assert r.find('if_sid').text == '100200'  # base classifier, NOT a verdict rule
        field = r.find('field')
        assert field.get('name') == 'whisper.tls.family'  # un-prefixed
        assert field.get('type') == 'pcre2' and field.text == '^cobalt-strike-default$'
        assert 'whisper_c2' in r.find('group').text

    def test_base_classifier(self):
        base = _rules('whisper_rules.xml')['100200']
        assert base.get('level') == '0'
        assert base.find('decoded_as').text == 'json'
        field = base.find('field')
        assert field.get('name') == 'integration'  # NOT data.-prefixed
        assert field.text == '^custom-whisper$' and field.get('type') == 'pcre2'

    def test_verdict_to_level_mapping(self):
        rules = _rules('whisper_rules.xml')
        expected = {  # rule id -> (level, verdict-or-level match)
            '100201': ('12', '^known_bad$'),
            '100202': ('7', '^suspicious$'),
            '100203': ('3', '^known_good$'),
            '100204': ('3', '^unknown$'),
        }
        for rid, (level, match) in expected.items():
            r = rules[rid]
            assert r.get('level') == level
            assert r.find('if_sid').text == '100200'
            field = r.find('field')
            assert field.get('type') == 'pcre2' and field.text == match

    def test_critical_escalation(self):
        r = _rules('whisper_rules.xml')['100205']
        assert r.get('level') == '14'
        assert r.find('if_sid').text == '100201'  # chains off known_bad
        assert r.find('field').get('name') == 'whisper.level'
        assert r.find('field').text == '^CRITICAL$'

    def test_all_fields_unprefixed(self):
        """Rules XML never uses the data. prefix (mapping §2.2)."""
        for r in _rules('whisper_rules.xml').values():
            for field in r.findall('field'):
                assert not field.get('name').startswith('data.')

    def test_loop_guard_group(self):
        """Emitted alerts sit in whisper_enrichment — the group the trigger filter must
        never watch (mapping §8)."""
        root = ET.parse(RULES / 'whisper_rules.xml').getroot()
        assert 'whisper_enrichment' in root.get('name')

    def test_custom_id_range(self):
        for rid in _rules('whisper_rules.xml'):
            assert 100000 <= int(rid) <= 109999  # above the built-in ceiling


class TestTestRules:
    def test_dev_rule_matches_sentinel(self):
        rules = _rules('whisper_test_rules.xml')
        assert set(rules) == {'100290'}
        r = rules['100290']
        assert r.find('decoded_as').text == 'json'
        # matches a whisper_test sentinel, NOT dns.rrname directly, so it can never fire on
        # real DNS logs — only on our injected {"whisper_test":"1", ...} test event
        assert r.find('field').get('name') == 'whisper_test'
        assert r.find('field').text == '^1$'

    def test_dev_group_is_whisper_test(self):
        root = ET.parse(RULES / 'whisper_test_rules.xml').getroot()
        # the group the install.sh --dev step adds to the <integration> filter
        assert 'whisper_test' in root.get('name')
        # and it must NOT be whisper_enrichment (that would create a loop)
        assert 'whisper_enrichment' not in root.get('name')
