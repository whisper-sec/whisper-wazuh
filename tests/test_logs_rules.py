"""#35 — whisper_agent_rules.xml: well-formed, correct ids/levels, loop-guard separation."""

import xml.etree.ElementTree as ET
from pathlib import Path

WHISPER = Path(__file__).resolve().parent.parent / 'integrations' / 'whisper'


def _rules(filename):
    root = ET.parse(WHISPER / filename).getroot()
    assert root.tag == 'group'
    return root, {r.get('id'): r for r in root.findall('rule')}


class TestAgentRules:
    def test_well_formed_and_id_range(self):
        _, rules = _rules('whisper_agent_rules.xml')
        assert set(rules) == {'100510', '100511', '100512', '100513', '100514', '100515'}
        for rid in rules:
            assert 100510 <= int(rid) <= 100549

    def test_base_classifier(self):
        _, rules = _rules('whisper_agent_rules.xml')
        base = rules['100510']
        assert base.get('level') == '0'
        assert base.find('decoded_as').text == 'json'
        field = base.find('field')
        assert field.get('name') == 'integration'  # NOT data.-prefixed
        assert field.text == '^whisper-logs$' and field.get('type') == 'pcre2'

    def test_kind_decision_level_map(self):
        _, rules = _rules('whisper_agent_rules.xml')
        # dns refused → 6, dns allow → 3, conn → 3, alloc → 4, gap → 8
        expected = {'100511': '6', '100512': '3', '100513': '3', '100514': '4', '100515': '8'}
        for rid, level in expected.items():
            r = rules[rid]
            assert r.get('level') == level
            assert r.find('if_sid').text == '100510'

    def test_gap_rule_keys_on_kind(self):
        _, rules = _rules('whisper_agent_rules.xml')
        gap = {f.get('name'): f.text for f in rules['100515'].findall('field')}
        assert gap['whisper_agent.kind'] == '^gap$'
        assert 'whisper_agent_gap' in rules['100515'].find('group').text

    def test_refused_requires_kind_and_decision(self):
        _, rules = _rules('whisper_agent_rules.xml')
        fields = {f.get('name'): f.text for f in rules['100511'].findall('field')}
        assert fields['whisper_agent.kind'] == '^dns$'
        assert fields['whisper_agent.decision'] == '^refused$'

    def test_allow_decision_distinct_from_refused(self):
        _, rules = _rules('whisper_agent_rules.xml')
        fields = {f.get('name'): f.text for f in rules['100512'].findall('field')}
        assert fields['whisper_agent.decision'] == '^allow$'

    def test_conn_and_alloc_key_on_kind(self):
        _, rules = _rules('whisper_agent_rules.xml')
        conn = {f.get('name'): f.text for f in rules['100513'].findall('field')}
        alloc = {f.get('name'): f.text for f in rules['100514'].findall('field')}
        assert conn['whisper_agent.kind'] == '^conn$'
        assert alloc['whisper_agent.kind'] == '^alloc$'

    def test_all_fields_unprefixed_and_anchored(self):
        _, rules = _rules('whisper_agent_rules.xml')
        for r in rules.values():
            for field in r.findall('field'):
                assert not field.get('name').startswith('data.')
                if field.get('type') == 'pcre2':
                    assert field.text.startswith('^') and field.text.endswith('$')

    def test_group_token(self):
        root, _ = _rules('whisper_agent_rules.xml')
        assert 'whisper_agent_activity' in root.get('name')
        # must NOT be the enrichment group (that would be a feedback loop)
        assert 'whisper_enrichment' not in root.get('name')


class TestLoopGuardSeparation:
    def test_disjoint_from_enrichment_rules(self):
        """The log-source group/ids never collide with the enrichment ruleset."""
        _, agent = _rules('whisper_agent_rules.xml')
        _, enrich = _rules('whisper_rules.xml')
        assert set(agent).isdisjoint(set(enrich))  # 100510+ vs 100500-100509
        enrich_root = ET.parse(WHISPER / 'whisper_rules.xml').getroot()
        assert 'whisper_agent_activity' not in enrich_root.get('name')

    def test_agent_group_only_in_loop_guard(self):
        """whisper_agent_activity may appear in install.sh ONLY in the loop-guard forbid list
        (EMITTED_GROUPS), never in an <integration> trigger filter — an enrichment trigger on it
        would cross-fire the keyed log-source alerts back into enrichment."""
        install = (WHISPER / 'install.sh').read_text()
        for line in install.splitlines():
            if 'whisper_agent_activity' in line:
                assert 'EMITTED_GROUPS' in line, f'agent group appears outside the loop guard: {line}'
        # and it IS in the guard, so `--group whisper_agent_*` is rejected at install time
        assert 'whisper_agent_activity' in install
