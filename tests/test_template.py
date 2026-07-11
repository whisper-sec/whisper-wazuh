"""#17 — indexer template (type coercion for the stringified data.whisper.* fields)."""

import json
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parent.parent / 'integrations' / 'whisper' / 'whisper-template.json'


def _load():
    return json.loads(TEMPLATE.read_text())


class TestTemplateFile:
    def test_valid_json_no_comment_key(self):
        t = _load()
        # the legacy _template API rejects unknown top-level keys (verified live: 400 on _comment)
        assert set(t) <= {'order', 'index_patterns', 'settings', 'mappings', 'aliases', 'version'}

    def test_legacy_merge_order_above_stock(self):
        """Stock _template/wazuh is legacy at order 0 (verified live); ours must sit above it
        so mappings merge. It must stay a LEGACY template — a composable one would silently
        disable the stock template for matching indices."""
        t = _load()
        assert t['order'] >= 1
        assert 'wazuh-alerts-4.x-*' in t['index_patterns']

    def test_typed_fields_match_the_envelope(self):
        """The exact numeric/boolean/date set from the live stringification finding (#17)."""
        w = _load()['mappings']['properties']['data']['properties']['whisper']['properties']
        assert w['risk_score']['type'] == 'float'
        for f in ('known', 'available', 'truncated'):
            assert w[f]['type'] == 'boolean'
        assert w['asn']['properties']['number']['type'] == 'long'
        tf = w['threat_feed']['properties']
        assert tf['sources_count']['type'] == 'long'
        assert tf['first_seen']['type'] == 'date' and tf['last_seen']['type'] == 'date'
        links = w['links']['properties']
        assert links['inbound_total']['type'] == 'long' and links['outbound_total']['type'] == 'long'
        assert links['suspicious_count']['type'] == 'long'  # #30
        assert w['variants']['properties']['confidence']['type'] == 'float'
        rep = w['asn']['properties']['reputation']['properties']
        assert all(rep[k]['type'] == 'float' for k in rep)
        # #29 registered-prefix threat fields
        pt = w['prefix_threat']['properties']
        assert pt['score']['type'] == 'float' and pt['threat_neighbor_count']['type'] == 'long'
        assert pt['is_threat']['type'] == 'boolean'

    def test_numerics_and_dates_never_reject_an_alert(self):
        """ignore_malformed on every numeric/date field — a bad value must drop the FIELD,
        never the whole alert (mapping §2.4)."""

        def walk(props):
            for name, spec in props.items():
                if 'properties' in spec:
                    walk(spec['properties'])
                elif spec.get('type') in ('float', 'long', 'date'):
                    assert spec.get('ignore_malformed') is True, f'{name} lacks ignore_malformed'

        walk(_load()['mappings']['properties'])

    def test_no_string_fields_mapped(self):
        """Keyword fields need no entry (string_as_keyword covers them) — the template stays
        minimal so it can never fight the stock dynamic mapping."""

        def walk(props):
            for spec in props.values():
                if 'properties' in spec:
                    walk(spec['properties'])
                else:
                    assert spec.get('type') in ('float', 'long', 'date', 'boolean')

        walk(_load()['mappings']['properties'])


class TestStripNulls:
    def test_nested_none_removed(self, wi):
        payload = {
            'integration': 'custom-whisper',
            'whisper': {
                'ioc': 'x',
                'advisory': None,
                'asn': {'number': 60729, 'name': None},
                'whois': {'registrar': 'R', 'previous_registrar': None},
                'coverage': {'granularity': 'ipv4', 'shared_host': None},
            },
        }
        out = wi.strip_nulls(payload)
        assert out['whisper'] == {
            'ioc': 'x',
            'asn': {'number': 60729},
            'whois': {'registrar': 'R'},
            'coverage': {'granularity': 'ipv4'},
        }

    def test_falsy_non_none_values_survive(self, wi):
        """False / 0 / '' / [] are real values — only None is the literal-"null" hazard."""
        out = wi.strip_nulls({'known': False, 'risk_score': 0.0, 'tags': [], 'note': ''})
        assert out == {'known': False, 'risk_score': 0.0, 'tags': [], 'note': ''}

    def test_lists_of_dicts_stripped(self, wi):
        out = wi.strip_nulls({'variants': [{'variant': 'a', 'confidence': None}, None]})
        assert out == {'variants': [{'variant': 'a'}]}

    def test_enrich_output_contains_no_nulls(self, wi, router):
        """End-to-end guard: nothing enrich() returns may contain a None anywhere."""
        router.add(
            'CALL explain',
            [{'available': True, 'found': True, 'sources': [], 'advisory': None, 'score': None}],
        )
        router.add('RETURN n.isThreat', [{'isThreat': False, 'isTor': None}])
        router.add(
            'BELONGS_TO', [{'prefix': None, 'asn': None, 'asn_name': None, 'country': None, 'city': None}]
        )
        payload = wi.enrich('8.8.4.4', 'ipv4', 'k', {'rule_id': '1'}, 'https://api', None, 10, 3)

        def assert_no_none(v, path='payload'):
            assert v is not None, f'None at {path}'  # covers list elements + scalars too
            if isinstance(v, dict):
                for k, vv in v.items():
                    assert_no_none(vv, f'{path}.{k}')
            elif isinstance(v, list):
                for i, vv in enumerate(v):
                    assert_no_none(vv, f'{path}[{i}]')

        assert_no_none(payload)
