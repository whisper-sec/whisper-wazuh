"""Unit tests for the Wazuh 5.0 option (b) spike poller (dev/wazuh-5-spike/finding_enricher.py).

The spike is dev-only and outside the shipped bundle; these tests cover its pure logic and the poll
loop against a stubbed indexer. No network and no docker. The connector it reuses comes from the
`whisper_module` / `wi` fixtures, so the guard under test is the connector's own.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SPIKE_DIR = _ROOT / 'dev' / 'wazuh-5-spike'
_INTEGRATIONS = _ROOT / 'integrations' / 'whisper'


def _load_enricher():
    spec = importlib.util.spec_from_file_location('finding_enricher', _SPIKE_DIR / 'finding_enricher.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules['finding_enricher'] = module
    spec.loader.exec_module(module)
    return module


fe = _load_enricher()

PUBLIC_IP = '185.220.101.1'


def _finding(fid='F1', index='.ds-wazuh-findings-v5-system-activity-000001', **source):
    src = {
        '@timestamp': '2026-11-12T21:30:52.247924889Z',
        'wazuh': {'agent': {'id': '001'}, 'rule': {'id': 'R1'}},
    }
    src.update(source)
    return {'_id': fid, '_index': index, '_source': src}


# --- extraction through the connector's guard --------------------------------------------------
def test_should_extract_public_ip_from_finding_when_field_path_matches(wi):
    found = fe.extract_finding_iocs(wi, {'source': {'ip': PUBLIC_IP}})
    assert found == [(PUBLIC_IP, 'ipv4', 'source.ip')]


def test_should_skip_private_and_testnet_ips_with_connector_guard(wi):
    finding = {
        'source': {'ip': '203.0.113.45'},  # TEST-NET-3
        'destination': {'ip': '10.1.2.3'},
        'client': {'ip': '127.0.0.1'},
        'server': {'ip': '192.168.0.9'},
    }
    assert fe.extract_finding_iocs(wi, finding) == []
    log = Path(wi.LOG_FILE).read_text()
    assert log.count('whisper: skip reason=non-global') == 4  # the connector's own log vocabulary


def test_should_ignore_related_ip_and_non_string_values(wi):
    finding = {'related': {'ip': [PUBLIC_IP]}, 'source': {'ip': 12345}}
    assert fe.extract_finding_iocs(wi, finding) == []


def test_should_extract_list_values_and_deduplicate(wi):
    finding = {'source': {'ip': [PUBLIC_IP, PUBLIC_IP]}, 'destination': {'ip': '8.8.8.8'}}
    found = fe.extract_finding_iocs(wi, finding)
    assert [f[0] for f in found] == [PUBLIC_IP, '8.8.8.8']


# --- the stored document -----------------------------------------------------------------------
def test_should_build_same_doc_id_for_same_finding_and_ioc():
    assert fe.enrichment_doc_id('F1', PUBLIC_IP) == fe.enrichment_doc_id('F1', PUBLIC_IP)
    assert fe.enrichment_doc_id('F1', PUBLIC_IP) != fe.enrichment_doc_id('F2', PUBLIC_IP)
    assert fe.enrichment_doc_id('F1', PUBLIC_IP) != fe.enrichment_doc_id('F1', '8.8.8.8')
    assert len(fe.enrichment_doc_id('F1', PUBLIC_IP)) == 64


def test_should_link_enrichment_to_finding_id_and_index():
    hit = _finding()
    doc = fe.build_enrichment_doc(
        hit, PUBLIC_IP, 'ipv4', 'source.ip', {'verdict': 'suspicious'}, now='2026-11-12T22:00:00.000Z'
    )
    assert doc['finding'] == {
        'id': 'F1',
        'index': '.ds-wazuh-findings-v5-system-activity-000001',
        'timestamp': '2026-11-12T21:30:52.247924889Z',
        'rule': {'id': 'R1'},
        'agent': {'id': '001'},
    }
    assert doc['ioc'] == PUBLIC_IP
    assert doc['whisper'] == {'verdict': 'suspicious'}


def test_should_read_a_lookback_window_sorted_by_timestamp():
    q = fe.findings_query(90)
    assert q['query'] == {'range': {'@timestamp': {'gte': 'now-90m'}}}
    assert q['sort'] == [{'@timestamp': 'asc'}]


# --- the poll loop against a stubbed indexer ---------------------------------------------------
class FakeIndexer:
    def __init__(self, hits, existing=()):
        self.hits = hits
        self.existing = set(existing)
        self.created = []
        self.calls = []

    def request(self, method, path, body=None):
        self.calls.append((method, path))
        if path.endswith('/_search'):
            start = body['from']
            return 200, {'hits': {'hits': self.hits[start : start + body['size']]}}
        if '/_mget' in path:
            return 200, {'docs': [{'_id': i, 'found': i in self.existing} for i in body['ids']]}
        if '/_create/' in path:
            doc_id = path.rsplit('/', 1)[1]
            if doc_id in self.existing:
                return 409, {'error': {'type': 'version_conflict_engine_exception'}}
            self.existing.add(doc_id)
            self.created.append((doc_id, body))
            return 201, {'result': 'created'}
        raise AssertionError(f'unexpected call {method} {path}')


@pytest.fixture()
def whisper_calls(wi, monkeypatch):
    calls = []

    def fake_enrich(
        ioc, ioc_type, dedup_key, source_ref, api_url, api_key, timeout, retries, extra=frozenset()
    ):
        calls.append(
            {'ioc': ioc, 'api_key': api_key, 'source_ref': source_ref, 'deadline': wi._INVOCATION_DEADLINE}
        )
        return {
            'integration': 'custom-whisper',
            'whisper': {'ioc': ioc, 'verdict': 'suspicious', 'source_ref': source_ref},
        }

    monkeypatch.setattr(wi, 'enrich', fake_enrich)
    return calls


def _poller(indexer, wi):
    cfg = {'api_url': 'https://graph.example.test', 'timeout': 5, 'retries': 1, 'deadline': 7, 'lookback': 60}
    return fe.Poller(indexer, wi, cfg)


def test_should_enrich_public_ip_finding_keyless_and_store_linked_doc(wi, whisper_calls):
    ix = FakeIndexer([_finding(source={'ip': PUBLIC_IP})])
    stats = _poller(ix, wi).poll_once()
    assert stats == {'created': 1, 'exists': 0, 'skipped': 0, 'failed': 0}
    assert whisper_calls[0]['api_key'] is None  # keyless tier
    assert whisper_calls[0]['deadline'] is not None  # a per-call budget was in force
    assert wi._INVOCATION_DEADLINE is None  # and never leaks out of the call
    doc_id, doc = ix.created[0]
    assert doc_id == fe.enrichment_doc_id('F1', PUBLIC_IP)
    assert doc['finding']['id'] == 'F1'
    assert doc['whisper']['source_ref']['finding_id'] == 'F1'


def test_should_treat_409_on_create_as_already_enriched(wi, whisper_calls):
    ix = FakeIndexer([_finding(source={'ip': PUBLIC_IP})])
    assert fe.create_enrichment(ix, 'abc', {'x': 1}) == 'created'
    assert fe.create_enrichment(ix, 'abc', {'x': 1}) == 'exists'


def test_should_not_call_whisper_or_duplicate_when_enrichment_exists(wi, whisper_calls):
    doc_id = fe.enrichment_doc_id('F1', PUBLIC_IP)
    ix = FakeIndexer([_finding(source={'ip': PUBLIC_IP})], existing=[doc_id])
    stats = _poller(ix, wi).poll_once()
    assert stats['exists'] == 1 and stats['created'] == 0
    assert whisper_calls == []
    assert ix.created == []


def test_should_not_enrich_the_same_finding_twice_across_polls(wi, whisper_calls):
    ix = FakeIndexer([_finding(source={'ip': PUBLIC_IP})])
    poller = _poller(ix, wi)
    poller.poll_once()
    second = poller.poll_once()
    assert second == {'created': 0, 'exists': 0, 'skipped': 0, 'failed': 0}
    assert len(ix.created) == 1 and len(whisper_calls) == 1


def test_should_reuse_one_whisper_verdict_for_two_findings_with_same_ioc(wi, whisper_calls):
    ix = FakeIndexer([_finding('F1', source={'ip': PUBLIC_IP}), _finding('F2', source={'ip': PUBLIC_IP})])
    stats = _poller(ix, wi).poll_once()
    assert stats['created'] == 2
    assert len(whisper_calls) == 1
    assert {d['finding']['id'] for _, d in ix.created} == {'F1', 'F2'}
    assert {d['whisper']['source_ref']['finding_id'] for _, d in ix.created} == {'F1', 'F2'}


def test_should_skip_findings_without_a_global_ip(wi, whisper_calls):
    ix = FakeIndexer([_finding(source={'ip': '10.0.0.5'}), _finding('F2')])
    stats = _poller(ix, wi).poll_once()
    assert stats['skipped'] == 2 and stats['created'] == 0
    assert whisper_calls == []


def test_should_retry_a_failed_enrichment_on_the_next_poll(wi, monkeypatch):
    attempts = []

    def flaky(ioc, ioc_type, key, source_ref, api_url, api_key, timeout, retries, extra=frozenset()):
        attempts.append(ioc)
        if len(attempts) == 1:
            raise wi.WhisperTransportError('down')
        return {'whisper': {'ioc': ioc, 'verdict': 'unknown'}}

    monkeypatch.setattr(wi, 'enrich', flaky)
    ix = FakeIndexer([_finding(source={'ip': PUBLIC_IP})])
    poller = _poller(ix, wi)
    assert poller.poll_once()['failed'] == 1
    assert ix.created == []
    assert poller.poll_once()['created'] == 1


def test_should_retry_only_the_failed_ioc_of_a_multi_ioc_finding(wi, monkeypatch):
    other_ip = '185.220.101.2'
    attempts = []

    def flaky(ioc, ioc_type, key, source_ref, api_url, api_key, timeout, retries, extra=frozenset()):
        attempts.append(ioc)
        if len(attempts) == 1:
            raise wi.WhisperTransportError('down')
        return {'whisper': {'ioc': ioc, 'verdict': 'unknown', 'dedup_key': key}}

    monkeypatch.setattr(wi, 'enrich', flaky)
    ix = FakeIndexer([_finding(source={'ip': PUBLIC_IP}, destination={'ip': other_ip})])
    poller = _poller(ix, wi)
    first = poller.poll_once()
    assert first['failed'] == 1 and first['created'] == 1
    second = poller.poll_once()
    assert second['created'] == 1 and second['failed'] == 0
    assert {d['ioc'] for _, d in ix.created} == {PUBLIC_IP, other_ip}


def test_should_page_through_the_window_until_a_short_page(wi, whisper_calls):
    hits = [_finding(f'F{i}', source={'ip': '10.0.0.1'}) for i in range(fe.PAGE_SIZE + 5)]
    ix = FakeIndexer(hits)
    stats = _poller(ix, wi).poll_once()
    assert stats['skipped'] == fe.PAGE_SIZE + 5
    assert sum(1 for m, p in ix.calls if p.endswith('/_search')) == 2


def test_should_fail_the_poll_without_leaking_a_secret_when_search_is_denied(wi):
    class Denied:
        def request(self, method, path, body=None):
            return 403, {'error': {'reason': 'no permissions for [indices:data/read/search]'}}

    with pytest.raises(RuntimeError, match='HTTP 403'):
        _poller(Denied(), wi).poll_once()


# --- role, template, loader --------------------------------------------------------------------
def test_should_not_grant_the_enricher_write_access_to_findings():
    for perm in fe.ROLE_BODY['index_permissions']:
        if any('findings' in p for p in perm['index_patterns']):
            assert perm['allowed_actions'] == ['read']
        else:
            assert all('findings' not in p for p in perm['index_patterns'])
    assert not any(
        a.startswith('indices:admin/create')
        for p in fe.ROLE_BODY['index_permissions']
        for a in p['allowed_actions']
    )


def test_should_parse_enrichment_template_and_match_index_name():
    tpl = json.loads(fe.TEMPLATE_FILE.read_text())
    assert tpl['index_patterns'] == [f'{fe.ENRICHMENT_INDEX}*']
    props = tpl['template']['mappings']['properties']
    assert props['finding']['properties']['id'] == {'type': 'keyword'}
    assert props['whisper']['properties']['verdict'] == {'type': 'keyword'}
    assert props['@timestamp'] == {'type': 'date'}


def test_should_keep_whisper_numeric_mapping_in_sync_with_the_shipped_template():
    shipped = json.loads((_INTEGRATIONS / 'whisper-template.json').read_text())
    shipped_whisper = shipped['mappings']['properties']['data']['properties']['whisper']['properties']
    spike_whisper = json.loads(fe.TEMPLATE_FILE.read_text())['template']['mappings']['properties']['whisper'][
        'properties'
    ]
    for name, mapping in shipped_whisper.items():
        assert spike_whisper[name] == mapping, name


def test_should_load_connector_without_writing_under_integrations(tmp_path):
    before = sorted(
        p.relative_to(_INTEGRATIONS) for p in _INTEGRATIONS.rglob('*') if '__pycache__' not in p.parts
    )
    code = (
        'import importlib.util, sys;'
        f'spec = importlib.util.spec_from_file_location("fe", {str(_SPIKE_DIR / "finding_enricher.py")!r});'
        'm = importlib.util.module_from_spec(spec); spec.loader.exec_module(m);'
        f'w = m.load_connector({str(_INTEGRATIONS)!r}, {str(tmp_path / "state")!r});'
        'print(w.LOG_FILE); print(w.DEDUP_DB)'
    )
    run = subprocess.run(
        [sys.executable, '-B', '-c', code],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert run.returncode == 0, run.stderr
    log_file, dedup_db = run.stdout.split()
    assert log_file.startswith(str(tmp_path)) and dedup_db.startswith(str(tmp_path))
    after = sorted(
        p.relative_to(_INTEGRATIONS) for p in _INTEGRATIONS.rglob('*') if '__pycache__' not in p.parts
    )
    assert after == before
