"""Wazuh 5.0 option (b) spike (issue #67): enrich findings without the <integration> hook.

Wazuh 5.0.0-rc2 ships no integratord, so nothing runs a script per alert. This poller is the
trigger instead. It reads `wazuh-findings-v5-*` through the indexer API, runs the shipped
connector's own IOC guard and `enrich()` on a finding's public IP, and writes the result as its own
document in `whisper-enrichment-v5`, keyed to the finding. It never writes to the findings.

Dev-only and stdlib-only; nothing here ships in the bundle. The connector
(`integrations/whisper/custom-whisper.py`) is loaded as it is, with only its log and dedup paths
redirected to a writable directory, so the public-IP guard and the verdict logic stay identical.

Subcommands (run inside the `whisper.enricher` service, see dev/README.md):
  setup   one-shot, with the indexer admin credential: index template, index, least-privilege
          role, user and role mapping; writes the enricher user's generated password
  run     poll forever (or `--once`) and enrich new findings
  query   print the enrichment documents stored for one finding id

Credentials are read from files (Docker secrets), never from argv or the environment, and are
never printed.
"""

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
import secrets
import ssl
import string
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CONNECTOR_DIR = '/opt/whisper'
DEFAULT_STATE_DIR = '/tmp/whisper-enricher'
DEFAULT_INDEXER_URL = 'https://wazuh.indexer:9200'
DEFAULT_CA = '/certs/root-ca.pem'
DEFAULT_ENRICHER_CREDENTIALS = '/run/secrets/whisper-enricher-credentials'
DEFAULT_ADMIN_CREDENTIALS = '/run/secrets/wazuh-credentials'
DEFAULT_OUT_DIR = '/out'

FINDINGS_PATTERN = 'wazuh-findings-v5-*'
ENRICHMENT_INDEX = 'whisper-enrichment-v5'
ROLE_NAME = 'whisper_spike_enricher'
USER_NAME = 'whisper_spike_enricher'
PASSWORD_KEY = 'WHISPER_SPIKE_ENRICHER_PASSWORD'
ADMIN_PASSWORD_KEY = 'WAZUH_INDEXER_ADMIN_PASSWORD'
TEMPLATE_FILE = HERE / 'whisper-enrichment-template.json'

# The finding's fields that can carry an IOC, as ECS paths. Only `source.ip` was observed on
# 5.0.0-rc2 (an sshd event); the others are ECS names that the same stream is expected to use.
# `related.ip` is left out on purpose: it aggregates every address of the event.
FINDING_FIELD_PATHS: 'tuple[tuple[str, str], ...]' = (
    ('source.ip', 'ip'),
    ('destination.ip', 'ip'),
    ('client.ip', 'ip'),
    ('server.ip', 'ip'),
    ('dns.question.name', 'domain'),
    ('url.domain', 'domain'),
)

# One finding's role. `read` is the stock action group (indices:data/read/*). Findings are read
# only; the enrichment index also takes writes. A single-document write is routed through the bulk
# action, which is why that action is listed. No index creation: `setup` creates the index.
ROLE_BODY = {
    'cluster_permissions': ['cluster_composite_ops_ro', 'indices:data/write/bulk'],
    'index_permissions': [
        {'index_patterns': [FINDINGS_PATTERN, '.ds-wazuh-findings-v5-*'], 'allowed_actions': ['read']},
        {
            'index_patterns': [f'{ENRICHMENT_INDEX}*'],
            'allowed_actions': [
                'read',
                'indices:data/write/index',
                'indices:data/write/bulk*',
                'indices:admin/mapping/put',  # dynamic mapping of whisper.* fields the template does not name
            ],
        },
    ],
}

PAGE_SIZE = 200
MAX_WINDOW = 10000  # index.max_result_window default: from + size may not pass it
IOC_CACHE_TTL = 300  # seconds an IOC's verdict is reused across findings


def log(msg: str) -> None:
    print(f'{datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")} whisper-enricher: {msg}', flush=True)


# --- the connector, loaded as it is ----------------------------------------------------------
def load_connector(connector_dir: str, state_dir: str):
    """Load custom-whisper.py (hyphenated filename, so importlib) with its paths made writable.

    The connector computes LOG_FILE and DEDUP_DB from its own location at import time, which is
    a read-only mount here. Nothing is written at import; both globals are redirected before any
    call, so the connector never creates a file under its own directory.
    """
    directory = str(Path(connector_dir).resolve())
    if directory not in sys.path:
        sys.path.insert(0, directory)
    spec = importlib.util.spec_from_file_location(
        'whisper_connector_spike', str(Path(directory) / 'custom-whisper.py')
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules['whisper_connector_spike'] = module
    spec.loader.exec_module(module)
    state = Path(state_dir)
    state.mkdir(parents=True, exist_ok=True)
    module.LOG_FILE = str(state / 'integrations.log')
    module.DEDUP_DB = str(state / 'dedup.db')
    module.debug_enabled = True  # the normative `whisper: skip reason=...` lines, on stdout
    return module


# --- pure logic ------------------------------------------------------------------------------
def extract_finding_iocs(w, finding: dict) -> 'list[tuple[str, str, str]]':
    """[(ioc, type, field_path)] for one finding `_source`, through the connector's own guard.

    `_classify` is what rejects a private, loopback or TEST-NET address (`skip reason=non-global`),
    so the poller enriches exactly the addresses the hook-based connector would.
    """
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for path, hint in FINDING_FIELD_PATHS:
        value = w.get_nested(finding, path)
        if value is None or value == '' or value == []:
            continue
        values = value if isinstance(value, list) else [value]
        for raw in values[: w.MAX_LIST_VALUES]:
            if not isinstance(raw, str) or not raw.strip():
                continue
            kind, ioc, ioc_type = w._classify(raw, hint)
            if kind == 'non-global':
                w.log_skip('non-global', ioc=ioc)
            elif kind == 'ok' and (ioc, ioc_type) not in seen:
                seen.add((ioc, ioc_type))
                out.append((ioc, ioc_type, path))
    return out


def enrichment_doc_id(finding_id: str, ioc: str) -> str:
    """Deterministic `_id`: the same finding and IOC always map to one document, so `_create`
    answers 409 on a re-run or an overlapping poll instead of writing a duplicate."""
    return hashlib.sha256(f'{finding_id}|{ioc}'.encode()).hexdigest()


def build_enrichment_doc(
    hit: dict, ioc: str, ioc_type: str, field_path: str, whisper: dict, now: 'str | None' = None
) -> dict:
    """The stored document: a link to the finding, the IOC, and the connector's `whisper` payload."""
    source = hit.get('_source') or {}
    return {
        '@timestamp': now or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
        'finding': {
            'id': hit['_id'],
            'index': hit['_index'],
            'timestamp': source.get('@timestamp'),
            'rule': {'id': (source.get('wazuh') or {}).get('rule', {}).get('id')},
            'agent': {'id': (source.get('wazuh') or {}).get('agent', {}).get('id')},
        },
        'ioc': ioc,
        'ioc_type': ioc_type,
        'field_path': field_path,
        'whisper': whisper,
    }


def findings_query(lookback_minutes: int) -> dict:
    return {
        'query': {'range': {'@timestamp': {'gte': f'now-{int(lookback_minutes)}m'}}},
        'sort': [{'@timestamp': 'asc'}],
        '_source': True,
        'track_total_hits': False,
    }


# --- indexer API (stdlib HTTP) -----------------------------------------------------------------
def read_env_file(path: str, key: str) -> str:
    """The value of KEY in a KEY=VALUE file (the shape of the generated credentials files)."""
    with open(path) as f:
        for line in f:
            if line.startswith(f'{key}='):
                return line.split('=', 1)[1].rstrip('\n')
    raise KeyError(f'{key} not found in {path}')


class Indexer:
    """Minimal indexer client. Basic auth on every call; the password is never logged."""

    def __init__(self, url: str, user: str, password: str, ca: str, timeout: int = 30):
        self.url = url.rstrip('/')
        token = base64.b64encode(f'{user}:{password}'.encode()).decode()
        self._auth = f'Basic {token}'
        self._ctx = ssl.create_default_context(cafile=ca)
        self.timeout = timeout

    def request(self, method: str, path: str, body: 'dict | None' = None) -> 'tuple[int, dict]':
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(f'{self.url}{path}', data=data, method=method)
        req.add_header('Authorization', self._auth)
        if data is not None:
            req.add_header('Content-Type', 'application/json')
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw) if raw else {}
            except ValueError:
                return exc.code, {}


def error_reason(payload: dict) -> str:
    """A short, secret-free reason out of an indexer error body."""
    err = payload.get('error')
    if isinstance(err, dict):
        return str(err.get('reason') or err.get('type') or 'error')[:200]
    return str(err or payload.get('message') or 'error')[:200]


def create_enrichment(indexer: Indexer, doc_id: str, doc: dict) -> str:
    """`PUT _create/<id>`: 'created', or 'exists' on 409 (already enriched). Anything else raises."""
    status, payload = indexer.request('PUT', f'/{ENRICHMENT_INDEX}/_create/{doc_id}', doc)
    if status in (200, 201):
        return 'created'
    if status == 409:
        return 'exists'
    raise RuntimeError(f'create {doc_id[:12]} failed: HTTP {status} {error_reason(payload)}')


def existing_ids(indexer: Indexer, ids: 'list[str]') -> 'set[str]':
    """Which of `ids` already have a document (one `_mget`, no source)."""
    if not ids:
        return set()
    status, payload = indexer.request('POST', f'/{ENRICHMENT_INDEX}/_mget?_source=false', {'ids': ids})
    if status != 200:
        raise RuntimeError(f'mget failed: HTTP {status} {error_reason(payload)}')
    return {d['_id'] for d in payload.get('docs', []) if d.get('found')}


# --- the poll ----------------------------------------------------------------------------------
class Poller:
    def __init__(self, indexer: Indexer, w, cfg: dict):
        self.indexer = indexer
        self.w = w
        self.cfg = cfg  # api_url, timeout, retries, deadline, lookback
        self._seen: set[str] = set()  # finding ids already handled in this process
        self._cache: dict[str, tuple[float, dict]] = {}  # ioc -> (monotonic ts, whisper dict)

    def _whisper_for(self, ioc: str, ioc_type: str, agent_id: str, source_ref: dict) -> dict:
        """The connector's enrich() under a per-call wall-clock budget. Keyless tier (no key)."""
        w = self.w
        now = time.monotonic()
        cached = self._cache.get(ioc)
        if cached and now - cached[0] < IOC_CACHE_TTL:
            whisper = copy.deepcopy(cached[1])
            whisper['source_ref'] = source_ref
            whisper['dedup_key'] = w.make_dedup_key(ioc_type, ioc, agent_id)
            return whisper
        budget = self.cfg['deadline']
        key = w.make_dedup_key(ioc_type, ioc, agent_id)
        w.log_invoke(ioc, ioc_type, key)
        w._INVOCATION_DEADLINE = time.monotonic() + budget
        previous = w._arm_hard_ceiling(budget + 1.0)
        try:
            payload = w.enrich(
                ioc,
                ioc_type,
                key,
                source_ref,
                self.cfg['api_url'],
                None,
                self.cfg['timeout'],
                self.cfg['retries'],
            )
        finally:
            w._disarm_hard_ceiling(previous)
            w._INVOCATION_DEADLINE = None
        self._cache[ioc] = (time.monotonic(), copy.deepcopy(payload['whisper']))
        return payload['whisper']

    def _fetch_window(self) -> 'list[dict]':
        hits: list[dict] = []
        offset = 0
        query = findings_query(self.cfg['lookback'])
        while offset + PAGE_SIZE <= MAX_WINDOW:
            body = dict(query, size=PAGE_SIZE, **{'from': offset})
            status, payload = self.indexer.request('POST', f'/{FINDINGS_PATTERN}/_search', body)
            if status != 200:
                raise RuntimeError(f'findings search failed: HTTP {status} {error_reason(payload)}')
            page = payload.get('hits', {}).get('hits', [])
            hits.extend(page)
            if len(page) < PAGE_SIZE:
                return hits
            offset += PAGE_SIZE
        log(f'warning: more than {MAX_WINDOW} findings in the lookback window; the newest are not read')
        return hits

    def poll_once(self) -> 'dict[str, int]':
        """One pass over the lookback window. Returns counters: created, exists, skipped, failed."""
        stats = {'created': 0, 'exists': 0, 'skipped': 0, 'failed': 0}
        hits = self._fetch_window()
        todo: list[tuple[dict, str, str, str, str]] = []  # hit, ioc, type, path, doc id
        for hit in hits:
            if hit['_id'] in self._seen:
                continue
            iocs = extract_finding_iocs(self.w, hit.get('_source') or {})
            if not iocs:
                self._seen.add(hit['_id'])
                stats['skipped'] += 1
                continue
            for ioc, ioc_type, path in iocs:
                todo.append((hit, ioc, ioc_type, path, enrichment_doc_id(hit['_id'], ioc)))
        have = existing_ids(self.indexer, [t[4] for t in todo])
        failed: set[str] = set()  # findings with at least one IOC that failed in this pass
        for hit, ioc, ioc_type, path, doc_id in todo:
            if doc_id in have:
                stats['exists'] += 1
                continue
            agent_id = str(self.w.get_nested(hit.get('_source') or {}, 'wazuh.agent.id') or '000')
            source_ref = {'finding_id': hit['_id'], 'finding_index': hit['_index'], 'field_path': path}
            try:
                whisper = self._whisper_for(ioc, ioc_type, agent_id, source_ref)
                outcome = create_enrichment(
                    self.indexer, doc_id, build_enrichment_doc(hit, ioc, ioc_type, path, whisper)
                )
            except (self.w.WhisperError, RuntimeError, OSError) as exc:
                # Not recorded as seen: the next poll retries this finding's missing documents.
                failed.add(hit['_id'])
                log(f'enrich failed finding={hit["_id"]} ioc={ioc}: {type(exc).__name__}: {exc}')
                stats['failed'] += 1
                continue
            stats[outcome] += 1
            log(
                f'{outcome} finding={hit["_id"]} ioc={ioc} verdict={whisper.get("verdict")} doc={doc_id[:12]}'
            )
        # A finding is done only when none of its IOCs failed in this pass.
        self._seen.update(t[0]['_id'] for t in todo if t[0]['_id'] not in failed)
        self._seen &= {h['_id'] for h in hits}
        return stats


# --- subcommands -------------------------------------------------------------------------------
def make_password() -> str:
    """A generated password with every character class (the indexer's password rules)."""
    alphabet = string.ascii_letters + string.digits
    body = ''.join(secrets.choice(alphabet) for _ in range(28))
    return f'{secrets.choice(string.ascii_uppercase)}{secrets.choice(string.ascii_lowercase)}{secrets.choice(string.digits)}.{body}'


def cmd_setup(args) -> int:
    admin_password = read_env_file(args.admin_credentials, ADMIN_PASSWORD_KEY)
    admin = Indexer(args.indexer_url, 'admin', admin_password, args.ca)
    out = Path(args.out_dir) / 'enricher.env'
    try:
        password = read_env_file(str(out), PASSWORD_KEY)
        log('reusing the enricher password already in the credentials file')
    except (OSError, KeyError):
        password = make_password()

    steps = [
        (
            'index template',
            'PUT',
            f'/_index_template/{ENRICHMENT_INDEX}',
            json.loads(TEMPLATE_FILE.read_text()),
        ),
        ('role', 'PUT', f'/_plugins/_security/api/roles/{ROLE_NAME}', ROLE_BODY),
        (
            'user',
            'PUT',
            f'/_plugins/_security/api/internalusers/{USER_NAME}',
            {'password': password, 'backend_roles': [], 'attributes': {'purpose': 'whisper-wazuh-spike'}},
        ),
        ('role mapping', 'PUT', f'/_plugins/_security/api/rolesmapping/{ROLE_NAME}', {'users': [USER_NAME]}),
    ]
    for name, method, path, body in steps:
        status, payload = admin.request(method, path, body)
        if status not in (200, 201):
            log(f'setup failed at {name}: HTTP {status} {error_reason(payload)}')
            return 1
        log(f'{name}: ok')
    status, payload = admin.request('HEAD', f'/{ENRICHMENT_INDEX}')
    if status == 404:
        status, payload = admin.request('PUT', f'/{ENRICHMENT_INDEX}', {})
        if status not in (200, 201):
            log(f'setup failed at index: HTTP {status} {error_reason(payload)}')
            return 1
        log('index: created')
    else:
        log('index: present')
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(f'{PASSWORD_KEY}={password}\n')
    log(f'enricher credentials written to {out.name}')
    return 0


def _enricher_indexer(args) -> Indexer:
    password = read_env_file(args.credentials, PASSWORD_KEY)
    return Indexer(args.indexer_url, USER_NAME, password, args.ca)


def cmd_run(args) -> int:
    w = load_connector(args.connector_dir, args.state_dir)
    api_url = w.resolve_api_url({'api_url': args.api_url} if args.api_url else {}, os.environ)
    poller = Poller(
        _enricher_indexer(args),
        w,
        {
            'api_url': api_url,
            'timeout': w.DEFAULT_TIMEOUT,
            'retries': w.DEFAULT_RETRIES,
            'deadline': w.DEFAULT_DEADLINE,
            'lookback': args.lookback,
        },
    )
    log(f'polling {FINDINGS_PATTERN} every {args.interval}s, lookback {args.lookback}m, api {api_url}')
    while True:
        try:
            stats = poller.poll_once()
            if any(stats.values()):
                log(f'poll: {stats}')
        except (RuntimeError, OSError, ValueError) as exc:
            log(f'poll failed: {type(exc).__name__}: {exc}')
        if args.once:
            return 0
        time.sleep(args.interval)


def cmd_query(args) -> int:
    indexer = _enricher_indexer(args)
    body = {'query': {'term': {'finding.id': args.finding}}, 'sort': [{'@timestamp': 'asc'}], 'size': 50}
    status, payload = indexer.request('POST', f'/{ENRICHMENT_INDEX}/_search', body)
    if status != 200:
        log(f'query failed: HTTP {status} {error_reason(payload)}')
        return 1
    hits = [h['_source'] for h in payload.get('hits', {}).get('hits', [])]
    print(json.dumps(hits, indent=2))
    return 0 if hits else 2


def build_parser() -> argparse.ArgumentParser:
    env = os.environ.get
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('--indexer-url', default=env('WHISPER_SPIKE_INDEXER_URL', DEFAULT_INDEXER_URL))
    p.add_argument('--ca', default=env('WHISPER_SPIKE_CA', DEFAULT_CA))
    sub = p.add_subparsers(dest='cmd', required=True)

    s = sub.add_parser('setup', help='create the template, index, role, user and mapping (admin credential)')
    s.add_argument(
        '--admin-credentials', default=env('WHISPER_SPIKE_ADMIN_CREDENTIALS', DEFAULT_ADMIN_CREDENTIALS)
    )
    s.add_argument('--out-dir', default=env('WHISPER_SPIKE_OUT_DIR', DEFAULT_OUT_DIR))
    s.set_defaults(func=cmd_setup)

    r = sub.add_parser('run', help='poll findings and write their enrichment')
    r.add_argument('--credentials', default=env('WHISPER_SPIKE_CREDENTIALS', DEFAULT_ENRICHER_CREDENTIALS))
    r.add_argument('--connector-dir', default=env('WHISPER_SPIKE_CONNECTOR_DIR', DEFAULT_CONNECTOR_DIR))
    r.add_argument('--state-dir', default=env('WHISPER_SPIKE_STATE_DIR', DEFAULT_STATE_DIR))
    r.add_argument('--api-url', default=env('WHISPER_API_URL'))
    r.add_argument('--interval', type=int, default=30, help='seconds between polls (default 30)')
    r.add_argument('--lookback', type=int, default=60, help='minutes of findings read per poll (default 60)')
    r.add_argument('--once', action='store_true', help='poll once and exit')
    r.set_defaults(func=cmd_run)

    q = sub.add_parser('query', help='print the enrichment stored for a finding id')
    q.add_argument('--credentials', default=env('WHISPER_SPIKE_CREDENTIALS', DEFAULT_ENRICHER_CREDENTIALS))
    q.add_argument('finding', help='the finding document _id')
    q.set_defaults(func=cmd_query)
    return p


def main(argv: 'list[str] | None' = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
