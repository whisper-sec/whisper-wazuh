#!/usr/bin/env python3
"""whisper-logs — Whisper agent-activity log source for Wazuh (keyed tier).

The KEYED half of the two-tier design (RULE 14). The graph-enrichment connector
(custom-whisper.py) is the graph/keyless half — reading intel INTO Wazuh; THIS poller
reads the caller's OWN tenant activity logs OUT of the Whisper control plane and feeds
them to the manager as decoded `data.whisper_agent.*` alerts. It requires the tenant API
key (the same key + endpoint enrichment already uses) and NEVER modifies enrichment.

Runs on the manager under the bundled Python (3.10) — stdlib only. Scheduled by a
`<wodle name="command">` (default 60s); each run pulls new rows since the persisted cursor,
projects them per kind, and writes NDJSON to a spool the logcollector tails (default sink)
or injects them on the analysisd socket (WHISPER_LOGS_SINK=socket).

ONE Whisper client, ONE dedup DB: this module IMPORTS the enrichment module and reuses its
execute_query / auth / config / dedup / socket helpers unchanged — nothing here is a second
copy of that machinery.

Live-verified control-plane contract (2026-07-14):
  * outer proxy envelope: columns=[op,ok,status,result,error,retry_after], rows=[{...}].
    execute_query() returns the OUTER rows list; we unwrap rows[0] here.
  * inner result is COLUMNAR: result.columns + result.rows (array-of-arrays);
    record = dict(zip(columns, row)); unused columns are null per kind.
  * `ts` is epoch-MILLISECONDS (int). Rows carry only a bare `agent` id (no /128, no fqdn) —
    address/fqdn resolve via op:identity (also columnar: address,fqdn,ptr,state).
  * `from` is the ONLY working watermark (inclusive lower bound); results are newest-first;
    `since`/`to` do NOT filter. See advance_cursor() for the single-shot poll rationale.

This poller writes NOTHING to stdout (the command wodle would otherwise ingest it) — all
diagnostics go to `{WAZUH}/logs/whisper-logs.log`.
"""

import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone

# --- reuse the enrichment module as the shared Whisper client -----------------------------
# custom-whisper.py is hyphenated (Wazuh's `<name>.py` convention) so it is not importable by
# name; load it by path. If a test harness already loaded it (sys.modules['whisper_integration'],
# as tests/conftest.py does) reuse THAT instance so a mocked execute_query is honoured — this is
# what makes it literally the same client, not a parallel one.
_DIR = os.path.dirname(os.path.realpath(__file__))
_ENRICHMENT_PATH = os.path.join(_DIR, 'custom-whisper.py')
_ENRICHMENT_MODULE = 'whisper_integration'


def _load_enrichment():
    if _ENRICHMENT_MODULE in sys.modules:
        return sys.modules[_ENRICHMENT_MODULE]
    spec = importlib.util.spec_from_file_location(_ENRICHMENT_MODULE, _ENRICHMENT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[_ENRICHMENT_MODULE] = module
    spec.loader.exec_module(module)
    return module


w = _load_enrichment()

# Wazuh home = one level up from integrations/ (mirrors the enrichment module's `pwd`).
pwd = os.path.dirname(_DIR)
LOG_FILE = f'{pwd}/logs/whisper-logs.log'
SPOOL_DEFAULT = f'{pwd}/logs/whisper-agent-activity.json'
CURSOR_DEFAULT = f'{pwd}/var/whisper/logs-cursor'

INTEGRATION_NAME = 'whisper-logs'

# --- config defaults ----------------------------------------------------------------------
DEFAULT_LIMIT = 1000
MAX_LIMIT = 10000
ALL_KINDS = ('dns', 'conn', 'alloc')
# How long a dedup row is retained past the cursor (ms). The `from` watermark is inclusive and
# several events can share a millisecond, so rows on the boundary are re-fetched next poll;
# dedup suppresses the re-emit. 10 min is comfortably longer than the poll interval.
LOGS_SEEN_RETAIN_MS = 10 * 60 * 1000

# Bare agent id (a<hex>) or the op:list-prefixed form (agent-a<hex>). Validated before it is
# ever inlined into Cypher (from/limit are ints, injection-safe by construction).
_AGENT_RE = re.compile(r'^(agent-)?a?[0-9a-f]+$')


# --- logging (file only; NEVER stdout — the command wodle would ingest it) -----------------
def log(msg: str) -> None:
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(f'{datetime.now(timezone.utc).isoformat(timespec="seconds")} whisper-logs: {msg}\n')
    except OSError:
        pass  # never let logging kill the run


# --- configuration resolution (env → keyfile; key REDACTED, runtime-only) ------------------
def resolve_config(argv: 'list[str]', environ: dict) -> dict:
    """Resolve runtime config. The API key + URL reuse the enrichment resolvers (same env var,
    same /var/ossec/etc/whisper.key file, same default endpoint) — one auth path, one keyfile."""
    api_key = w.resolve_api_key(argv[1] if len(argv) > 1 else '', environ)
    api_url = w.resolve_api_url({}, environ)

    sink = (environ.get('WHISPER_LOGS_SINK') or 'logcollector').strip().lower()
    if sink not in ('logcollector', 'socket'):
        sink = 'logcollector'

    limit = w._argv_int([None, environ.get('WHISPER_LOGS_LIMIT', '')], 1, DEFAULT_LIMIT)
    limit = max(1, min(limit, MAX_LIMIT))

    agent = (environ.get('WHISPER_LOGS_AGENT') or '').strip()
    if agent and not _AGENT_RE.match(agent):
        log(f'ignoring WHISPER_LOGS_AGENT (invalid format): {agent!r}')
        agent = ''

    kinds_raw = (environ.get('WHISPER_LOGS_KINDS') or 'all').strip().lower()
    if kinds_raw in ('', 'all', '*'):
        kinds = set(ALL_KINDS)
    else:
        kinds = {k.strip() for k in kinds_raw.split(',') if k.strip() in ALL_KINDS}
        if not kinds:
            kinds = set(ALL_KINDS)

    return {
        'api_key': api_key,
        'api_url': api_url,
        'timeout': w.DEFAULT_TIMEOUT,
        'retries': w.DEFAULT_RETRIES,
        'sink': sink,
        'spool': (environ.get('WHISPER_LOGS_SPOOL') or SPOOL_DEFAULT).strip(),
        'cursor_path': (environ.get('WHISPER_LOGS_CURSOR') or CURSOR_DEFAULT).strip(),
        'limit': limit,
        'agent': agent,
        'kinds': kinds,
    }


# --- cursor persistence (the native-equivalent checkpoint, like the azure/aws wodles) ------
def load_cursor(path: str) -> 'int | None':
    """The persisted `from` watermark (epoch-ms), or None on first run / unreadable state."""
    try:
        with open(path) as f:
            data = json.load(f)
        value = data.get('from')
        return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None
    except (OSError, ValueError, AttributeError):
        return None


def save_cursor(path: str, value: int) -> None:
    """Persist the watermark atomically (write-temp-then-rename) so a crash never leaves a
    half-written cursor that would re-scan or skip the whole history."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f'{path}.tmp'
        with open(tmp, 'w') as f:
            json.dump({'from': int(value)}, f)
        os.replace(tmp, path)
    except OSError as exc:
        log(f'could not persist cursor to {path}: {exc}')


# --- control-plane calls (unwrap the outer proxy envelope; reuse the error taxonomy) -------
def _args_literal(args: dict) -> str:
    """Render an args map for `whisper.agents({op:..., args:<here>})`. from/limit are ints
    (injection-safe); `agent` is pre-validated by _AGENT_RE before it ever reaches here."""
    parts = []
    for key, value in args.items():
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            parts.append(f'{key}:{value}')
        elif isinstance(value, str):
            parts.append(f"{key}:'{value}'")
    return '{' + ', '.join(parts) + '}'


def _unwrap(outer: 'list[dict]', op: str) -> 'tuple[list[str], list[list]]':
    """Unwrap the outer `whisper.agents` proxy envelope → (result.columns, result.rows).

    Maps the inner op status onto the enrichment error taxonomy so callers handle logs errors
    exactly like enrichment errors — never a traceback:
      401/403                       → WhisperAuthError (terminal)
      429 / 5xx                     → WhisperTransportError (transient)
      other >=400 / ok:false / bad  → WhisperQueryError
    """
    if not outer or not isinstance(outer[0], dict):
        raise w.WhisperQueryError(f'empty/invalid proxy envelope for op:{op}')
    env = outer[0]
    status = env.get('status')
    err = env.get('error')
    failed = env.get('ok') is False or (isinstance(status, int) and status >= 400) or err
    if failed:
        detail = f'op:{op} status={status} error={err}'
        if status in (401, 403):
            raise w.WhisperAuthError(detail)
        if status == 429 or (isinstance(status, int) and status >= 500):
            raise w.WhisperTransportError(detail)
        raise w.WhisperQueryError(detail)
    result = env.get('result')
    if (
        not isinstance(result, dict)
        or not isinstance(result.get('columns'), list)
        or not isinstance(result.get('rows'), list)
    ):
        raise w.WhisperQueryError(f'malformed result for op:{op}')
    return result['columns'], result['rows']


def call_op(cfg: dict, op: str, args: dict) -> 'list[dict]':
    """Run one whisper.agents op and return its rows as dicts (dict(zip(columns,row)))."""
    cypher = f"CALL whisper.agents({{op:'{op}', args:{_args_literal(args)}}})"
    outer = w.execute_query(cfg['api_url'], cfg['api_key'], cypher, None, cfg['timeout'], cfg['retries'])
    columns, rows = _unwrap(outer, op)
    # strict=False: be liberal in what we accept — a short/long row degrades, never crashes.
    return [dict(zip(columns, row, strict=False)) for row in rows]


def fetch_logs(cfg: dict, cursor: 'int | None') -> 'list[dict]':
    """Fetch agent-activity rows ≥ cursor (inclusive), newest-first, capped at cfg['limit']."""
    args: dict = {'limit': cfg['limit']}
    if cursor is not None:
        args['from'] = cursor
    if cfg['agent']:
        args['agent'] = cfg['agent']
    return call_op(cfg, 'logs', args)


def resolve_identity(cfg: dict, agent_id: str, cache: dict) -> dict:
    """{address, fqdn} for an agent id via op:identity (cached per run). Best-effort: identity
    failures degrade to an id-only alert, they never abort the poll."""
    if agent_id in cache:
        return cache[agent_id]
    ident: dict = {}
    if _AGENT_RE.match(agent_id):
        try:
            rows = call_op(cfg, 'identity', {'agent': agent_id})
            if rows:
                rec = rows[0]
                addr = rec.get('address')
                fqdn = rec.get('fqdn')
                if isinstance(addr, str):
                    ident['address'] = addr
                if isinstance(fqdn, str):
                    ident['fqdn'] = fqdn.rstrip('.') or None
        except w.WhisperAuthError:
            raise  # terminal — the same key fails for everything, propagate
        except w.WhisperError as exc:
            log(f'identity lookup failed for {agent_id}: {exc}')
    cache[agent_id] = ident
    return ident


# --- projection: columnar record → data.whisper_agent.* ------------------------------------
def _iso(ms: 'int | float') -> 'str | None':
    """epoch-ms → ISO-8601 UTC (Z), millisecond precision — the Wazuh-friendly timestamp."""
    try:
        dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None
    return dt.isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def _split_hostport(peer: str) -> 'tuple[str | None, int | None]':
    """'host:port' → (host, port); '[::1]:443' → ('::1', 443); bare host → (host, None)."""
    if not isinstance(peer, str) or not peer:
        return (None, None)
    if peer.startswith('[') and ']' in peer:
        host = peer[1 : peer.index(']')]
        rest = peer[peer.index(']') + 1 :]
        port = rest[1:] if rest.startswith(':') else ''
    elif peer.count(':') == 1:
        host, _, port = peer.partition(':')
    else:
        return (peer, None)  # bare IPv6 or host with no port
    return (host or None, int(port) if port.isdigit() else None)


def dedup_key(rec: dict) -> str:
    """Composite key for boundary/restart dedup: agent|ts|kind|(qname|peer)|(decision|reason).
    `from` is inclusive so the boundary ms is re-fetched; this makes each event emit once."""
    agent = str(rec.get('agent') or '')
    ts = str(rec.get('ts') or '')
    kind = str(rec.get('kind') or '')
    who = str(rec.get('qname') or rec.get('peer') or '')
    why = str(rec.get('decision') or rec.get('reason') or '')
    return f'{agent}|{ts}|{kind}|{who}|{why}'


def project(rec: dict, identity: dict) -> 'dict | None':
    """One columnar record → the `whisper_agent` alert body (nulls stripped before send).
    Returns None for a record with no usable ts/kind."""
    ts = rec.get('ts')
    kind = rec.get('kind')
    if not isinstance(ts, (int, float)) or kind not in ALL_KINDS:
        return None

    body: dict = {
        'ts_ms': int(ts),
        'ts': _iso(ts),
        'kind': kind,
        'agent_id': rec.get('agent'),
        'address': identity.get('address'),
        'fqdn': identity.get('fqdn'),
    }
    if kind == 'dns':
        body['decision'] = rec.get('decision')
        body['dns'] = {
            'qname': rec.get('qname'),
            'qtype': rec.get('qtype'),
            'rcode': rec.get('rcode'),
            'source': rec.get('source'),
            'answer': rec.get('answer'),
            'latency_ms': rec.get('latency_ms'),
        }
    elif kind == 'conn':
        host, port = _split_hostport(rec.get('peer'))
        body['conn'] = {
            'dst': rec.get('peer'),
            'dst_host': host,
            'dst_port': port,
            'state': rec.get('reason'),
            'bytes_up': rec.get('bytes_up'),
            'bytes_down': rec.get('bytes_down'),
            'packets_up': rec.get('packets_up'),
            'packets_down': rec.get('packets_down'),
            'duration_ms': rec.get('duration_ms'),
            'client_src': rec.get('client_src'),
        }
    # kind == 'alloc' carries only ts/kind/agent + the resolved address/fqdn (identity event).
    return w.strip_nulls({'integration': INTEGRATION_NAME, 'whisper_agent': body})


# --- logs_seen dedup (a NEW table in the EXISTING dedup.db; reuses _dedup_connect) ---------
def _logs_seen_conn():
    """Open the shared dedup DB (reusing the enrichment connect/busy-timeout) and ensure the
    logs_seen table exists. None (fail-open) when the cache is unavailable."""
    conn = w._dedup_connect()
    if conn is None:
        return None
    try:
        conn.execute('CREATE TABLE IF NOT EXISTS logs_seen (key TEXT PRIMARY KEY, ts INTEGER NOT NULL)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_logs_seen_ts ON logs_seen (ts)')
        return conn
    except Exception as exc:  # noqa: BLE001 — fail-open: a cache error must never lose logs
        log(f'logs_seen unavailable: {exc}')
        conn.close()
        return None


def filter_new(records: 'list[dict]') -> 'tuple[list[dict], object]':
    """Return (records not seen before, open-connection-or-None). Fails OPEN — on any cache
    error every record is treated as new (a duplicate alert beats a lost one)."""
    conn = _logs_seen_conn()
    if conn is None:
        return (list(records), None)
    fresh = []
    try:
        for rec in records:
            key = dedup_key(rec)
            row = conn.execute('SELECT 1 FROM logs_seen WHERE key = ?', (key,)).fetchone()
            if row is None:
                fresh.append(rec)
    except Exception as exc:  # noqa: BLE001
        log(f'logs_seen check failed (fail-open): {exc}')
        conn.close()
        return (list(records), None)
    return (fresh, conn)


def record_seen(conn, rec: dict) -> None:
    """Mark one record emitted (best-effort)."""
    if conn is None:
        return
    try:
        with conn:
            conn.execute(
                'INSERT OR REPLACE INTO logs_seen (key, ts) VALUES (?, ?)',
                (dedup_key(rec), int(rec.get('ts') or 0)),
            )
    except Exception as exc:  # noqa: BLE001
        log(f'logs_seen record failed: {exc}')


def prune_seen(conn, max_ts: int) -> None:
    """Drop dedup rows older than the retention window below max_ts — keeps the table tiny."""
    if conn is None:
        return
    try:
        with conn:
            conn.execute('DELETE FROM logs_seen WHERE ts < ?', (max_ts - LOGS_SEEN_RETAIN_MS,))
    except Exception as exc:  # noqa: BLE001
        log(f'logs_seen prune failed: {exc}')


# --- sinks --------------------------------------------------------------------------------
def write_spool(spool_path: str, payloads: 'list[dict]') -> int:
    """Append one JSON object per line to the NDJSON spool the logcollector tails.
    Returns bytes written. Raises OSError to the caller on a spool failure."""
    os.makedirs(os.path.dirname(spool_path), exist_ok=True)
    written = 0
    with open(spool_path, 'a') as f:
        for payload in payloads:
            line = json.dumps(payload, separators=(',', ':')) + '\n'
            f.write(line)
            written += len(line.encode('utf-8'))
    return written


# --- incremental cursor advance -----------------------------------------------------------
def advance_cursor(records: 'list[dict]') -> 'int | None':
    """Next `from` watermark = max(ts)+1 over the batch, or None when the batch is empty.

    Single-shot rationale: the API returns rows NEWEST-FIRST and `from` is only a lower bound
    (`to`/`since` do not filter — verified live), so classic forward multi-page draining is
    impossible; one request per poll returns every row >= cursor up to the limit. If a poll
    returns exactly `limit` rows, older rows in the same window may have been truncated — the
    caller logs a loud gap warning (raise WHISPER_LOGS_LIMIT / shorten the interval)."""
    ts_values = [int(r['ts']) for r in records if isinstance(r.get('ts'), (int, float))]
    return max(ts_values) + 1 if ts_values else None


# --- entry point --------------------------------------------------------------------------
def poll(cfg: dict) -> int:
    """One poll cycle. Returns the number of events emitted."""
    cursor = load_cursor(cfg['cursor_path'])
    records = fetch_logs(cfg, cursor)
    if not records:
        return 0
    if len(records) >= cfg['limit']:
        log(
            f'poll hit the limit of {cfg["limit"]} rows — older rows in this window may be '
            f'missed; raise WHISPER_LOGS_LIMIT (cap {MAX_LIMIT}) or shorten the poll interval'
        )

    # Advance the cursor over the FULL batch (even rows we filter/dedup) so the watermark always
    # moves past everything the API returned this poll.
    next_cursor = advance_cursor(records)

    records = [r for r in records if r.get('kind') in cfg['kinds']]
    fresh, conn = filter_new(records)

    identity_cache: dict = {}
    emitted = 0
    try:
        payloads = []
        emit_recs = []
        for rec in fresh:
            agent_id = rec.get('agent')
            identity = resolve_identity(cfg, agent_id, identity_cache) if agent_id else {}
            payload = project(rec, identity)
            if payload is None:
                continue
            payloads.append(payload)
            emit_recs.append(rec)

        if payloads:
            if cfg['sink'] == 'socket':
                for payload in payloads:
                    w.send_event(payload, None)  # Form A: 1:custom-whisper:<json> (location cosmetic)
            else:
                write_spool(cfg['spool'], payloads)
            for rec in emit_recs:
                record_seen(conn, rec)
            emitted = len(payloads)

        if next_cursor is not None:
            prune_seen(conn, next_cursor - 1)
    finally:
        if conn is not None:
            conn.close()

    if next_cursor is not None:
        save_cursor(cfg['cursor_path'], next_cursor)
    return emitted


def main(argv: 'list[str]') -> int:
    cfg = resolve_config(argv, os.environ)
    if not cfg['api_key']:
        log(
            'no API key resolved (WHISPER_API_KEY / whisper.key) — the log source is the KEYED '
            'tier and needs the tenant key; nothing polled'
        )
        return 2
    try:
        emitted = poll(cfg)
    except w.WhisperAuthError as exc:
        log(f'auth error (terminal): {exc}')
        return 8
    except w.WhisperError as exc:
        log(f'error class={exc.log_class} detail={exc}')
        return 1
    except OSError as exc:
        log(f'spool/io error: {exc}')
        return 1
    log(f'poll complete: emitted={emitted} sink={cfg["sink"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
