#!/usr/bin/env python3
"""custom-whisper — Whisper enrichment integration for Wazuh (Pattern A).

Runs on the manager under wazuh-integratord. Extracts network IOCs (IPv4/IPv6/domain)
from the triggering alert, enriches them from the Whisper infrastructure graph, and
writes the result back as a new alert via the analysisd queue socket.

Contracts implemented here (do not drift — the acceptance tests grep for them):
  - argv:            docs/whisper-to-wazuh-mapping.md §2.3 (positional, never argc-based)
  - log vocabulary:  docs/mvp-acceptance-criteria.md §3 (normative grep tokens)
  - IOC extraction:  docs/whisper-to-wazuh-mapping.md §9 — table validated against the
                     live 4.14.5 stack + ruleset source (issue #12 Q1, 2026-07-06)
  - exit codes:      stock Wazuh integration numbering (virustotal.py) where meanings
                     overlap: 2 bad args · 6 alert file not found · 7 invalid JSON

Runtime: the manager's bundled Python (3.10) — stdlib only, no third-party imports.

Pipeline (all stages implemented): extract IOCs (#13) → dedup check (#15) → enrich via
the Whisper graph (#14) → inject a new alert onto the analysisd socket (#16) → record dedup.
"""

import http.client
import ipaddress
import json
import os
import re
import socket
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

# --- integratord argv contract (docs/whisper-to-wazuh-mapping.md §2.3) -----------------
# argv[1] alert tmp file · argv[2] api_key · argv[3] hook_url (ignored, never validated;
# deliberately no constant — this integration never reads it) · argv[4] 'debug'/'' ·
# argv[5] options tmp file/'' · argv[6] timeout · argv[7] retries
# (+ a literal trailing "> /dev/null 2>&1" argument when debug is off — read positionally)
ALERT_INDEX = 1
APIKEY_INDEX = 2
DEBUG_INDEX = 4
OPTIONS_INDEX = 5
TIMEOUT_INDEX = 6
RETRIES_INDEX = 7

DEFAULT_TIMEOUT = 10
DEFAULT_RETRIES = 3

# Exit codes. 2/6/7 mirror the stock convention exactly (virustotal.py: ERR_BAD_ARGUMENTS,
# ERR_FILE_NOT_FOUND, ERR_INVALID_JSON); 5 is reserved to match ERR_SOCKET_OPERATION for
# #16. 8/10 are whisper-specific and picked from unclaimed numbers.
ERR_BAD_ARGUMENTS = 2
ERR_SOCKET_OPERATION = 5  # reserved — #16
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7
ERR_AUTH = 8  # terminal auth failure (TC-12)

INTEGRATION_NAME = 'custom-whisper'

# Wazuh home is one level up from integrations/. realpath (not abspath) so a symlinked
# install still resolves inside /var/ossec — mirrors the stock virustotal.py idiom.
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f'{pwd}/logs/integrations.log'
KEY_FILE = f'{pwd}/etc/whisper.key'
SOCKET_ADDR = f'{pwd}/queue/sockets/queue'
DEDUP_DB = f'{pwd}/var/whisper/dedup.db'  # normative path — mapping §7.5
MAX_EVENT_SIZE = 65535  # analysisd DGRAM datagram limit (matches maltiverse.py); errno 90 above it

# --- configuration defaults (resolution: <options> JSON → environment → default) --------
API_KEY_PLACEHOLDER = 'WHISPER_API_KEY_PLACEHOLDER'
DEFAULT_API_URL = 'https://graph.whisper.security'
DEFAULT_DEDUP_TTL = 3600  # seconds — mapping §7.4
DEFAULT_DEDUP_SCOPE = 'endpoint'  # 'endpoint' (key includes agent_id) | 'org' — mapping §7.2

# --- IOC extraction table (mapping §9, validated by issue #12 Q1 on 2026-07-06) ---------
# One table, one row per path: (full dotted path from the alert root, hint, status).
# hint drives the normalizer dispatch; status 'inactive' rows are documented-but-not-
# extracted and emit the normative unsupported-type line (TC-22). Order = emission order.
# Evidence classes from Q1: live-observed on the dev stack, template-mapped in
# wazuh-template.json, or ruleset-referenced in the 4.14.5 rules/decoders.
ACTIVE = 'active'
INACTIVE = 'inactive'
FIELD_PATHS: 'tuple[tuple[str, str, str], ...]' = (
    # Generic network decoders (srcip live-observed: sshd 5710/5715, nginx 31101)
    ('data.srcip', 'ip', ACTIVE),
    ('data.dstip', 'ip', ACTIVE),
    ('data.audit.srcip', 'ip', ACTIVE),
    # Appliance decoders — Cisco FTD/ASA, Sophos FW (ruleset-referenced)
    ('data.src_ip', 'ip', ACTIVE),
    ('data.dst_ip', 'ip', ACTIVE),
    # Suricata eve — NB dest_ip, not dst_ip (0999 rules 99915-99918)
    ('data.dest_ip', 'ip', ACTIVE),
    ('data.http.hostname', 'domain', ACTIVE),
    ('data.dns.rrname', 'domain', ACTIVE),
    # Windows / Sysmon — casing verified against 0810/0840/0590 rules
    ('data.win.eventdata.ipAddress', 'ip', ACTIVE),
    ('data.win.eventdata.sourceIp', 'ip', ACTIVE),
    ('data.win.eventdata.destinationIp', 'ip', ACTIVE),
    ('data.win.eventdata.queryName', 'domain', ACTIVE),
    ('data.win.eventdata.destinationHostname', 'domain', ACTIVE),
    # AWS — CloudTrail camelCase AND Macie snake_case both exist; VPC flow; WAF;
    # GuardDuty network/port-probe findings; Security Lake
    ('data.aws.sourceIPAddress', 'ip', ACTIVE),
    ('data.aws.source_ip_address', 'ip', ACTIVE),
    ('data.aws.srcaddr', 'ip', ACTIVE),
    ('data.aws.dstaddr', 'ip', ACTIVE),
    ('data.aws.httpRequest.clientIp', 'ip', ACTIVE),
    ('data.aws.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4', 'ip', ACTIVE),
    ('data.aws.service.action.portProbeAction.portProbeDetails.remoteIpDetails.ipAddressV4', 'ip', ACTIVE),
    ('data.src_endpoint.ip', 'ip', ACTIVE),
    # GCP
    ('data.gcp.jsonPayload.sourceIP', 'ip', ACTIVE),
    ('data.gcp.jsonPayload.queryName', 'domain', ACTIVE),
    # Office 365 / MS Graph — ClientIP frequently carries ip:port (normalizer strips it)
    ('data.office365.ClientIP', 'ip', ACTIVE),
    ('data.ms-graph.actor.ipAddress', 'ip', ACTIVE),
    # Cloudflare WAF (0935 + 0999 rule 99902)
    ('data.ClientIP', 'ip', ACTIVE),
    ('data.OriginIP', 'ip', ACTIVE),
    # macOS screen sharing (0999 rules 99909/99910)
    ('data.ip_address', 'ip', ACTIVE),
    # Web access logs: host component of ABSOLUTE URLs only — nginx/apache values are
    # path-only (Q1 live evidence); squid-style absolute URLs carry a host
    ('data.url', 'url_host', ACTIVE),
    # Documented-but-inactive (mapping §9: hash/path triggers out of MVP scope) — TC-22
    ('syscheck.sha256_after', 'hash', INACTIVE),
    ('syscheck.path', 'path', INACTIVE),
    # NOTE agent.ip is deliberately NOT a trigger (present on every agent alert; the
    # alert is not about the agent's own address). Resolved with #12 Q1.
)

MAX_LIST_VALUES = 10  # bound list-valued fields (some JSON decoders aggregate repeats)
ORIGINAL_LOG_MAX = 512  # source_ref.original_full_log truncation — mapping §4.2

# Conservative RFC-1035-ish shape check for domain-hinted values (lowercased, no trailing
# dot): ≥2 labels; TLD alphabetic OR a punycode A-label (xn--…) so IDN domains as DNS
# logs actually render them are not dropped. Values that fail are quietly debug-logged.
_DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+' r'(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$'
)


# --- error taxonomy (mirrors whisper-opencti; drives the `error class=` log line) -------
class WhisperError(Exception):
    """Base for Whisper-boundary failures."""

    log_class = 'query'


class WhisperAuthError(WhisperError):
    """401/403 — terminal: the same key fails for every candidate, so stop the run."""

    log_class = 'auth'


class WhisperTransportError(WhisperError):
    """Network / 5xx / 429-after-retries — transient."""

    log_class = 'transport'


class WhisperQueryError(WhisperError):
    """Other 4xx / malformed body — likely a connector bug."""

    log_class = 'query'


class WhisperSocketError(WhisperError):
    """analysisd socket failures (errno 90 oversize, connect refused) — for #16."""

    log_class = 'socket'


# --- logging (virustotal.py convention + the normative vocabulary) ----------------------
debug_enabled = False


def log_always(msg: str) -> None:
    """Unconditional log write (bad-argument errors are logged even with debug off)."""
    print(msg)
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')
    except OSError:
        pass  # never let logging kill the run


def debug(msg: str) -> None:
    if debug_enabled:
        log_always(msg)


# Normative vocabulary — docs/mvp-acceptance-criteria.md §3. Exact prefixes; tests assert.
def log_invoke(ioc: str, ioc_type: str, key: str) -> None:
    debug(f'whisper: invoke ioc={ioc} type={ioc_type} dedup_key={key}')


def log_skip(reason: str, **kv: str) -> None:
    extra = ''.join(f' {k}={v}' for k, v in kv.items())
    debug(f'whisper: skip reason={reason}{extra}')


def log_api(url: str, ms: int) -> None:
    debug(f'whisper: api url={url} ms={ms}')


def log_error(exc: WhisperError) -> None:
    debug(f'whisper: error class={exc.log_class} detail={exc}')


def log_emit(key: str, payload_bytes: int) -> None:
    debug(f'whisper: emit dedup_key={key} payload_bytes={payload_bytes}')


# --- configuration resolution ------------------------------------------------------------
def load_options(path: str) -> dict:
    """Read the <options> JSON tmp file (argv[5]); empty/missing/invalid → {}."""
    if not path:
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def resolve_api_url(options: dict, environ: dict) -> str:
    """<options>.api_url → WHISPER_API_URL → default (mapping §2.3)."""
    for candidate in (options.get('api_url'), environ.get('WHISPER_API_URL')):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip().rstrip('/')
    return DEFAULT_API_URL


def resolve_dedup_ttl(options: dict, environ: dict) -> int:
    """<options>.dedup_ttl → WHISPER_DEDUP_TTL → default.

    Non-numeric, negative, and JSON booleans all fall through — int(True) == 1 would
    otherwise turn a well-meant `"dedup_ttl": true` into a 1-second TTL.
    """
    for candidate in (options.get('dedup_ttl'), environ.get('WHISPER_DEDUP_TTL')):
        if candidate is None or isinstance(candidate, bool):
            continue
        try:
            ttl = int(str(candidate).strip())
        except ValueError:
            continue
        if ttl >= 0:
            return ttl
    return DEFAULT_DEDUP_TTL


def resolve_dedup_scope(options: dict, environ: dict) -> bool:
    """True = per-endpoint dedup (key includes agent_id); False = org-wide (mapping §7.2).

    <options>.dedup_scope → WHISPER_DEDUP_SCOPE → default 'endpoint'.
    """
    for candidate in (options.get('dedup_scope'), environ.get('WHISPER_DEDUP_SCOPE')):
        if isinstance(candidate, str):
            scope = candidate.strip().lower()
            if scope == 'org':
                return False
            if scope == 'endpoint':
                return True
    return DEFAULT_DEDUP_SCOPE == 'endpoint'


def resolve_api_key(argv_key: str, environ: dict, key_file: 'str | None' = None) -> 'str | None':
    """WHISPER_API_KEY env → key file (640 root:wazuh) → argv[2]; placeholder never counts.

    Keeping the real key out of ossec.conf keeps it out of the integratord child's
    /proc cmdline — scope §3.8 / acceptance TC-19. `key_file` defaults to the module
    global at CALL time so tests can monkeypatch KEY_FILE.
    """
    if key_file is None:
        key_file = KEY_FILE
    env_key = environ.get('WHISPER_API_KEY', '').strip()
    if env_key and env_key != API_KEY_PLACEHOLDER:
        return env_key
    try:
        with open(key_file) as f:
            file_key = f.read().strip()
        if file_key and file_key != API_KEY_PLACEHOLDER:
            return file_key
    except OSError:
        pass
    argv_key = (argv_key or '').strip()
    if argv_key and argv_key != API_KEY_PLACEHOLDER:
        return argv_key
    return None


def _argv_int(args: 'list[str]', idx: int, default: int) -> int:
    """Lenient positive-int parse for integratord's timeout/retries argv slots."""
    if len(args) > idx:
        try:
            n = int(args[idx])
        except (TypeError, ValueError):
            return default
        if n > 0:
            return n
    return default


# --- alert handling ----------------------------------------------------------------------
def load_alert(path: str) -> dict:
    """Read the single-alert JSON tmp file integratord hands us (argv[1])."""
    with open(path) as f:
        return json.load(f)


def get_nested(obj: dict, dotted: str):
    """Resolve a dotted path against the alert JSON; None when any hop is missing."""
    cur = obj
    for part in dotted.split('.'):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def is_self_alert(alert: dict) -> bool:
    """Feedback-loop guard #3: never process our own enrichment alerts (mapping §8)."""
    return get_nested(alert, 'data.integration') == INTEGRATION_NAME


def _strip_port(value: str) -> str:
    """'1.2.3.4:56' → '1.2.3.4'; '[::1]:56' → '::1'; anything else unchanged.

    Office 365 ClientIP (and other audit sources) frequently render peers as ip:port.
    Bare IPv6 (multiple colons, no brackets) passes through untouched.
    """
    if value.startswith('[') and ']' in value:
        return value[1 : value.index(']')]
    if value.count(':') == 1:
        host, _, port = value.partition(':')
        if '.' in host and port.isdigit():
            return host
    return value


def parse_ip(value: str) -> 'ipaddress.IPv4Address | ipaddress.IPv6Address | None':
    """The ipaddress object for a raw field value, or None when it isn't an IP.

    Strips an ip:port suffix and unwraps IPv4-mapped IPv6 (::ffff:a.b.c.d) — dual-stack
    listeners log peers in mapped form, and the mapped range is not `is_global` even
    when the embedded IPv4 is.
    """
    try:
        ip = ipaddress.ip_address(_strip_port(value))
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip


def classify_domain(value: str) -> 'str | None':
    """Normalize + validate a domain-hinted value; None when it isn't a plausible domain."""
    candidate = value.strip().rstrip('.').lower()
    if _DOMAIN_RE.match(candidate):
        return candidate
    return None


def extract_url_host(value: str) -> 'str | None':
    """Host component of an ABSOLUTE url; None for path-only values (nginx/apache logs)."""
    if '://' not in value:
        return None
    try:
        return urlsplit(value).hostname or None
    except ValueError:
        return None


def _classify(value: str, hint: str) -> 'tuple[str | None, str | None, str | None]':
    """Classify one raw string value per its path hint.

    Returns a tagged tuple — plain data flow, no exceptions as control flow:
      ('ok', ioc, ioc_type)        — a global IP or plausible domain
      ('non-global', display, None) — an IP the public-IP guard rejects
      (None, None, None)            — not an IOC of this hint's kind
    """
    v = value.strip()
    if hint == 'url_host':
        host = extract_url_host(v)
        if host is None:
            return (None, None, None)
        v = host  # the host may itself be an IP or a domain — fall through
    ip = parse_ip(v)
    if ip is not None:
        if not ip.is_global:
            return ('non-global', v, None)
        return ('ok', str(ip), 'ipv4' if ip.version == 4 else 'ipv6')
    if hint in ('domain', 'url_host'):
        domain = classify_domain(v)
        if domain is not None:
            return ('ok', domain, 'domain')
    return (None, None, None)


def extract_iocs(alert: dict) -> 'list[tuple[str, str, str]]':
    """Walk FIELD_PATHS and return [(ioc, type, field_path), ...], deduplicated.

    Emits the normative guard lines (acceptance §3):
      skip reason=non-global        — public-IP guard (TC-04/05)
      skip reason=unsupported-type  — inactive hash/path rows (TC-22)
      skip reason=no-ioc            — NO supported path had any value at all (TC-21);
                                      a path holding a non-IOC value is 'present' and
                                      therefore never a no-ioc case (it gets a debug line)
    """
    candidates: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    any_present = False

    for path, hint, status in FIELD_PATHS:
        value = get_nested(alert, path)
        if value is None or value == '' or value == []:
            continue
        any_present = True  # presence is about the PATH, not the value's type/validity

        if status == INACTIVE:
            log_skip('unsupported-type', field=path)
            continue

        values = value if isinstance(value, list) else [value]
        for raw in values[:MAX_LIST_VALUES]:
            if not isinstance(raw, str) or not raw.strip():
                debug(f'whisper: ignoring non-string value at {path}')
                continue
            kind, ioc, ioc_type = _classify(raw, hint)
            if kind == 'non-global':
                log_skip('non-global', ioc=ioc)
            elif kind == 'ok':
                if (ioc, ioc_type) not in seen:
                    seen.add((ioc, ioc_type))
                    candidates.append((ioc, ioc_type, path))
            else:
                debug(f'whisper: ignoring value at {path} (not a valid {hint})')

    if not any_present:
        log_skip('no-ioc')
    return candidates


def make_dedup_key(ioc_type: str, ioc: str, agent_id: str, include_agent: bool = True) -> str:
    """`{type}|{ioc}|{agent_id}` — agent segment gated by dedup_scope (mapping §7.2)."""
    if include_agent:
        return f'{ioc_type}|{ioc}|{agent_id}'
    return f'{ioc_type}|{ioc}'


def build_source_ref(alert: dict, field_path: str) -> dict:
    """The mapping-§4.2 source_ref linkage block for one extracted IOC."""
    return {
        'rule_id': str(get_nested(alert, 'rule.id') or ''),
        'alert_id': str(alert.get('id') or ''),
        'agent_id': str(get_nested(alert, 'agent.id') or '000'),
        'field_path': field_path,
        'original_full_log': str(alert.get('full_log') or '')[:ORIGINAL_LOG_MAX],
    }


# ==========================================================================================
# #14 — Whisper client, enrichment builders & verdict derivation
# ==========================================================================================

# --- HTTP client (stdlib urllib; POST /api/query with bound parameters) ------------------
# Bound parameters verified against the live API 2026-07-06 (incl. procedure args) — this
# supersedes the older literal-inlining constraint documented from the opencti era.
API_QUERY_PATH = '/api/query'
BACKOFF_BASE = 0.5
BACKOFF_CAP = 60.0
# Common CA-bundle locations, tried when the interpreter's compiled-in paths are empty.
# The Wazuh framework Python's default verify paths point at /usr/local/ssl/cert.pem (absent),
# so create_default_context() loads zero CAs and TLS verification would always fail. We keep
# verification ON (scope §3.8) and locate a real bundle instead.
_CA_BUNDLE_CANDIDATES = (
    '/etc/ssl/certs/ca-certificates.crt',  # Debian/Ubuntu (Wazuh manager image)
    '/etc/pki/tls/certs/ca-bundle.crt',  # RHEL/CentOS
    '/etc/ssl/cert.pem',  # Alpine/BSD
)


def _ssl_context() -> 'ssl.SSLContext':
    """A verifying TLS context that actually has CAs loaded, wherever the bundle lives.

    Resolution: the interpreter default → `SSL_CERT_FILE` → well-known bundle paths → the
    bundled `certifi` (ships with the framework Python). Verification stays ON throughout.
    """
    ctx = ssl.create_default_context()
    if ctx.get_ca_certs():
        return ctx
    candidates = [os.environ.get('SSL_CERT_FILE'), *_CA_BUNDLE_CANDIDATES]
    for path in candidates:
        if path and os.path.exists(path):
            try:
                ctx.load_verify_locations(path)
            except (ssl.SSLError, OSError):
                continue
            if ctx.get_ca_certs():  # an empty/placeholder PEM loads 0 certs without raising
                return ctx
    try:
        import certifi  # bundled with the Wazuh framework Python; last-resort only

        ctx.load_verify_locations(certifi.where())
    except (ImportError, ssl.SSLError, OSError):
        pass  # nothing found — verification will fail loudly (better than silently trusting all)
    return ctx


def _http_post(url: str, body: dict, headers: dict, timeout: int) -> 'tuple[int, bytes, dict]':
    """Thin transport seam (tests monkeypatch this). Returns (status, raw, lower-cased headers)."""
    req = urllib.request.Request(url, data=json.dumps(body).encode('utf-8'), headers=headers, method='POST')
    ctx = _ssl_context() if url.startswith('https') else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310 — https URL from config
            return resp.status, resp.read(), {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), {k.lower(): v for k, v in (exc.headers or {}).items()}


def _retry_after_seconds(headers: dict) -> 'float | None':
    value = headers.get('retry-after')
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return None


def execute_query(
    api_url: str,
    api_key: 'str | None',
    cypher: str,
    params: 'dict | None' = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> 'list[dict]':
    """POST one Cypher query; return `rows` (list of dicts keyed by column name).

    Error taxonomy (drives the `error class=` log line):
      401/403                    → WhisperAuthError (terminal)
      429 / 5xx after retries    → WhisperTransportError (Retry-After honoured per attempt)
      network failure            → WhisperTransportError
      other 4xx / bad body       → WhisperQueryError
    """
    headers = {'Content-Type': 'application/json'}
    if api_key:
        headers['X-API-Key'] = api_key
    body: dict = {'query': cypher}
    if params:
        body['parameters'] = params
    url = f'{api_url}{API_QUERY_PATH}'

    attempt = 0
    while True:
        started = time.monotonic()
        try:
            status, raw, resp_headers = _http_post(url, body, headers, timeout)
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            # http.client.HTTPException (BadStatusLine/IncompleteRead) is NOT an OSError —
            # catch it explicitly so a garbled response stays inside the retry budget and
            # the taxonomy instead of crashing main() with an unhandled traceback.
            log_api(api_url, int((time.monotonic() - started) * 1000))
            if attempt < retries:
                attempt += 1
                time.sleep(min(BACKOFF_BASE * (2 ** (attempt - 1)), BACKOFF_CAP))
                continue
            raise WhisperTransportError(f'network error after {retries} retries: {exc}') from exc
        log_api(api_url, int((time.monotonic() - started) * 1000))

        if status in (401, 403):
            raise WhisperAuthError(f'HTTP {status} from Whisper API')
        if status == 429 or status >= 500:
            if attempt < retries:
                attempt += 1
                delay = _retry_after_seconds(resp_headers)
                if delay is None:
                    delay = BACKOFF_BASE * (2 ** (attempt - 1))
                time.sleep(min(delay, BACKOFF_CAP))
                continue
            raise WhisperTransportError(f'HTTP {status} after {retries} retries')
        if status >= 400:
            raise WhisperQueryError(f'HTTP {status}: {raw[:500].decode("utf-8", "replace")}')

        try:
            parsed = json.loads(raw)
        except ValueError as exc:
            raise WhisperQueryError('non-JSON response body') from exc
        if parsed.get('success') is False:
            raise WhisperQueryError(str(parsed.get('error', 'unknown query error'))[:500])
        rows = parsed.get('rows')
        if not isinstance(rows, list):
            raise WhisperQueryError('malformed response: missing rows')
        return rows


# --- explain() — the authoritative threat verdict (mapping §5/§6) -------------------------
# The procedure is multi-shape: the rich shape below on success, and a degraded shape
# carrying error/retryAfter when the scoring backend is down. NOTE the REST layer has no
# `coverage` field (that is an MCP-surface addition) — coverage.granularity is derived
# from the IOC type; shared_host/data_coverage stay None and are stripped before send.
_EXPLAIN_FIELDS = (
    'indicator, type, available, cached, found, score, level, '
    'explanation, factors, sources, breakdown, advisory'
)
_EXPLAIN_ERROR_FIELDS = 'indicator, type, available, error, retryAfter, advisory'


def call_explain(cfg: dict, ioc: str) -> dict:
    """One explain() row for the IOC; {'available': False, ...} when the backend is degraded."""
    rich = f'CALL explain($ioc) YIELD {_EXPLAIN_FIELDS} RETURN {_EXPLAIN_FIELDS} LIMIT 1'
    try:
        rows = execute_query(
            cfg['api_url'], cfg['api_key'], rich, {'ioc': ioc}, cfg['timeout'], cfg['retries']
        )
    except WhisperQueryError as rich_err:
        # A query error on the rich shape is usually the degraded backend answering with the
        # error-shaped YIELD — retry that shape to harvest retryAfter. But a genuine 400 (bad
        # YIELD, proxy HTML) fails BOTH shapes; surface the ORIGINAL error, not the fallback's.
        debug(f'whisper: explain rich-shape failed, trying degraded shape ({rich_err})')
        fallback = f'CALL explain($ioc) YIELD {_EXPLAIN_ERROR_FIELDS} RETURN {_EXPLAIN_ERROR_FIELDS} LIMIT 1'
        try:
            rows = execute_query(
                cfg['api_url'], cfg['api_key'], fallback, {'ioc': ioc}, cfg['timeout'], cfg['retries']
            )
        except WhisperQueryError:
            raise rich_err from None
    return rows[0] if rows else {'available': False, 'found': False}


# --- feed polarity (issue #12 Q5) ---------------------------------------------------------
# Static slug→category map generated from the live graph (FEED_SOURCE.id → CATEGORY.name,
# 43 feeds, 2026-07-06). "Listed in N feeds" is never itself bad — polarity comes from the
# category (mapping §6). The feed set evolves (per-variant slugs like hagezi-dns-pro-ip),
# so unknown slugs fall through to prefix matching, then to None (neutral).
FEED_CATEGORIES = {
    'tranco-top1m': 'Popularity/Trust',
    'cloudflare-radar-top1m': 'Popularity/Trust',
    'abuse-ch-feodo-tracker': 'C2 Servers',
    'abuse-ch-threatfox-iocs': 'C2 Servers',
    'botvrij-ioc-dst-ip': 'C2 Servers',
    'c2intelfeeds': 'C2 Servers',
    'abuse-ch-urlhaus': 'Malware Distribution',
    'abuse-ch-malwarebazaar': 'Malware Distribution',
    'openphish': 'Phishing',
    'blocklist-de-ssh': 'Brute Force',
    'dataplane-sshpwauth': 'Brute Force',
    'dataplane-sshclient': 'Brute Force',
    'bruteforceblocker': 'Brute Force',
    'cert-pl-domains': 'Malicious Domains',
    'botvrij-ioc-domain': 'Malicious Domains',
    'ofac-sdn-crypto-eth': 'OFAC SDN Sanctions',
    'ofac-sdn-crypto-btc': 'OFAC SDN Sanctions',
    'ofac-sdn-crypto-trx': 'OFAC SDN Sanctions',
    'ofac-sdn-crypto-sol': 'OFAC SDN Sanctions',
    'tor-exit-nodes': 'TOR Network',
    'dan-tor-exit': 'TOR Network',
    'firehol-anonymous': 'Proxies',
    'spamhaus-drop': 'General Blacklists',
    'spamhaus-edrop': 'General Blacklists',
    'firehol-level1': 'General Blacklists',
    'firehol-level2': 'General Blacklists',
    'firehol-level3': 'General Blacklists',
    'stamparm-ipsum': 'General Blacklists',
    'greensnow': 'General Blacklists',
    'blocklist-de-all': 'General Blacklists',
    'cins-score': 'General Blacklists',
    'binarydefense-banlist': 'General Blacklists',
    'emerging-threats-compromised': 'General Blacklists',
    'interserver-level1': 'General Blacklists',
    'firehol-abusers-1d': 'General Blacklists',
    'firehol-webclient': 'General Blacklists',
    'dataplane-dnsrd': 'General Blacklists',
    'abuse-ch-ssl-blacklist': 'General Blacklists',
    'blocklist-de-mail': 'Spam',
    'alienvault-reputation': 'Reputation',
    'stevenblack-hosts': 'Ad/Tracking Blocklists',
    'hagezi-dns-light': 'Ad/Tracking Blocklists',
    'hagezi-dns-pro': 'Ad/Tracking Blocklists',
}
FEED_CATEGORY_PREFIXES = (
    ('hagezi-', 'Ad/Tracking Blocklists'),
    ('oisd-', 'Ad/Tracking Blocklists'),
    ('stevenblack-', 'Ad/Tracking Blocklists'),
    ('stopforumspam-', 'Spam'),
    ('firehol-', 'General Blacklists'),
    ('blocklist-de-', 'General Blacklists'),
    ('ofac-sdn-', 'OFAC SDN Sanctions'),
    ('phishtank', 'Phishing'),
    ('tor-', 'TOR Network'),
)
TRUST_CATEGORIES = frozenset({'Popularity/Trust'})
CONFIRMED_BAD_CATEGORIES = frozenset(
    {
        'C2 Servers',
        'Malware Distribution',
        'Phishing',
        'Brute Force',
        'Attack Sources',
        'Exfiltration Destinations',
        'Malicious Domains',
        'Malicious Infrastructure',
        'State Actor & Sanctions',
        'OFAC SDN Sanctions',
    }
)
# Real-but-not-confirmed-malicious threat signals → suspicious (never known_good, never
# known_bad on their own). Ad/Tracking Blocklists are DNS-filter noise and Reputation is
# a weak aggregate; both are treated as neutral (not enough for suspicious by themselves).
SUSPICIOUS_CATEGORIES = CONFIRMED_BAD_CATEGORIES | frozenset(
    {
        'General Blacklists',
        'Spam',
        'TOR Network',
        'Proxies',
        'Anonymization Infrastructure',
        'VPNs',
    }
)


def feed_category(slug: str) -> 'str | None':
    if slug in FEED_CATEGORIES:
        return FEED_CATEGORIES[slug]
    for prefix, category in FEED_CATEGORY_PREFIXES:
        if slug.startswith(prefix):
            return category
    return None


# --- node threat flags ---------------------------------------------------------------------
THREAT_FLAGS = (
    'isThreat',
    'isC2',
    'isMalware',
    'isPhishing',
    'isBotnet',
    'isBruteforce',
    'isScanner',
    'isSpam',
    'isBlacklist',
    'isDga',
    'isExfilDestination',
    'isOfacSanctioned',
    'isStateActor',
    'isTor',
    'isProxy',
    'isVpn',
    'isAnonymizer',
    'isReputation',
    'isWhitelist',
)
# Flags that count as threat evidence for the verdict (Tor/proxy/VPN/anonymizer are
# context, not maliciousness — mapping §6's Tor example).
BAD_FLAGS = frozenset(
    {
        'isThreat',
        'isC2',
        'isMalware',
        'isPhishing',
        'isBotnet',
        'isBruteforce',
        'isScanner',
        'isSpam',
        'isBlacklist',
        'isDga',
        'isExfilDestination',
        'isOfacSanctioned',
        'isStateActor',
    }
)
TAG_BY_FLAG = {
    'isThreat': 'threat',
    'isC2': 'c2',
    'isMalware': 'malware',
    'isPhishing': 'phishing',
    'isBotnet': 'botnet',
    'isBruteforce': 'bruteforce',
    'isScanner': 'scanner',
    'isSpam': 'spam',
    'isBlacklist': 'blacklist',
    'isDga': 'dga',
    'isExfilDestination': 'exfil',
    'isOfacSanctioned': 'ofac-sanctioned',
    'isStateActor': 'state-actor',
    'isTor': 'tor',
    'isProxy': 'proxy',
    'isVpn': 'vpn',
    'isAnonymizer': 'anonymizer',
}
_NODE_LABELS = {'ipv4': 'IPV4', 'ipv6': 'IPV6', 'domain': 'HOSTNAME'}


def fetch_flags(cfg: dict, ioc: str, ioc_type: str) -> 'dict | None':
    """The node's is* boolean threat flags, or None when the node is ABSENT.

    This is also the authoritative `known` signal: `explain().found` is unreliable for
    domains (it returns true for any well-formed name even with no node — verified
    2026-07-06), so node existence is determined here, by an anchored MATCH.
    """
    label = _NODE_LABELS[ioc_type]
    projection = ', '.join(f'n.{f} AS {f}' for f in THREAT_FLAGS)
    rows = execute_query(
        cfg['api_url'],
        cfg['api_key'],
        f'MATCH (n:{label} {{name: $v}}) RETURN {projection} LIMIT 1',
        {'v': ioc},
        cfg['timeout'],
        cfg['retries'],
    )
    return rows[0] if rows else None


# --- verdict derivation (mapping §6 — ordered gates, first match wins) ---------------------
def derive_verdict(explain_row: dict, flags: dict, known: bool = True) -> str:
    """Evidence-derived verdict. The Whisper score is evidence, never the answer:
    verdict comes from the level enum + feed *category* polarity + node flags —
    never from the raw score and never from the explanation string (they can disagree).

    `known` = the IOC has a real graph node (from fetch_flags, NOT explain().found, which
    is unreliable for domains). NOTE the §6 coverage gate (shared_host / data_coverage →
    unknown) is NOT enforced here: the REST explain() surface exposes no coverage block
    (verified 2026-07-06). The gate order is otherwise conservative — any confirmed-bad or
    threat signal blocks known_good — so a multi-tenant apex listed only in trust feeds is
    the one residual case (documented in mapping §6/§11).
    """
    level = explain_row.get('level') or 'NONE'
    sources = explain_row.get('sources') or []
    categories = [feed_category(str(s.get('feedId', ''))) for s in sources]
    has_confirmed_bad = any(c in CONFIRMED_BAD_CATEGORIES for c in categories)
    has_suspicious_cat = any(c in SUSPICIOUS_CATEGORIES for c in categories)
    has_bad_flags = any(flags.get(f) for f in BAD_FLAGS)
    has_threat_evidence = has_confirmed_bad or has_suspicious_cat or has_bad_flags

    # Gate 1 — unknown: no data ≠ benign. `known` is node existence, not explain().found.
    if not explain_row.get('available', False) or not known:
        return 'unknown'

    # Gate 2 — known_good: a positive trust signal AND no threat evidence to override it.
    trust_only = bool(sources) and all(c in TRUST_CATEGORIES for c in categories)
    has_trust_signal = (
        explain_row.get('advisory') == 'allowlist-vouched' or flags.get('isWhitelist') or trust_only
    )
    if has_trust_signal and not has_threat_evidence and level not in ('HIGH', 'CRITICAL'):
        return 'known_good'

    # Gate 3 — known_bad: severity AND a confirmed-bad category.
    if level in ('HIGH', 'CRITICAL') and has_confirmed_bad:
        return 'known_bad'

    # Gate 4 — suspicious: a real score band, or any threat evidence short of confirmed-bad.
    if level in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') or has_threat_evidence:
        return 'suspicious'

    # Found, but only trust/neutral/no evidence and no score band → unknown, not known_good.
    return 'unknown'


# --- threat_feed / tags fragments -----------------------------------------------------------
def build_threat_feed(sources: 'list[dict]', flags: dict) -> dict:
    feeds = [str(s.get('feedId', '')) for s in sources]
    categories = sorted({c for c in (feed_category(f) for f in feeds) if c})
    true_flags = [f for f in THREAT_FLAGS if flags.get(f)]
    # ISO-8601 strings compare lexicographically — min/max are chronological.
    firsts = [s['firstSeen'] for s in sources if s.get('firstSeen')]
    lasts = [s['lastSeen'] for s in sources if s.get('lastSeen')]
    return {
        'feeds': feeds,
        'categories': categories,
        'flags': true_flags,
        'sources_count': len(feeds),
        'first_seen': min(firsts) if firsts else None,
        'last_seen': max(lasts) if lasts else None,
    }


def build_tags(flags: dict, categories: 'list[str]') -> 'list[str]':
    tags = {TAG_BY_FLAG[f] for f in TAG_BY_FLAG if flags.get(f)}
    category_tags = {
        'Phishing': 'phishing',
        'C2 Servers': 'c2',
        'Malware Distribution': 'malware',
        'Brute Force': 'bruteforce',
        'TOR Network': 'tor',
        'Proxies': 'proxy',
        'VPNs': 'vpn',
        'Spam': 'spam',
        'OFAC SDN Sanctions': 'ofac-sanctioned',
    }
    tags.update(category_tags[c] for c in categories if c in category_tags)
    return sorted(tags)


# --- IP enrichment (mapping §5.1/§5.3) -------------------------------------------------------
_ASN_NUM_RE = re.compile(r'^AS(\d+)$')
# No direct IP→ASN edge: BELONGS_TO→PREFIX←ROUTES−ASN; human name via HAS_NAME (nullable —
# verified: AS60729 has no ASN_NAME). IPv6 has no HAS_COUNTRY edge — country via ASN/CITY.
_Q_IP_CONTEXT_V4 = (
    'MATCH (ip:IPV4 {name: $v}) '
    'OPTIONAL MATCH (ip)-[:BELONGS_TO]->(p:PREFIX)<-[:ROUTES]-(a:ASN) '
    'OPTIONAL MATCH (a)-[:HAS_NAME]->(an:ASN_NAME) '
    'OPTIONAL MATCH (a)-[:HAS_COUNTRY]->(ac:COUNTRY) '
    'OPTIONAL MATCH (ip)-[:HAS_COUNTRY]->(c:COUNTRY) '
    'OPTIONAL MATCH (ip)-[:LOCATED_IN]->(city:CITY) '
    'RETURN p.name AS prefix, a.name AS asn, an.name AS asn_name, '
    'ac.name AS asn_country, c.name AS country, city.name AS city LIMIT 1'
)
_Q_IP_CONTEXT_V6 = (
    'MATCH (ip:IPV6 {name: $v}) '
    'OPTIONAL MATCH (ip)-[:BELONGS_TO]->(p:PREFIX)<-[:ROUTES]-(a:ASN) '
    'OPTIONAL MATCH (a)-[:HAS_NAME]->(an:ASN_NAME) '
    'OPTIONAL MATCH (a)-[:HAS_COUNTRY]->(ac:COUNTRY) '
    'OPTIONAL MATCH (ip)-[:LOCATED_IN]->(city:CITY) '
    'RETURN p.name AS prefix, a.name AS asn, an.name AS asn_name, '
    'ac.name AS asn_country, city.name AS city LIMIT 1'
)


def build_ip_fragments(cfg: dict, ioc: str, ioc_type: str, flags: dict, notes: 'list[str]') -> dict:
    cypher = _Q_IP_CONTEXT_V4 if ioc_type == 'ipv4' else _Q_IP_CONTEXT_V6
    rows = execute_query(cfg['api_url'], cfg['api_key'], cypher, {'v': ioc}, cfg['timeout'], cfg['retries'])
    ctx = rows[0] if rows else {}

    asn_obj: 'dict | None' = None
    asn_raw = ctx.get('asn')
    if isinstance(asn_raw, str):
        match = _ASN_NUM_RE.match(asn_raw)
        if match:
            asn_obj = {'number': int(match.group(1)), 'name': ctx.get('asn_name')}
            country = ctx.get('asn_country')
            if country:
                asn_obj['country'] = country
            # ASN reputation: breakdown from explain(asn) — the top-level score reflects
            # only direct feed listing (often 0); the actionable signal is the breakdown.
            # Auth errors must still terminate the run (never swallowed into a note).
            try:
                rep = call_explain(cfg, asn_raw)
                if rep.get('breakdown'):
                    asn_obj['reputation'] = rep['breakdown']
            except (WhisperTransportError, WhisperQueryError):
                notes.append('asn reputation lookup failed')

    geo = {}
    country = ctx.get('country') or ctx.get('asn_country')
    if country:
        geo['country'] = country
    if ctx.get('city'):
        geo['city'] = ctx['city']

    fragments: dict = {}
    if asn_obj:
        fragments['asn'] = asn_obj
    if ctx.get('prefix'):
        fragments['prefix'] = ctx['prefix']
    if geo:
        fragments['geo'] = geo
    # related.neighbors[] (reverse RESOLVES_TO / co-hosting) is deferred graph-wide — a plain
    # reverse traversal is rejected as an unanchored 2.6B-node scan (mapping §11 Q4). It is a
    # known non-goal, not per-alert unmapped data, so it is NOT noted here (keeps
    # unmapped_summary absent for a clean IP — matching the §4.1 example).
    return fragments


# --- domain enrichment (mapping §5.2 — one anchored DIRECTIONAL query per category) ----------
LIST_CAP = 25
WHOIS_CAP = 10
ORG_CAP = 5
# The engine clamps LIMIT to 500 (live CLAMP_LIMIT rewrite, verified 2026-07-06), so a
# bounded count maxes at 500; a total == 500 means "≥500, capped" (mapping §8 truncation).
LINKS_COUNT_CAP = 500
# Templates carry a {cap} placeholder so the reader queries cap+1 and can detect truncation
# (an integer constant — safe to inline). NS/MX point neighbour→seed: own records via `<-`.
_Q_DNS = {
    'a': 'MATCH (d:HOSTNAME {{name: $v}})-[:RESOLVES_TO]->(m:IPV4) WITH m LIMIT {cap} RETURN m.name AS name',
    'aaaa': 'MATCH (d:HOSTNAME {{name: $v}})-[:RESOLVES_TO]->(m:IPV6) WITH m LIMIT {cap} RETURN m.name AS name',
    'cname': 'MATCH (d:HOSTNAME {{name: $v}})-[:ALIAS_OF]->(m:HOSTNAME) WITH m LIMIT {cap} RETURN m.name AS name',
    'ns': 'MATCH (d:HOSTNAME {{name: $v}})<-[:NAMESERVER_FOR]-(m:HOSTNAME) WITH m LIMIT {cap} RETURN m.name AS name',
    'mx': 'MATCH (d:HOSTNAME {{name: $v}})<-[:MAIL_FOR]-(m:HOSTNAME) WITH m LIMIT {cap} RETURN m.name AS name',
}
# Query registrar BEFORE previous-registrar; first-writer-wins when the same node
# appears under both edges (opencti #61 ordering discipline).
_Q_WHOIS_REGISTRARS = (
    'MATCH (d:HOSTNAME {name: $v}) '
    'OPTIONAL MATCH (d)-[:HAS_REGISTRAR]->(r:REGISTRAR) '
    'OPTIONAL MATCH (d)-[:PREV_REGISTRAR]->(pr:REGISTRAR) '
    'RETURN r.name AS registrar, pr.name AS previous LIMIT 1'
)
_Q_WHOIS_ORG = 'MATCH (d:HOSTNAME {{name: $v}})-[:REGISTERED_BY]->(o:ORGANIZATION) WITH o LIMIT {cap} RETURN o.name AS name'
_Q_WHOIS_EMAIL = (
    'MATCH (d:HOSTNAME {{name: $v}})-[:HAS_EMAIL]->(m:EMAIL) WITH m LIMIT {cap} RETURN m.name AS name'
)
_Q_WHOIS_PHONE = (
    'MATCH (d:HOSTNAME {{name: $v}})-[:HAS_PHONE]->(m:PHONE) WITH m LIMIT {cap} RETURN m.name AS name'
)
_Q_SPF = {
    'include': 'MATCH (d:HOSTNAME {{name: $v}})-[:SPF_INCLUDE]->(m) WITH m LIMIT {cap} RETURN m.name AS name',
    'a': 'MATCH (d:HOSTNAME {{name: $v}})-[:SPF_A]->(m) WITH m LIMIT {cap} RETURN m.name AS name',
    'mx': 'MATCH (d:HOSTNAME {{name: $v}})-[:SPF_MX]->(m) WITH m LIMIT {cap} RETURN m.name AS name',
    'ip': 'MATCH (d:HOSTNAME {{name: $v}})-[:SPF_IP]->(m) WITH m LIMIT {cap} RETURN m.name AS name',
    'exists': 'MATCH (d:HOSTNAME {{name: $v}})-[:SPF_EXISTS]->(m) WITH m LIMIT {cap} RETURN m.name AS name',
}
_Q_SPF_REDIRECT = 'MATCH (d:HOSTNAME {name: $v})-[:SPF_REDIRECT]->(m) RETURN m.name AS name LIMIT 1'
_Q_LINKS_OUT = (
    'MATCH (d:HOSTNAME {{name: $v}})-[:LINKS_TO]->(o:HOSTNAME) WITH o LIMIT {cap} RETURN o.name AS name'
)
_Q_LINKS_IN = (
    'MATCH (d:HOSTNAME {{name: $v}})<-[:LINKS_TO]-(o:HOSTNAME) WITH o LIMIT {cap} RETURN o.name AS name'
)
# Exact counts error on hub domains (collect >1M) — bounded count (engine clamps to 500).
_Q_LINKS_OUT_COUNT = (
    'MATCH (d:HOSTNAME {name: $v})-[:LINKS_TO]->(o:HOSTNAME) WITH o LIMIT 500 RETURN count(o) AS c'
)
_Q_LINKS_IN_COUNT = (
    'MATCH (d:HOSTNAME {name: $v})<-[:LINKS_TO]-(o:HOSTNAME) WITH o LIMIT 500 RETURN count(o) AS c'
)


def _names(cfg: dict, cypher: str, ioc: str) -> 'list[str]':
    """Names from a plain (already-LIMITed) template — no truncation tracking."""
    rows = execute_query(cfg['api_url'], cfg['api_key'], cypher, {'v': ioc}, cfg['timeout'], cfg['retries'])
    return [r['name'] for r in rows if isinstance(r.get('name'), str)]


def _capped_names(
    cfg: dict, template: str, ioc: str, cap: int, label: str, trunc: 'list[str]'
) -> 'list[str]':
    """Names from a {cap}-templated query, capped at `cap`. Queries cap+1 to DETECT
    truncation; records the field label in `trunc` and slices to `cap` when there are more."""
    rows = execute_query(
        cfg['api_url'],
        cfg['api_key'],
        template.format(cap=cap + 1),
        {'v': ioc},
        cfg['timeout'],
        cfg['retries'],
    )
    names = [r['name'] for r in rows if isinstance(r.get('name'), str)]
    if len(names) > cap:
        trunc.append(label)
        return names[:cap]
    return names


def _count_capped(cfg: dict, cypher: str, ioc: str) -> 'tuple[int, bool]':
    """(count, at_cap). at_cap True when the engine-clamped count hit LINKS_COUNT_CAP."""
    rows = execute_query(cfg['api_url'], cfg['api_key'], cypher, {'v': ioc}, cfg['timeout'], cfg['retries'])
    value = rows[0].get('c') if rows else 0
    count = value if isinstance(value, int) else 0
    return count, count >= LINKS_COUNT_CAP


# --- domain variants (no LOOKALIKE_OF edge — generate in-process, confirm registration) ------
_HOMOGLYPHS = {'o': '0', 'l': '1', 'i': '1', 'e': '3', 'a': '4', 's': '5', 'g': '9', 'b': '8'}
_VARIANT_TLDS = ('com', 'net', 'org', 'info', 'co', 'io', 'xyz', 'top')
MAX_VARIANT_CANDIDATES = 60
VARIANTS_CAP = 25


def registrable_domain(domain: str) -> 'str | None':
    """The registrable apex to squat on: (sld, tld) → 'sld.tld'. Heuristic — the last two
    labels; a full PSL is out of MVP scope, so multi-part suffixes (co.uk) squat the
    second level (documented). Reduces subdomains (www.evil.com → evil.com) so variants
    mutate the real registrable label, not 'www'."""
    parts = [p for p in domain.split('.') if p]
    if len(parts) < 2:
        return None
    return '.'.join(parts[-2:])


def generate_domain_variants(domain: str) -> 'list[tuple[str, str, float]]':
    """Bounded typosquat candidates: [(variant, method, confidence), ...] — opencti's
    generator ported. Operates on the REGISTRABLE domain (not a subdomain label).
    `exists` ≠ malicious; registration is confirmed separately."""
    apex = registrable_domain(domain)
    if apex is None:
        return []
    label, _, rest = apex.partition('.')
    seen: set[str] = {domain, apex}
    out: list[tuple[str, str, float]] = []

    def add(candidate: str, method: str, confidence: float) -> None:
        if candidate not in seen and len(out) < MAX_VARIANT_CANDIDATES:
            seen.add(candidate)
            out.append((candidate, method, confidence))

    for i, ch in enumerate(label):
        if ch in _HOMOGLYPHS:
            add(f'{label[:i]}{_HOMOGLYPHS[ch]}{label[i + 1 :]}.{rest}', 'homoglyph', 0.9)
    if len(label) > 2:
        for i in range(len(label)):
            add(f'{label[:i]}{label[i + 1 :]}.{rest}', 'omission', 0.7)
    for i in range(len(label) - 1):
        swapped = f'{label[:i]}{label[i + 1]}{label[i]}{label[i + 2 :]}'
        add(f'{swapped}.{rest}', 'transposition', 0.7)
    for i, ch in enumerate(label):
        add(f'{label[:i]}{ch}{ch}{label[i + 1 :]}.{rest}', 'repetition', 0.7)
    for tld in _VARIANT_TLDS:
        if rest != tld:
            add(f'{label}.{tld}', 'tld-swap', 0.5)
    for i in range(1, len(label)):
        add(f'{label[:i]}-{label[i:]}.{rest}', 'hyphenation', 0.3)
    return out


def confirm_variants(
    cfg: dict, candidates: 'list[tuple[str, str, float]]', trunc: 'list[str]'
) -> 'list[dict]':
    """One UNWIND existence query; only REGISTERED variants survive."""
    if not candidates:
        return []
    rows = execute_query(
        cfg['api_url'],
        cfg['api_key'],
        'UNWIND $cands AS v MATCH (h:HOSTNAME {name: v}) RETURN h.name AS name',
        {'cands': [c[0] for c in candidates]},
        cfg['timeout'],
        cfg['retries'],
    )
    existing = {r['name'] for r in rows if isinstance(r.get('name'), str)}
    confirmed = [{'variant': v, 'method': m, 'confidence': c} for v, m, c in candidates if v in existing]
    if len(confirmed) > VARIANTS_CAP:
        trunc.append('variants')
    return confirmed[:VARIANTS_CAP]


def build_domain_fragments(cfg: dict, ioc: str, notes: 'list[str]', trunc: 'list[str]') -> dict:
    fragments: dict = {
        'dns': {
            key: _capped_names(cfg, tpl, ioc, LIST_CAP, f'dns.{key}', trunc) for key, tpl in _Q_DNS.items()
        },
    }

    reg_rows = execute_query(
        cfg['api_url'], cfg['api_key'], _Q_WHOIS_REGISTRARS, {'v': ioc}, cfg['timeout'], cfg['retries']
    )
    reg = reg_rows[0] if reg_rows else {}
    registrar = reg.get('registrar')
    previous = reg.get('previous')
    if previous == registrar:
        previous = None  # first-writer-wins: current state owns the shared node
    orgs = _capped_names(cfg, _Q_WHOIS_ORG, ioc, ORG_CAP, 'whois.registered_by', trunc)
    if len(orgs) > 1:
        notes.append(f'{len(orgs) - 1} additional registrant org(s) not mapped')
    fragments['whois'] = {
        'registrar': registrar,
        'previous_registrar': previous,
        'registered_by': orgs[0] if orgs else None,
        'email': _capped_names(cfg, _Q_WHOIS_EMAIL, ioc, WHOIS_CAP, 'whois.email', trunc),
        'phone': _capped_names(cfg, _Q_WHOIS_PHONE, ioc, WHOIS_CAP, 'whois.phone', trunc),
    }

    spf = {key: _capped_names(cfg, tpl, ioc, LIST_CAP, f'spf.{key}', trunc) for key, tpl in _Q_SPF.items()}
    redirect = _names(cfg, _Q_SPF_REDIRECT, ioc)
    spf['redirect'] = redirect[0] if redirect else None
    fragments['spf'] = spf

    out_names = _capped_names(cfg, _Q_LINKS_OUT, ioc, LIST_CAP, 'links.outbound', trunc)
    in_names = _capped_names(cfg, _Q_LINKS_IN, ioc, LIST_CAP, 'links.inbound', trunc)
    out_total, out_capped = _count_capped(cfg, _Q_LINKS_OUT_COUNT, ioc)
    in_total, in_capped = _count_capped(cfg, _Q_LINKS_IN_COUNT, ioc)
    if out_capped:
        trunc.append('links.outbound_total')
    if in_capped:
        trunc.append('links.inbound_total')
    fragments['links'] = {
        'outbound': out_names,
        'outbound_total': out_total,
        'inbound': in_names,
        'inbound_total': in_total,
    }

    fragments['variants'] = confirm_variants(cfg, generate_domain_variants(ioc), trunc)
    return fragments


# --- envelope assembly & payload guard (mapping §4.2 / §8) -----------------------------------
MAX_PAYLOAD_BYTES = 60 * 1024
FRAMING_MARGIN = 1024  # headroom for the Form-B location prefix + integration wrapper (#16)
_GRANULARITY = {'ipv4': 'ipv4', 'ipv6': 'ipv6', 'domain': 'hostname'}
# Optional list fields, largest-first, dropped when over budget; core verdict/evidence
# fields are never dropped. spf.* is included (six lists) so a pathological SPF graph can
# still be trimmed.
_DROP_ORDER = (
    ('links', 'outbound'),
    ('links', 'inbound'),
    ('variants', None),
    ('spf', 'include'),
    ('spf', 'ip'),
    ('spf', 'a'),
    ('spf', 'mx'),
    ('spf', 'exists'),
    ('whois', 'email'),
    ('whois', 'phone'),
    ('dns', 'a'),
    ('dns', 'aaaa'),
    ('dns', 'ns'),
    ('dns', 'mx'),
    ('dns', 'cname'),
    ('threat_feed', 'feeds'),
)
# Never dropped by the last-resort core reduction.
_CORE_KEYS = frozenset(
    {
        'schema_version',
        'ioc',
        'type',
        'known',
        'available',
        'verdict',
        'risk_score',
        'level',
        'advisory',
        'permalink',
        'graph_node_id',
        'source_ref',
        'coverage',
        'dedup_key',
        'tags',
        'threat_feed',
        'unmapped_summary',
        'truncated',
    }
)


def _payload_size(payload: dict) -> int:
    return len(json.dumps(payload, separators=(',', ':')).encode('utf-8'))


def _over_budget(payload: dict) -> bool:
    # Budget the WHOLE datagram incl. the {'integration': ...} wrapper + framing headroom.
    return _payload_size(payload) + FRAMING_MARGIN > MAX_PAYLOAD_BYTES


def fit_payload(payload: dict, notes: 'list[str]') -> dict:
    """Enforce the 60 KB budget (mapping §8): drop the largest optional lists first, then —
    as a last resort — reduce to the core verdict/evidence fields. Every drop is recorded;
    never a silent truncation, never a failed send. `payload` is the full injected dict."""
    whisper = payload['whisper']
    for section, key in _DROP_ORDER:
        if not _over_budget(payload):
            break
        container = whisper.get(section)
        if key is None and whisper.get(section):
            whisper[section] = []
            whisper['truncated'] = True
            notes.append(f'{section} dropped (payload budget)')
        elif isinstance(container, dict) and container.get(key):
            container[key] = []
            whisper['truncated'] = True
            notes.append(f'{section}.{key} dropped (payload budget)')

    if _over_budget(payload):
        for k in [k for k in whisper if k not in _CORE_KEYS]:
            whisper.pop(k, None)
        whisper['truncated'] = True
        notes.append('reduced to core (payload budget)')

    if _over_budget(payload):
        notes.append('payload_too_large')
    return payload


def enrich(
    ioc: str,
    ioc_type: str,
    dedup_key: str,
    source_ref: dict,
    api_url: str,
    api_key: 'str | None',
    timeout: int,
    retries: int,
) -> dict:
    """Build the full injection payload ({'integration': ..., 'whisper': {...}}) for one IOC.

    explain() is the authoritative verdict source (threat evidence from sources[], never
    Cypher LISTED_IN) and is FAIL-HARD — the verdict depends on it. The category fragments
    are best-effort: a transport/query failure in any auxiliary query degrades with a note
    rather than discarding an already-computed verdict (auth errors still terminate). The
    whole datagram respects the 60 KB socket budget.
    """
    cfg = {'api_url': api_url, 'api_key': api_key, 'timeout': timeout, 'retries': retries}
    notes: list[str] = []
    trunc: list[str] = []

    explain_row = call_explain(cfg, ioc)  # fail-hard
    available = bool(explain_row.get('available', False))
    granularity = _GRANULARITY[ioc_type]
    kind = 'domain' if ioc_type == 'domain' else 'ip'
    if explain_row.get('retryAfter') is not None:
        notes.append(f'scoring degraded (retryAfter={explain_row["retryAfter"]})')

    whisper: dict = {
        'schema_version': '1.0',
        'ioc': ioc,
        'type': ioc_type,
        'known': False,  # set from real node existence below (explain().found is unreliable)
        'available': available,
        'verdict': 'unknown',
        'risk_score': float(explain_row.get('score') or 0.0),
        'level': str(explain_row.get('level') or 'NONE'),
        'advisory': explain_row.get('advisory'),
        'permalink': f'{api_url}/{kind}/{ioc}',
        'graph_node_id': None,
        'source_ref': source_ref,
        # The REST layer has no coverage block (MCP-surface only): granularity is
        # derived from the IOC type; shared_host/data_coverage stay None here and are
        # stripped before send (nullable fields are omitted, never JSON null — §2.4).
        'coverage': {'granularity': granularity, 'shared_host': None, 'data_coverage': None},
        'dedup_key': dedup_key,
        'unmapped_summary': None,
        'truncated': False,
    }
    payload = {'integration': INTEGRATION_NAME, 'whisper': whisper}

    # A feed listing proves the node exists (you can't be listed without one); otherwise
    # node existence is confirmed by fetch_flags. Both are best-effort past the verdict.
    sources = explain_row.get('sources') or []
    flags: dict = {}
    known = bool(sources)
    if available:
        try:
            node = fetch_flags(cfg, ioc, ioc_type)  # None → no node
            known = known or node is not None
            flags = node or {}
        except (WhisperTransportError, WhisperQueryError) as exc:
            notes.append(f'flags unavailable ({exc.log_class})')  # known may still hold via sources
        whisper['known'] = known
        if known:
            whisper['graph_node_id'] = f'{granularity}/{ioc}'
            threat_feed = build_threat_feed(sources, flags)
            whisper['threat_feed'] = threat_feed
            whisper['tags'] = build_tags(flags, threat_feed['categories'])
            try:
                if ioc_type == 'domain':
                    whisper.update(build_domain_fragments(cfg, ioc, notes, trunc))
                else:
                    whisper.update(build_ip_fragments(cfg, ioc, ioc_type, flags, notes))
            except (WhisperTransportError, WhisperQueryError) as exc:
                # Context fragments are best-effort — keep the verdict + threat_feed.
                notes.append(f'context enrichment degraded ({exc.log_class})')

    if trunc:
        whisper['truncated'] = True
        notes.append(f'lists truncated: {", ".join(sorted(set(trunc)))}')

    whisper['verdict'] = derive_verdict(explain_row, flags, known)
    if notes:
        whisper['unmapped_summary'] = '; '.join(notes)
    # Strip nulls BEFORE the budget check so fit_payload measures the bytes actually sent
    # (nulls about to be deleted must not trigger spurious trimming at the boundary).
    payload = strip_nulls(payload)
    whisper = payload['whisper']  # strip_nulls returns new dicts — rebind before mutating
    fit_payload(payload, notes)  # may append further drop notes...
    if notes:  # ...so refresh the summary after fitting
        whisper['unmapped_summary'] = '; '.join(notes)
    return payload


def strip_nulls(value):
    """Recursively drop None values from the payload before it is framed.

    analysisd's JSON decoder stringifies every leaf, so a JSON `null` would index as the
    LITERAL keyword string "null" (verified live on 4.14.5 — issue #17). Nullable fields
    (asn.name, advisory, graph_node_id, unmapped_summary, whois.*, spf.redirect, coverage.*)
    are therefore OMITTED when unknown; empty lists are kept (stable structure, and they
    index as no-value, not as a string).
    """
    if isinstance(value, dict):
        return {k: strip_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [strip_nulls(v) for v in value if v is not None]
    return value


# ==========================================================================================
# #15 — persistent dedup cache (SQLite; mapping §7)
# ==========================================================================================
# integratord spawns this script PER matching alert, so an in-process cache never persists
# between alerts (mapping §7.5). The cache is an on-disk SQLite DB at DEDUP_DB, shared across
# invocations. Backend choice = SQLite (#12 Q2): stdlib, atomic commits, a busy_timeout so
# concurrent script processes serialize writes, and flush == delete the file.
#
# HARD CONSTRAINT — DO NOT enable `PRAGMA journal_mode=WAL`. The flush contract (`rm dedup.db*`)
# and per-commit durability both depend on the DEFAULT rollback journal: WAL would create
# persistent -wal/-shm sidecars that a bare flush wouldn't clear, and WAL's default
# synchronous=NORMAL drops the fsync-per-commit that lets the NEXT spawned process see a record.
#
# READ/WRITE split (concurrency): check_dedup is a bare SELECT (shared read lock only) so pure
# reads don't serialize against each other; pruning of expired rows happens in record_dedup,
# which already holds a write lock — keeping the write lock OFF the hot read path.
#
# Fail-OPEN: any cache error makes check_dedup return False (do not suppress) and record_dedup
# a silent no-op — a duplicate enrichment alert is far better than silently losing enrichment.
DEDUP_BUSY_TIMEOUT = 5.0  # seconds a write waits on a concurrent writer before "database is locked"


def _dedup_connect() -> 'sqlite3.Connection | None':
    """Open (creating the dir + schema) the dedup DB, or None when it is unavailable."""
    try:
        os.makedirs(os.path.dirname(DEDUP_DB), exist_ok=True)
        conn = sqlite3.connect(DEDUP_DB, timeout=DEDUP_BUSY_TIMEOUT)
        conn.execute('CREATE TABLE IF NOT EXISTS dedup (key TEXT PRIMARY KEY, ts REAL NOT NULL)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_dedup_ts ON dedup (ts)')  # for the prune
        return conn
    except (sqlite3.Error, OSError) as exc:
        debug(f'whisper: dedup cache unavailable ({exc})')
        return None


def check_dedup(key: str, ttl: int) -> bool:
    """True when `key` was recorded within `ttl` seconds → suppress this enrichment.

    Read-only (no prune) so it takes only a shared lock. `ttl <= 0` disables dedup. Fails OPEN
    (returns False) on any cache error. A future timestamp (`age < 0`, e.g. an NTP step-back) is
    treated as NOT-suppressed so a clock anomaly can never hold back a real enrichment.

    Best-effort, not exactly-once: two processes enriching the SAME IOC can both pass this check
    before either records, and both emit — a rare duplicate under concurrency. The race can only
    ever produce a duplicate, never suppress a legitimate first enrichment.
    """
    if ttl <= 0:
        return False
    conn = _dedup_connect()
    if conn is None:
        return False
    try:
        row = conn.execute('SELECT ts FROM dedup WHERE key = ?', (key,)).fetchone()
    except sqlite3.Error as exc:
        debug(f'whisper: dedup check failed ({exc})')
        return False
    finally:
        conn.close()
    if row is None:
        return False
    age = time.time() - row[0]
    return 0 <= age < ttl


def record_dedup(key: str, ttl: int = DEFAULT_DEDUP_TTL) -> None:
    """Record `key` at the current time (mapping §7.3 step 3) and prune rows older than `ttl`.

    Silent no-op on cache error. Called only AFTER a successful emit so failed enrichments stay
    retryable within the TTL — recording earlier would cache failures (TC-09/TC-12 interaction).
    Re-recording refreshes the timestamp; since duplicates are suppressed *before* emit, this
    only fires on a genuine (first or post-expiry) emit — effectively one emit per TTL window,
    reset at each emit.
    """
    conn = _dedup_connect()
    if conn is None:
        return
    try:
        now = time.time()
        with conn:  # single write transaction: prune (housekeeping) + upsert
            if ttl > 0:
                conn.execute('DELETE FROM dedup WHERE ts < ?', (now - ttl,))
            conn.execute('INSERT OR REPLACE INTO dedup (key, ts) VALUES (?, ?)', (key, now))
    except sqlite3.Error as exc:
        debug(f'whisper: dedup record failed ({exc})')
    finally:
        conn.close()


# ==========================================================================================
# #16 — analysisd socket write-back (mapping §2.3)
# ==========================================================================================
def frame_event(payload: dict, agent: 'dict | None') -> str:
    """Frame the enrichment event for the analysisd queue socket (mapping §2.3).

    Form A (manager/local — agent absent or id '000'):  `1:custom-whisper:<json>`
    Form B (real originating agent — Q3 decision):        `1:<location>-><name>:<json>`
      where location = `[<id>] (<name>) <ip|any>`, then `.replace('|','||').replace(':','|:')`
      so colons/pipes inside it can't collide with the `1:...:` framing delimiters.

    The leading `1` is the analysisd queue message type (a location-prefixed event). Compact
    JSON separators keep the datagram small; no trailing newline.
    """
    body = json.dumps(payload, separators=(',', ':'))
    if not agent or str(agent.get('id')) == '000':
        return f'1:{INTEGRATION_NAME}:{body}'
    location = f'[{agent.get("id")}] ({agent.get("name")}) {agent.get("ip") or "any"}'
    location = location.replace('|', '||').replace(':', '|:')
    return f'1:{location}->{INTEGRATION_NAME}:{body}'


def send_event(payload: dict, alert_agent: 'dict | None') -> int:
    """Frame + send the enrichment event to the analysisd socket; returns bytes sent.

    Stamps the alert onto the originating agent (Form B, #12 Q3). Socket-layer failures
    (missing socket, connect refused, errno 90 oversize) raise WhisperSocketError so
    main()'s error taxonomy handles them uniformly (never an unhandled traceback).
    """
    encoded = frame_event(payload, alert_agent).encode('utf-8')
    # Two independent ceilings: enrich() budgets the JSON body to ~60 KB (MAX_PAYLOAD_BYTES +
    # FRAMING_MARGIN); this guard is the datagram hard limit (65535). fit_payload may still
    # return an over-budget core payload tagged `payload_too_large`, so re-check here.
    if len(encoded) > MAX_EVENT_SIZE:
        raise WhisperSocketError(f'framed event {len(encoded)}B exceeds {MAX_EVENT_SIZE}B (errno 90)')
    try:
        # socket() is inside the try so an fd-exhaustion (EMFILE) OSError at construction is
        # mapped to WhisperSocketError too — never an unhandled traceback.
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            sock.connect(SOCKET_ADDR)
            sock.send(encoded)
        finally:
            sock.close()
    except OSError as exc:
        raise WhisperSocketError(f'analysisd socket send failed at {SOCKET_ADDR}: {exc}') from exc
    return len(encoded)


# --- entry point --------------------------------------------------------------------------
def main(args: 'list[str]') -> int:
    global debug_enabled

    if len(args) < 4:
        log_always('# Error: Wrong arguments')
        return ERR_BAD_ARGUMENTS
    debug_enabled = len(args) > DEBUG_INDEX and args[DEBUG_INDEX] == 'debug'

    # Mirror stock get_json_alert(): missing file and corrupt JSON are distinct
    # failures with distinct exit codes (6 vs 7) for standard Wazuh triage.
    try:
        alert = load_alert(args[ALERT_INDEX])
    except FileNotFoundError:
        log_always(f'# Error: Alert file not found: {args[ALERT_INDEX]}')
        return ERR_FILE_NOT_FOUND
    except json.JSONDecodeError as exc:
        log_always(f'# Error: Invalid alert JSON: {exc}')
        return ERR_INVALID_JSON

    if is_self_alert(alert):
        # Loop guard #3 (after the integration filter + rule-group separation) — mapping §8.
        log_skip('self-alert')
        return 0

    # Extraction runs before any config I/O so no-IOC alerts exit without touching
    # the options/key files (the common case under broad rule filters).
    candidates = extract_iocs(alert)
    if not candidates:
        return 0

    options = load_options(args[OPTIONS_INDEX] if len(args) > OPTIONS_INDEX else '')
    api_url = resolve_api_url(options, os.environ)
    dedup_ttl = resolve_dedup_ttl(options, os.environ)
    include_agent = resolve_dedup_scope(options, os.environ)
    api_key = resolve_api_key(args[APIKEY_INDEX] if len(args) > APIKEY_INDEX else '', os.environ)
    timeout = _argv_int(args, TIMEOUT_INDEX, DEFAULT_TIMEOUT)
    retries = _argv_int(args, RETRIES_INDEX, DEFAULT_RETRIES)
    agent_id = str(get_nested(alert, 'agent.id') or '000')

    emitted = 0
    errors = 0
    for ioc, ioc_type, field_path in candidates:
        key = make_dedup_key(ioc_type, ioc, agent_id, include_agent)
        log_invoke(ioc, ioc_type, key)
        if check_dedup(key, dedup_ttl):
            log_skip('dedup', dedup_key=key)
            continue
        try:
            payload = enrich(
                ioc, ioc_type, key, build_source_ref(alert, field_path), api_url, api_key, timeout, retries
            )
            sent = send_event(payload, alert.get('agent'))
            record_dedup(key, dedup_ttl)  # only after a successful emit — failures stay retryable
            log_emit(key, sent)
            emitted += 1
        except WhisperAuthError as exc:
            # Terminal: the same key fails for every remaining candidate — stop the run.
            log_error(exc)
            return ERR_AUTH
        except WhisperError as exc:
            log_error(exc)
            errors += 1

    # Exit 0 when anything landed (TC-15: a successful emit must not produce an
    # 'Exit status was:' line in ossec.log); non-zero only for all-failure runs (TC-13).
    return 0 if emitted or not errors else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
