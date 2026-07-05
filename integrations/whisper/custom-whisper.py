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

Scaffold status (#13): extraction, guards, config resolution and logging are complete;
the enrichment client (#14), dedup cache (#15) and socket write-back (#16) are seams
that raise/no-op until their issues land. The seam signatures carry everything the
mapping-§4.2 envelope needs (source_ref, dedup_key), so those issues slot in without
rewriting main().
"""

import ipaddress
import json
import os
import re
import sys
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
ERR_NOT_IMPLEMENTED = 10  # scaffold seams — removed as #14/#15/#16 land

INTEGRATION_NAME = 'custom-whisper'

# Wazuh home is one level up from integrations/. realpath (not abspath) so a symlinked
# install still resolves inside /var/ossec — mirrors the stock virustotal.py idiom.
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f'{pwd}/logs/integrations.log'
KEY_FILE = f'{pwd}/etc/whisper.key'
SOCKET_ADDR = f'{pwd}/queue/sockets/queue'
DEDUP_DB = f'{pwd}/var/whisper/dedup.db'  # normative path — mapping §7.5

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


# --- seams for the follow-up issues ------------------------------------------------------
def check_dedup(key: str, ttl: int) -> bool:
    """True when `key` was recorded within `ttl` seconds → suppress this enrichment.

    Seam for #15: the persistent, flushable cache at DEDUP_DB (mapping §7.5).
    The scaffold never suppresses.
    """
    return False


def record_dedup(key: str) -> None:
    """Record `key` with a timestamp (mapping §7.3 step 3). Seam for #15.

    Called only AFTER a successful emit so failed enrichments stay retryable within
    the TTL — recording earlier would cache failures (TC-09/TC-12 interaction).
    """


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

    Seam for #14. The signature deliberately carries everything the mapping-§4.2
    envelope needs (dedup_key + source_ref linkage) so #14 lands without touching main().
    """
    raise NotImplementedError('enrichment client lands with #14')


def send_event(payload: dict, alert_agent: 'dict | None') -> int:
    """Frame + send the enrichment event to the analysisd socket; returns bytes sent.

    Seam for #16 (Form A/B framing per mapping §2.3 — pending #12 Q3). Socket-layer
    failures raise WhisperSocketError so main()'s taxonomy handling stays uniform.
    """
    raise NotImplementedError('socket write-back lands with #16')


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
            record_dedup(key)  # only after a successful emit — failures stay retryable
            log_emit(key, sent)
            emitted += 1
        except WhisperAuthError as exc:
            # Terminal: the same key fails for every remaining candidate — stop the run.
            log_error(exc)
            return ERR_AUTH
        except WhisperError as exc:
            log_error(exc)
            errors += 1
        except NotImplementedError as exc:
            log_always(f'# Error: scaffold seam not implemented: {exc}')
            return ERR_NOT_IMPLEMENTED

    # Exit 0 when anything landed (TC-15: a successful emit must not produce an
    # 'Exit status was:' line in ossec.log); non-zero only for all-failure runs (TC-13).
    return 0 if emitted or not errors else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
