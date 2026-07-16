#!/usr/bin/env python3
"""whisper-investigate — analyst-triggered on-demand Whisper investigation (Pattern A / #33).

Runs a heavy Whisper *workflow* (a multi-step investigation, e.g. the 81-step `indicator`
Threat Investigation) against one IOC and writes a Markdown or JSON report. Unlike the
per-alert connector (custom-whisper.py), this is invoked by an ANALYST on demand — not by
integratord — so it takes flags and prints a report rather than injecting an alert.

Transport: Whisper workflows are NOT on the REST /api/query surface — they run only via the
MCP server (mcp.whisper.security) over MCP Streamable-HTTP JSON-RPC (initialize →
notifications/initialized → tools/call run_workflow). This module speaks that protocol with
the stdlib, reusing whisper_client for the TLS context, the WAF-safe transport and the auth /
error taxonomy. Verified live 2026-07-14.

Runtime: the manager's bundled Python (3.10) — stdlib only. Installs alongside the connector
in /var/ossec/integrations/ (whisper_client.py is its sibling on sys.path[0]).

Usage:
  whisper-investigate <ioc> [--workflow SLUG] [--format md|json] [--out FILE]
                            [--api-key KEY] [--mcp-url URL] [--timeout SECONDS] [--verbose]
"""

import argparse
import http.client
import json
import os
import sys
import time
import urllib.error

from whisper_client import (
    API_KEY_PLACEHOLDER,
    WhisperAuthError,
    WhisperError,
    WhisperQueryError,
    WhisperTransportError,
    _http_post,
    classify_domain,
    parse_ip,
    resolve_api_key,
)

VERSION = '0.1'
# The WAF blocks urllib's default UA on both hosts; use our own (whisper_client's rule).
USER_AGENT = f'whisper-investigate/{VERSION}'
DEFAULT_MCP_URL = 'https://mcp.whisper.security/'
MCP_PROTOCOL_VERSION = '2025-06-18'
DEFAULT_WORKFLOW = 'indicator'
# A heavy workflow blocks 13-23s (indicator, live); default well above that.
DEFAULT_TIMEOUT = 90

# Exit codes — 2 (argparse), 3 bad IOC, 8 terminal auth (mirrors the connector's ERR_AUTH), 1 other.
ERR_BAD_IOC = 3
ERR_AUTH = 8
ERR_GENERAL = 1

# Investigation-oriented workflows; slug -> human title for the report H1. Any other slug is
# still accepted (the MCP server validates it) and titled by its slug.
WORKFLOWS = {
    'indicator': 'Threat Investigation',
    'indicator-enrichment': 'Indicator Enrichment',
    'attack-surface': 'Attack-Surface Mapper',
    'typosquat': 'Typosquat & Brand-Impersonation Scan',
    'subdomain-takeover': 'Subdomain Takeover Detection',
    'bgp-hijack-exposure': 'BGP Hijack & Routing-Hygiene Audit',
    'build-takedown-evidence-package': 'Takedown Evidence Package',
    'infrastructure-mapping': 'Digital Infrastructure Mapping',
    'supply-chain': 'Supply-Chain Dependency Mapping',
    'nameserver-hijack-dns-consistency': 'Nameserver & DNS Delegation Audit',
    'route-health': 'Network & Routing Report',
}

_SEV_BADGE = {
    'error': '🔴',
    'warning': '🟠',
    'info': '🔵',
    'critical': '🔴',
    'high': '🟠',
    'medium': '🟡',
    'low': '🔵',
}


def log_verbose(enabled: bool, msg: str) -> None:
    if enabled:
        print(f'whisper-investigate: {msg}', file=sys.stderr)


# --- IOC detection ------------------------------------------------------------------------
def detect_ioc_type(ioc: str) -> 'tuple[str, str] | None':
    """(normalized_ioc, 'ipv4'|'ipv6'|'domain') or None when it isn't a recognizable IOC.

    Reuses the connector's IOC primitives but NOT its is_global guard — an analyst may
    deliberately investigate a private/reserved address, so we don't reject those here.
    """
    ip = parse_ip(ioc)
    if ip is not None:
        return str(ip), ('ipv4' if ip.version == 4 else 'ipv6')
    domain = classify_domain(ioc)
    if domain is not None:
        return domain, 'domain'
    return None


# --- MCP Streamable-HTTP JSON-RPC client --------------------------------------------------
def _parse_jsonrpc(raw: bytes, resp_headers: dict, want_id: 'int | None') -> dict:
    """One JSON-RPC object from an MCP response — the body is EITHER application/json (one
    object) OR text/event-stream (SSE frames `data: {...}`), so handle both and pick the
    frame whose id matches the request."""
    text = raw.decode('utf-8', 'replace')
    ct = resp_headers.get('content-type', '')
    # Dispatch on the content-type ONLY — a JSON body can legitimately contain the substring
    # "data:" (e.g. "Metadata: ..." or a data: URI), and scanning for it would misroute a valid
    # JSON response to the SSE parser and silently drop it. JSON is the default; SSE is used only
    # when the header says so (or as a last-resort fallback if a JSON parse fails but data: frames
    # are present — a server that sent SSE without the header).
    if 'text/event-stream' not in ct:
        stripped = text.strip()
        if not stripped:
            return {}  # e.g. a 202 for the initialized notification
        try:
            return json.loads(stripped)
        except ValueError:
            if 'data:' not in text:
                raise WhisperQueryError('non-JSON MCP response body') from None
            # else: fall through and try SSE framing
    objs = []
    for line in text.splitlines():
        if line.startswith('data:'):
            chunk = line[5:].strip()
            if chunk:
                try:
                    objs.append(json.loads(chunk))
                except ValueError:
                    pass
    for obj in objs:
        if isinstance(obj, dict) and obj.get('id') == want_id:
            return obj
    return objs[-1] if objs else {}


def _result_text(result: dict) -> str:
    content = result.get('content')
    if isinstance(content, list) and content and isinstance(content[0], dict):
        return str(content[0].get('text', ''))
    return ''


def run_workflow(
    mcp_url: str, api_key: str, slug: str, ioc: str, timeout: int, verbose: bool = False
) -> dict:
    """Run one workflow via MCP and return the normalized run envelope (results[0]).

    Raises WhisperAuthError (401/403), WhisperTransportError (network / 5xx), or
    WhisperQueryError (JSON-RPC error, tool error, malformed body).
    """
    # The X-API-Key is sent to whatever --mcp-url names; refuse plain HTTP so the key can never
    # go out in cleartext (an analyst pointing --mcp-url at http://attacker would else leak it).
    if not mcp_url.lower().startswith('https://'):
        raise WhisperError(f'refusing to send the API key over a non-HTTPS URL: {mcp_url}')
    session = {'id': None}

    def call(payload: dict, want_id: 'int | None') -> dict:
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'X-API-Key': api_key,
            'User-Agent': USER_AGENT,
            'MCP-Protocol-Version': MCP_PROTOCOL_VERSION,
        }
        if session['id']:
            headers['Mcp-Session-Id'] = session['id']
        started = time.monotonic()
        try:
            status, raw, resp_headers = _http_post(mcp_url, payload, headers, timeout)
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            raise WhisperTransportError(f'MCP transport error: {exc}') from exc
        log_verbose(
            verbose,
            f'{payload.get("method")} -> HTTP {status} ({int((time.monotonic() - started) * 1000)}ms)',
        )
        if resp_headers.get('mcp-session-id'):
            session['id'] = resp_headers['mcp-session-id']
        if status in (401, 403):
            raise WhisperAuthError(f'HTTP {status} from MCP server (check --api-key)')
        if status >= 500:
            raise WhisperTransportError(f'HTTP {status} from MCP server')
        if status >= 400:
            raise WhisperQueryError(f'HTTP {status} from MCP server: {raw[:300].decode("utf-8", "replace")}')
        return _parse_jsonrpc(raw, resp_headers, want_id)

    def check_rpc(obj: dict) -> None:
        if isinstance(obj.get('error'), dict):
            err = obj['error']
            raise WhisperQueryError(f'MCP error {err.get("code")}: {err.get("message")}')

    # 1) initialize — capture the session id from the response header
    check_rpc(
        call(
            {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'initialize',
                'params': {
                    'protocolVersion': MCP_PROTOCOL_VERSION,
                    'capabilities': {},
                    'clientInfo': {'name': 'whisper-investigate', 'version': VERSION},
                },
            },
            1,
        )
    )
    # 2) initialized notification (no id / no result body expected)
    call({'jsonrpc': '2.0', 'method': 'notifications/initialized'}, None)
    # 3) tools/call run_workflow — the blocking run
    resp = call(
        {
            'jsonrpc': '2.0',
            'id': 2,
            'method': 'tools/call',
            'params': {
                'name': 'run_workflow',
                'arguments': {
                    'runs': [{'slug': slug, 'input': ioc}],
                    'format': 'compact',
                    'output': {'emit': 'query-only', 'slices': ['summary', 'details', 'lede', 'evidence']},
                },
            },
        },
        2,
    )
    check_rpc(resp)
    result = resp.get('result') or {}
    if result.get('isError'):
        raise WhisperQueryError(f'workflow returned an error: {_result_text(result)[:300]}')
    # The report envelope is structuredContent, or the stringified envelope in content[0].text.
    # Guard EVERY server-supplied shape with isinstance — a non-dict (array/scalar) must raise a
    # clean WhisperQueryError, never an AttributeError that escapes main() as a traceback.
    envelope = result.get('structuredContent')
    if not isinstance(envelope, dict):
        try:
            parsed = json.loads(_result_text(result))
            envelope = parsed if isinstance(parsed, dict) else None
        except ValueError:
            envelope = None
    runs = envelope.get('results') if isinstance(envelope, dict) else None
    if not isinstance(runs, list) or not runs:
        raise WhisperQueryError('MCP returned no workflow results')
    run = runs[0]
    if not isinstance(run, dict):
        raise WhisperQueryError('MCP returned a malformed workflow result')
    return {'run': run, 'references': envelope.get('references', {}), 'quota': envelope.get('quota', {})}


# --- report rendering ---------------------------------------------------------------------
def _headline(text: str) -> 'tuple[str, str]':
    """Split a summary fact 'Headline: explanation' into (bold headline, rest)."""
    head, sep, rest = str(text).partition(': ')
    return (head, rest) if sep else (text, '')


_TABLE_ROW_CAP = 50


def _render_view(view: dict, out: list) -> None:
    # Every list field uses `or []` (not `.get(k, [])`): the workflow orchestrator can emit a
    # JSON `null` for an empty field, and iterating None would crash the whole report.
    if not isinstance(view, dict):
        return
    kind = view.get('kind')
    if kind == 'stats':
        for item in view.get('items') or []:
            hint = f" _{item['hint']}_" if item.get('hint') else ''
            out.append(f"- **{item.get('label', '')}:** {item.get('value', '')}{hint}")
    elif kind == 'coverage':
        if view.get('caption'):
            out.append(f"_{view['caption']}_")
        for chk in view.get('checks') or []:
            mark = '✓' if chk.get('state') == 'present' else '✗'
            note = f" — {chk['note']}" if chk.get('note') else ''
            out.append(f"- {mark} {chk.get('label', '')}{note}")
    elif kind == 'findings':
        for f in view.get('items') or []:
            badge = _SEV_BADGE.get(str(f.get('severity', '')).lower(), '•')
            out.append(f"- {badge} **{f.get('title', '')}** — {f.get('detail', '')}")
            if f.get('fix'):
                out.append(f"  - _Fix:_ {f['fix']}")
    elif kind == 'table':
        cols = view.get('columns') or []
        rows = view.get('rows') or []
        if cols:
            out.append('| ' + ' | '.join(str(c) for c in cols) + ' |')
            out.append('| ' + ' | '.join('---' for _ in cols) + ' |')
            for row in rows[:_TABLE_ROW_CAP]:
                out.append('| ' + ' | '.join(str(c) for c in (row or [])) + ' |')
            if len(rows) > _TABLE_ROW_CAP:  # never silently drop evidence rows
                out.append(f'_… {len(rows) - _TABLE_ROW_CAP} more row(s) not shown (use --format json)_')
    else:  # unknown kind — never crash; dump defensively
        out.append('```json')
        out.append(json.dumps(view, indent=2, ensure_ascii=False)[:2000])
        out.append('```')


def render_markdown(payload: dict, ioc: str, slug: str) -> str:
    # Every optional field is guarded and every list uses `or []` — the report must render (or
    # degrade gracefully) for ANY server-supplied shape, incl. JSON nulls and non-dict elements,
    # rather than crash main() with a traceback.
    run = payload.get('run') or {}
    derived = run.get('derived') or {}
    title = WORKFLOWS.get(slug, slug)
    cov = run.get('coverage') or {}  # null-safe (a JSON null coverage must not crash the meta line)
    out = [f'# Whisper Investigation: {ioc}', '']
    meta = f'**{title}** · {cov.get("stepsTotal", "?")} steps'
    if run.get('totalLatencyMs') is not None:
        meta += f' · {run["totalLatencyMs"]} ms'
    if run.get('complete') is False:
        meta += ' · ⚠️ INCOMPLETE'
    out.append(meta)
    lede = derived.get('lede')
    if isinstance(lede, dict):  # some workflows (indicator) return {text, evidence}
        lede = lede.get('text', '')
    if isinstance(lede, str) and lede.strip():
        out += ['', lede]

    verdict = derived.get('verdict')
    if isinstance(verdict, dict):
        score = verdict.get('score', 0)
        score_str = f'{score:.2f}' if isinstance(score, (int, float)) else score
        out += ['', f"## Verdict: {verdict.get('level', 'NONE')} (score {score_str})"]
        for factor in verdict.get('factors') or []:
            out.append(f"- {factor.get('label', '')}" if isinstance(factor, dict) else f'- {factor}')
        if verdict.get('sources'):
            out.append(f"- _sources: {', '.join(str(s) for s in verdict['sources'])}_")

    summary = derived.get('summary') or []
    if summary:
        out += ['', '## Summary']
        for fact in summary:
            if not isinstance(fact, dict):
                continue
            badge = _SEV_BADGE.get(str(fact.get('severity', '')).lower(), '•')
            head, rest = _headline(fact.get('text', ''))
            out.append(f'- {badge} **{head}**' + (f' — {rest}' if rest else ''))

    details = [s for s in (derived.get('details') or []) if isinstance(s, dict)]
    for section in sorted(details, key=lambda s: (str(s.get('group', '')), s.get('order', 0) or 0)):
        out += ['', f"## {section.get('title', 'Section')}"]
        if section.get('description'):
            out.append(f"> {section['description']}")
        for view in section.get('views') or []:
            _render_view(view, out)

    if cov:
        out += [
            '',
            '## Coverage',
            f"{cov.get('stepsWithData', 0)}/{cov.get('stepsTotal', 0)} steps returned data "
            f"({cov.get('stepsEmpty', 0)} empty, {cov.get('stepsSkipped', 0)} skipped, "
            f"{cov.get('stepsError', 0)} error). No-data is not proof of benign.",
        ]

    evidence = derived.get('evidence') or []
    if evidence:
        out += ['', '## Evidence']
        for ev in evidence:
            if not isinstance(ev, dict):
                continue
            prov = ev.get('provenance') or {}
            out.append(f"- **{ev.get('id', '')}** ({prov.get('rowCount', 0)} rows): {ev.get('fact', '')}")
            if prov.get('query'):
                out.append(f"  ```cypher\n  {prov['query']}\n  ```")
    out.append('')
    return '\n'.join(out)


def render_json(payload: dict, ioc: str, slug: str) -> str:
    run = payload['run']
    return json.dumps(
        {
            'ioc': ioc,
            'workflow': slug,
            'complete': run.get('complete'),
            'total_latency_ms': run.get('totalLatencyMs'),
            'coverage': run.get('coverage'),
            'derived': run.get('derived'),
            'references': payload.get('references'),
        },
        indent=2,
        ensure_ascii=False,
    )


# --- CLI ----------------------------------------------------------------------------------
def resolve_cli_key(flag_key: 'str | None', environ: dict) -> 'str | None':
    """Flag-first for a CLI (an explicit --api-key must win), then env → key file."""
    if flag_key:
        flag_key = flag_key.strip()
        if flag_key and flag_key != API_KEY_PLACEHOLDER:
            return flag_key
    return resolve_api_key('', environ)  # env → key file


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='whisper-investigate',
        description='Run a Whisper investigation workflow against an IOC and print a report.',
    )
    p.add_argument('ioc', help='the indicator to investigate (IP, IPv6, or domain)')
    p.add_argument(
        '--workflow',
        default=DEFAULT_WORKFLOW,
        help=f'workflow slug (default: {DEFAULT_WORKFLOW}). Known: {", ".join(sorted(WORKFLOWS))}',
    )
    p.add_argument('--format', choices=('md', 'json'), default='md', help='report format (default: md)')
    p.add_argument('--out', help='write the report to FILE instead of stdout')
    p.add_argument('--api-key', help='Whisper API key (else $WHISPER_API_KEY, else the key file)')
    p.add_argument(
        '--mcp-url',
        default=os.environ.get('WHISPER_MCP_URL', DEFAULT_MCP_URL),
        help=f'MCP server URL (default: {DEFAULT_MCP_URL})',
    )
    p.add_argument(
        '--timeout',
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f'per-call HTTP timeout, seconds (default: {DEFAULT_TIMEOUT})',
    )
    p.add_argument('--verbose', action='store_true', help='log request timing to stderr')
    return p


def main(argv: 'list[str]') -> int:
    args = build_parser().parse_args(argv)

    detected = detect_ioc_type(args.ioc)
    if detected is None:
        print(f'whisper-investigate: not a recognizable IOC (IP or domain): {args.ioc}', file=sys.stderr)
        return ERR_BAD_IOC
    ioc, _ioc_type = detected

    api_key = resolve_cli_key(args.api_key, os.environ)
    if not api_key:
        print(
            'whisper-investigate: no API key (pass --api-key, set $WHISPER_API_KEY, or the key file)',
            file=sys.stderr,
        )
        return ERR_AUTH

    try:
        payload = run_workflow(args.mcp_url, api_key, args.workflow, ioc, args.timeout, args.verbose)
    except WhisperAuthError as exc:
        print(f'whisper-investigate: authentication failed — {exc}', file=sys.stderr)
        return ERR_AUTH
    except WhisperError as exc:
        print(f'whisper-investigate: {exc}', file=sys.stderr)
        return ERR_GENERAL

    report = (
        render_json(payload, ioc, args.workflow)
        if args.format == 'json'
        else render_markdown(payload, ioc, args.workflow)
    )
    if args.out:
        try:
            with open(args.out, 'w') as f:
                f.write(report + ('\n' if not report.endswith('\n') else ''))
        except OSError as exc:
            print(f'whisper-investigate: cannot write {args.out}: {exc}', file=sys.stderr)
            return ERR_GENERAL
        print(f'whisper-investigate: report written to {args.out}', file=sys.stderr)
    else:
        print(report)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
