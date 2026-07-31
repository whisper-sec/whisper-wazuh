# Changelog

All notable changes to whisper-wazuh. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions are [semver](https://semver.org/).

## [Unreleased]

## [1.1.0] — 2026-07-31

Adds the **keyed tier** — the agent-activity log source — alongside the v1.0.0 enrichment
connector, and clarifies the keyless/keyed model across the docs. The enrichment path is
unchanged; the log source is opt-in (`install.sh --logs`).

### Added

- **Agent-activity log source** (`whisper-logs`, the *keyed* tier) — an opt-in (`install.sh --logs`)
  scheduled poller that pulls a tenant's own agent activity from the Whisper control plane (`op:logs`)
  and writes it into Wazuh as `data.whisper_agent.*` alerts: DNS allow/refused, egress connections,
  and identity allocation. Runs from a 60s `command`-wodle into a JSON spool (or the analysisd socket),
  keeps an incremental cursor, and raises a **telemetry-gap alert** (rule 100215) when a poll truncates
  its window rather than dropping rows silently. New rules `whisper_agent_rules.xml` (100210–100215,
  group `whisper_agent_activity` — disjoint from enrichment, no feedback loop). Reuses the connector's
  Whisper client / auth / dedup DB / socket via import — one client, one key, one cache; the enrichment
  path is unchanged. Configurable via `WHISPER_LOGS_*`. Docs: [installation](docs/installation.md#the-agent-activity-log-source---logs),
  [architecture](docs/architecture.md#the-agent-activity-log-source-the-keyed-tier), and mapping §14.

## [1.0.0] — 2026-07-27

First release — a Wazuh integration that enriches alerts with context from the Whisper
infrastructure graph. Tested on **Wazuh 4.14.5**; stdlib-only Python 3.10 (the manager's bundled
interpreter); bring your own Whisper API key.

### Added

- **Per-alert connector** (`custom-whisper`) — extracts network IOCs from matching alerts,
  enriches them against the Whisper graph, and writes back an evidence-graded enrichment alert via
  the analysisd socket (Pattern A, like the built-in VirusTotal integration). The verdict is
  derived from *evidence* (feed categories + node flags), never copied from the raw score —
  "trust never overrides threat".
- **Enrichment fields** (`data.whisper.*`) — verdict, risk_score, level, threat_feed, tags,
  ASN + reputation, prefix + registered-prefix threat, geo; for domains also DNS / WHOIS / SPF /
  web-links / lookalike variants. Confirmed-malicious node flags (C2 / malware / phishing / …)
  derive `known_bad`. Opt-in `tls_fingerprint` (Cobalt-Strike JARM → rule 100206).
- **Rules** (`whisper_rules.xml`) mapping the verdict to an alert level; the **indexer template**
  typing `data.whisper.*` (analysisd stringifies everything); a **SQLite dedup** cache so an
  indicator isn't re-looked-up on every alert within a TTL.
- **On-demand CLI** (`whisper-investigate`) — runs heavy Whisper *workflows* (e.g. the 81-step
  Threat Investigation) via the Whisper MCP server and prints a Markdown/JSON report.
- **install.sh / uninstall.sh** — safe, idempotent install (indexer template PUT, `ossec.conf`
  patch with rollback, restart + verify). `--api-key-file` provisions the API key from a file
  (never on a command line); `--group` selects the trigger rule groups.
- **Distribution** — a one-line `bootstrap.sh` installer, versioned release tarballs, and `.deb` /
  `.rpm` packages (built with `nfpm`) that stage the bundle for `apt`/`yum` and config management.
  A tagged `v*` push builds all of them, with `SHA256SUMS`, into a GitHub Release.
- **Tests & CI** — 236 unit tests + `ruff`, run on every PR (Python 3.10 & 3.12); an end-to-end
  acceptance runner (`tests/e2e/run_acceptance.py`, `make dev-acceptance`) exercising TC-01..TC-22
  against a live single-node stack.
- **Docs** — [architecture](docs/architecture.md), an
  [installation & configuration guide](docs/installation.md), the
  [Whisper→Wazuh mapping](docs/whisper-to-wazuh-mapping.md), the
  [acceptance criteria](docs/mvp-acceptance-criteria.md), and a captured
  [scenario](docs/scenarios/01-tor-ip-enrichment.md).

[Unreleased]: https://github.com/whisper-sec/whisper-wazuh/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/whisper-sec/whisper-wazuh/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/whisper-sec/whisper-wazuh/releases/tag/v1.0.0