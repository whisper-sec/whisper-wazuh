# Changelog

All notable changes to whisper-wazuh. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions are [semver](https://semver.org/).

## [Unreleased]

## [1.2.0] — 2026-09-10

Hardens the enrichment connector after the `wazuh/integrations` maintainer review, moves the rule
IDs out of the crowded `1002xx` band, and aligns the licence metadata with the MIT relicense.
**Upgrading from 1.1.0 changes rule IDs**; see the notes under each item.

### Changed

The first two changes come from the maintainer review of the `wazuh/integrations` submission.

- **Rule IDs moved out of the `100200`–`100249` band.** Enrichment is now `100500`–`100506` and
  the agent-activity log source `100510`–`100515`: a uniform `+300` shift, structure and levels
  unchanged. The old band collided with three integrations already in `wazuh/integrations`
  (`1password`, `socradar_ti_feeds`, `endian_mercury_utm`) and with the `100200` starting point
  Wazuh's own custom-rules docs use. analysisd keeps only the first rule carrying a duplicated ID
  and silently drops the rest, so a colliding ruleset stopped working with nothing but a line in
  `ossec.log`. **Upgrading:** re-run `install.sh` with the same flags as the original install
  (add `--logs` if the log source is installed, or its old `100210`–`100215` rules stay on disk),
  re-add any `<options>` you had (the installer re-renders the block), and repoint dashboards or
  saved searches keyed on the old IDs — see [Upgrading](docs/installation.md#upgrading).
- **A wall-clock budget for the synchronous integratord callout.** integratord runs integrations
  serially, one alert at a time, and nothing bounded the total: up to nine queries per IOC, several
  IOCs per alert, each with three retries under a 60 s backoff cap. An unreachable API measured
  87 s per alert and a rate-limited one 180 s, with every other integration blocked behind it. Now
  one per-invocation `deadline` (`<options>`, default `20` s) is checked before every IOC and
  threaded into every query, so per-request timeouts and retry backoff shrink to what is left and
  a retry never sleeps past it; a SIGALRM hard ceiling at deadline + 1 s backs that up when a
  socket operation itself stalls (a dripping response, a hung resolver); the backoff cap is `5` s;
  and `max_iocs` (default `5`) bounds enrichment work per alert (cache hits do not count). An
  outage now costs seconds: measured live on integratord, a two-IOC alert against a blackholed API
  took 22 s (was 87 s) and against a 429 + `Retry-After: 60` server 17.5 s (was 180 s for one IOC).
  New skip reasons `deadline` and `max-iocs`; a context query cut by the deadline notes
  `context skipped (deadline)` and the verdict is kept.
- **Licence metadata says MIT everywhere.** The project was relicensed from Apache-2.0 to MIT
  (matching the Whisper SDKs; still GPLv2-compatible), but only `LICENSE` changed at the time. The
  package metadata (`.deb`/`.rpm`), the README, CONTRIBUTING and the `wazuh/integrations`
  submission notes now say MIT too, and the three script headers defer to the repository's
  `LICENSE` instead of naming a licence (the copy contributed to `wazuh/integrations` is under that
  repository's AGPL-3.0, and a header naming MIT there was misleading).

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

[Unreleased]: https://github.com/whisper-sec/whisper-wazuh/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/whisper-sec/whisper-wazuh/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/whisper-sec/whisper-wazuh/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/whisper-sec/whisper-wazuh/releases/tag/v1.0.0