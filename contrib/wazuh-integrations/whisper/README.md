# Wazuh – Whisper Threat-Intelligence Enrichment Integration

Enrich Wazuh alerts with relationship context from the [Whisper](https://www.whisper.security)
infrastructure graph — the internet modeled as one connected graph (ASNs, prefixes, DNS, WHOIS,
threat feeds, Tor relays, TLS fingerprints). When an alert carries a public IP or domain, this
integration asks the graph what it knows and writes the answer back into Wazuh as a new,
evidence-graded alert.

> **This is the enrichment tier — it needs no API key** (the Whisper graph is queried anonymously).
> Whisper also ships a *keyed* tier (an agent-activity log source) and an on-demand investigation
> CLI, plus packaged installers (`.deb`/`.rpm`, a one-line bootstrap). Those live in the upstream
> project — see [Beyond enrichment](#beyond-enrichment--the-keyed-tier) and
> **https://github.com/whisper-sec/whisper-wazuh**.

## Table of Contents

- [Introduction](#introduction)
- [Verdict → alert level](#verdict--alert-level)
- [Installation and Configuration](#installation-and-configuration)
- [Wazuh Configuration](#wazuh-configuration)
  - [Integrator Config (manager `ossec.conf`)](#integrator-config-manager-ossecconf)
  - [Custom Rules](#custom-rules)
  - [Manual Tests](#manual-tests)
- [Beyond enrichment — the keyed tier](#beyond-enrichment--the-keyed-tier)
- [Sources](#sources)

## Introduction

This integration:

- Extracts a **public IP or domain** from matching Wazuh alerts (flexible field-path detection across
  `data.srcip`, Suricata/Cloudflare/GuardDuty/Security-Lake paths, etc.).
- Queries the **Whisper graph** (`POST https://graph.whisper.security/api/query`) for an
  evidence-based threat verdict — **no API key required** for these graph lookups.
- Derives the **verdict from evidence** (threat-feed categories + confirmed-malicious node flags),
  never copied from the raw score — *"trust never overrides threat."*
- Writes back a new alert under `data.whisper.*`: verdict, risk score, level, threat feeds, tags,
  ASN + reputation, prefix + registered-prefix threat, geo; for domains also DNS / WHOIS / SPF /
  web-links / lookalike variants.
- Links each enrichment to its triggering alert via `source_ref`, and de-duplicates repeat
  indicators with a small SQLite cache (no re-lookup within a TTL).
- Handles API / transport / auth errors gracefully, emitting typed error alerts rather than crashing.

## Verdict → alert level

The verdict is evidence-derived and mapped to a Wazuh alert level by the bundled rules
(`whisper_rules.xml`):

| Verdict | Meaning | Rule | Level |
|---|---|---|---|
| `known_bad` | confirmed-malicious evidence (C2 / malware / phishing feed or node flag) | 100201 | 12 |
| `known_bad` (CRITICAL) | as above, with a critical graph score | 100205 | 14 |
| `suspicious` | a threat signal without a confirmed-bad category (e.g. Tor / anonymizer / blocklist) | 100202 | 7 |
| `known_good` | allowlist-vouched, no threat | 100203 | 3 |
| `unknown` | no data at this granularity (no-data ≠ safe) | 100204 | 3 |

Opt-in: rule **100206** flags a Cobalt-Strike TLS fingerprint (JARM) when the integration's
`extra_enrichments` option includes `tls_fingerprint`.

## Installation and Configuration

The integration is **stdlib-only Python** on the manager's bundled interpreter — nothing to
`pip install`. It ships five files:

| File | Destination | Perms |
|---|---|---|
| `custom-whisper` (shell wrapper) | `/var/ossec/integrations/` | 750 `root:wazuh` |
| `custom-whisper.py` (the connector) | `/var/ossec/integrations/` | 750 `root:wazuh` |
| `whisper_client.py` (shared HTTP/TLS client — **imported** by the connector) | `/var/ossec/integrations/` | 640 `root:wazuh` |
| `whisper_rules.xml` | `/var/ossec/etc/rules/` | 660 `root:wazuh` |
| `whisper-template.json` (indexer field types) | PUT to the indexer | — |

```bash
# 1. scripts (the connector imports whisper_client.py, so all three go together)
cp custom-whisper custom-whisper.py whisper_client.py /var/ossec/integrations/
chown root:wazuh /var/ossec/integrations/custom-whisper /var/ossec/integrations/custom-whisper.py /var/ossec/integrations/whisper_client.py
chmod 750 /var/ossec/integrations/custom-whisper /var/ossec/integrations/custom-whisper.py
chmod 640 /var/ossec/integrations/whisper_client.py

# 2. rules
cp whisper_rules.xml /var/ossec/etc/rules/
chown root:wazuh /var/ossec/etc/rules/whisper_rules.xml && chmod 660 /var/ossec/etc/rules/whisper_rules.xml

# 3. indexer field types (analysisd stringifies every value; the template coerces
#    data.whisper.* numbers/booleans back so range queries work)
curl -sk -u <indexer-user>:<indexer-pass> -XPUT "https://<indexer>:9200/_template/whisper" \
  -H 'Content-Type: application/json' -d @whisper-template.json
```

> The upstream project ships an `install.sh` that does all of the above with an `ossec.conf`
> rollback and a post-restart verify, plus `.deb`/`.rpm` packages and a one-line bootstrap. If you
> want the turnkey path, use it: <https://github.com/whisper-sec/whisper-wazuh#install>.

## Wazuh Configuration

### Integrator Config (manager `ossec.conf`)

Add an `<integration>` block. There is **no `<api_key>`** — the graph enrichment is keyless. The
`<name>` must match the shell wrapper.

```xml
<integration>
  <name>custom-whisper</name>
  <group>sshd</group>          <!-- the rule groups whose alerts get enriched -->
  <alert_format>json</alert_format>
</integration>
```

`<group>` (or `<rule_id>`) is your cost/noise dial: every matching alert that carries a public IP or
domain becomes one graph lookup (deduped by the cache). Start narrow (e.g. `sshd`) and widen
deliberately. **Never** point it at a group the enrichment alerts themselves carry — that would loop.

Then restart the manager: `sudo /var/ossec/bin/wazuh-control restart`.

### Custom Rules

`whisper_rules.xml` renders the verdict as an alert level (see the table above). It installs to
`/var/ossec/etc/rules/` and is picked up on the next manager restart. Without it, an enrichment is
just a decoded event with no severity.

### Manual Tests

Turn on the connector's debug log first:

```bash
echo 'integrator.debug=2' | sudo tee -a /var/ossec/etc/local_internal_options.conf
sudo /var/ossec/bin/wazuh-control restart
```

#### Test 1 — the rules render a verdict (`wazuh-logtest`)

`wazuh-logtest` loads the ruleset from disk, so it confirms `whisper_rules.xml` maps a verdict to the
right level without waiting for a live alert:

<details>
<summary>Feed a decoded enrichment event per verdict and check the matched rule/level</summary>

```bash
# suspicious (a Tor exit) → rule 100202, level 7
printf '%s\n' '{"integration":"custom-whisper","whisper":{"ioc":"185.220.101.1","verdict":"suspicious","level":"HIGH"}}' \
  | sudo /var/ossec/bin/wazuh-logtest
#   Phase 3: id '100202'  level '7'  "Whisper: 185.220.101.1 is SUSPICIOUS (HIGH)"

# known_good (an allowlisted resolver) → rule 100203, level 3
printf '%s\n' '{"integration":"custom-whisper","whisper":{"ioc":"8.8.8.8","verdict":"known_good","level":"NONE"}}' \
  | sudo /var/ossec/bin/wazuh-logtest
#   Phase 3: id '100203'  level '3'

# known_bad → rule 100201, level 12
printf '%s\n' '{"integration":"custom-whisper","whisper":{"ioc":"1.2.3.4","verdict":"known_bad","level":"HIGH"}}' \
  | sudo /var/ossec/bin/wazuh-logtest
#   Phase 3: id '100201'  level '12'
```

</details>

#### Test 2 — the connector enriches a live indicator (end to end)

Run the connector against a single-alert JSON file (argv: `<alert-file> <api_key> <hook_url> debug`;
the `api_key` is unused for the keyless graph and can be empty):

<details>
<summary>Enrich a real public IP and inspect the emitted <code>data.whisper.*</code> payload</summary>

```bash
cat > /tmp/alert.json <<'JSON'
{"timestamp":"2026-01-01T00:00:00.000+0000","rule":{"id":"5710","level":5,"groups":["sshd"]},
 "agent":{"id":"000","name":"manager"},"id":"1700000000.1","full_log":"...",
 "data":{"srcip":"185.220.101.1"},"location":"/var/log/auth.log"}
JSON

sudo /var/ossec/integrations/custom-whisper.py /tmp/alert.json '' '' debug
#   whisper: invoke ioc=185.220.101.1 type=ipv4 ...
#   whisper: api url=https://graph.whisper.security ms=...
#   whisper: emit ... payload_bytes=...
```

A new enrichment alert appears in **Discover → `wazuh-alerts-*`**; search `data.whisper.ioc:185.220.101.1`.
A full captured walkthrough (the real graph response → the resulting `data.whisper.*` alert JSON) is
in the upstream repo:
[docs/scenarios/01-tor-ip-enrichment.md](https://github.com/whisper-sec/whisper-wazuh/blob/main/docs/scenarios/01-tor-ip-enrichment.md).

</details>

#### Test 3 — private / non-global IPs are skipped

Private, loopback and TEST-NET addresses are never looked up (the public-IP guard). With debug on,
`sudo grep whisper: /var/ossec/logs/integrations.log` shows `skip reason=non-global` — expected, no
alert.

## Beyond enrichment — the keyed tier

The enrichment above is the keyless, always-on half. The upstream project adds a **keyed** tier for
Whisper customers running agents on the platform:

- **Agent-activity log source** (`whisper-logs`) — a scheduled poller that pulls your own agents'
  activity (DNS allow/refused, egress connections, identity allocation) into Wazuh as
  `data.whisper_agent.*` alerts. Enabled with `install.sh --logs`.
- **On-demand CLI** (`whisper-investigate`) — runs deep Whisper investigation workflows on a single
  indicator and prints a report.

Both need a Whisper API key. See the upstream repo for install, packaging, and the full docs:
**https://github.com/whisper-sec/whisper-wazuh**.

## Sources

- **Upstream project & full documentation:** <https://github.com/whisper-sec/whisper-wazuh>
- **Adapted by:** Whisper Security
- **Tested versions:** Wazuh **4.14.5**
- **Maintainer:** Whisper Security (`security@whisper.security`)
- **Support:** best-effort via the upstream repository's issues. API keys and tiers for the keyed
  features: <https://www.whisper.security/pricing>