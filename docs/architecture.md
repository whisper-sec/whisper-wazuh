# Architecture

## The short version

Wazuh is a SIEM — it collects logs, turns them into alerts, and shows them to analysts. This
project bolts threat intelligence onto that: when an alert mentions a public IP or domain, we
ask the **Whisper infrastructure graph** what it knows about that indicator, and write the answer
back into Wazuh as a new, graded alert.

There are two ways to use it:

- **The connector** — automatic. Runs on the manager for every alert in the groups you pick, and
  enriches the indicators it finds. This is the always-on layer.
- **The CLI (`whisper-investigate`)** — manual. An analyst runs it on one indicator to get a deep
  investigation report. This is the on-demand deep-dive.

Both are plain Python using only the standard library, running on the Python that already ships
with Wazuh. No extra services, no database of our own, nothing to `pip install` on the manager.

---

## The whole thing in one picture

```
   endpoints                ┌──────────────────────────── WAZUH MANAGER ────────────────────────────┐
  ┌──────────┐   logs, FIM  │                                                                        │
  │  agent   │ ───────────► │  ┌───────────┐  decode + match rules   ┌────────────┐   append         │
  │ (server, │              │  │ analysisd │ ──────────────────────► │ alerts.json│ ──┐              │
  │  laptop) │              │  └─────▲─────┘                         └────────────┘   │ ④ Filebeat   │
  └──────────┘              │        │                                                │   ships each  │
  (or raw syslog —          │        │ ③ writes the enriched alert back               │   alert       │
   agents are optional)     │        │    onto the queue socket, where analysisd      │              │
                            │        │    picks it up like any other event            │              │
                            │   queue socket                                          │              │
                            │        ▲                                                │              │
                            │        │                                                │              │
                            │  ┌─────┴────────────┐   ① integratord hands each        │              │
                            │  │  custom-whisper   │◄──  finished alert (in a trigger  │              │
                            │  │  (the connector)  │     group) to the connector       │              │
                            │  └─────────┬─────────┘                                   │              │
                            │            │ ② enrich the IOC (HTTPS)                     │              │
                            │   ┌────────┴────────┐                                    │              │
                            │   │ whisper_client  │ ───────────────────┐               │              │
                            │   └────────▲────────┘                     │              │              │
                            │            │ (shared HTTP/TLS/auth)       │              │              │
                            │  ┌─────────┴──────────┐                   │              ▼              │
                            │  │ whisper-investigate │ ──── MCP ───┐    │        ┌───────────┐        │
                            │  │  (analyst CLI)      │             │    │        │  INDEXER  │        │
                            │  └─────────▲───────────┘             │    │        │(OpenSearch)        │
                            └────────────┼─────────────────────────┼────┼────────┴─────┬─────┴────────┘
                                         │ runs it on demand       │    │              │
                                  ┌──────┴──────┐                  ▼    ▼              ▼
                                  │   analyst   │         mcp.whisper.security   ┌───────────┐
                                  │   (shell)   │         graph.whisper.security │ DASHBOARD │
                                  └─────────────┘          (the Whisper graph)   │ (web UI)  │
                                                                                 └───────────┘
```

The four Wazuh pieces (agent, manager, indexer, dashboard) are stock — we don't change them. Our
code is the two boxes inside the manager (`custom-whisper` and `whisper-investigate`) plus a
shared client, some rules, and an indexer template.

---

## How an alert actually gets enriched

This is the important flow — the numbered steps from the picture, spelled out:

```
  1. An alert fires that carries a public indicator
     e.g.  sshd rule 5710  ·  data.srcip = 185.220.101.1

  2. integratord (a post-alert hook) sees it's in a configured trigger group
     and runs  /var/ossec/integrations/custom-whisper  with the alert JSON

  3. The connector EXTRACTS the indicator
     - pulls IPs/domains from known fields (data.srcip, data.dns.rrname, …)
     - SKIPS private/reserved IPs (10.x, 192.168.x, TEST-NET) — nothing to look up

  4. The connector ENRICHES it against the Whisper graph  (HTTPS, with your key)
     - explain()  → the threat read: which feeds list it, at what level
     - context    → ASN, prefix + its own threat listing, geo, and for domains
                    DNS / WHOIS / SPF / web links

  5. The connector DECIDES a verdict from the EVIDENCE  (not the raw score)
     unknown  →  known_good  →  known_bad  →  suspicious, by ordered gates
     (a HIGH score alone is evidence, not a conviction — see "why" below)

  6. The connector WRITES BACK a new alert onto the analysisd queue socket
     1:custom-whisper:{"whisper":{"verdict":"suspicious", …}}

  7. analysisd re-decodes it, OUR RULES match, and assign a LEVEL
     verdict "suspicious"  →  rule 100202  →  level 7

  8. The indexer TEMPLATE coerces the field types (analysisd stringifies everything),
     so numbers stay numbers and range queries work

  9. Filebeat ships the enriched alert; it shows up in the DASHBOARD next to the trigger
```

So one triggering event produces **two** alerts: the original (the sshd alert) and the
enrichment (the SUSPICIOUS alert). They're separate documents, linked by a `source_ref` field on
the enrichment. We create a new alert rather than editing the original because Wazuh's alert log
is append-only and integratord only runs *after* the alert is already written — there's nothing
in-flight to modify. This is the same pattern the built-in VirusTotal integration uses.

---

## The on-demand CLI, briefly

The connector is cheap and automatic. Sometimes an analyst wants to go deep on one indicator
instead. That's the CLI:

```
   analyst  ──►  whisper-investigate theblackservicenetwork.com
                       │
                       │  runs a heavy Whisper WORKFLOW (dozens of steps:
                       │  related domains, real servers behind CDNs, abuse history…)
                       ▼
                 a full Markdown / JSON report
                 (verdict, ranked findings, the evidence behind each)
```

One wrinkle we found the hard way: those workflows aren't on Whisper's REST API — they only run
through Whisper's **MCP server**. So the CLI is a small MCP client. It shares `whisper_client`
with the connector so the tricky bits (the request headers the WAF wants, TLS handling, retries)
live in exactly one place.

---

## The moving parts

| File | What it is |
|---|---|
| `custom-whisper` + `custom-whisper.py` | The connector. Wrapper + the actual Python. integratord runs the wrapper; it execs the `.py` on Wazuh's bundled interpreter. |
| `whisper_client.py` | Shared plumbing — the HTTPS client, TLS/CA handling, the retry/error rules, the IOC parsers, key/URL resolution. Imported by both the connector and the CLI. |
| `whisper-investigate` + `whisper-investigate.py` | The on-demand analyst CLI (the MCP client + the report renderer). |
| `whisper_rules.xml` | Turns a verdict into an alert level (known_bad→12, suspicious→7, …). Without these, the enrichment is just a decoded event with no severity. |
| `whisper-template.json` | Registers the field *types* on the indexer, so `data.whisper.*` numbers/booleans index correctly (analysisd stringifies everything on the way through). |
| `dedup.db` (SQLite) | A small cache so the same indicator isn't re-looked-up on every alert within a TTL. |
| `install.sh` / `uninstall.sh` | Do the manual "copy files, patch ossec.conf, push the template, restart, verify" dance safely (with rollback), so you don't have to. |

---

## Why it's built this way

The interesting decisions, and the reasoning:

**We write a new alert, we don't touch the original.**
integratord runs after the alert is finalized and appended to an immutable log. There's no
in-flight alert to edit, and mutating alert history would be a bad idea anyway (it's a
tamper-evident audit trail). So enrichment is a new, linked alert. Idiomatic Wazuh.

**The verdict comes from evidence, never from the score.**
A high threat score doesn't make something "bad." A Tor exit node scores HIGH but the feeds
listing it are Tor/anonymizer categories — that's `suspicious`, not `known_bad`. An
allow-listed IP that *also* shows up on a blacklist gets downgraded — trust never overrides
threat. This is the core design property, and it's what the acceptance suite checks.

**Everything is stdlib-only, on Wazuh's own Python.**
No dependencies to install on the manager, no side services, no database of ours. It uses
Wazuh's interpreter, Wazuh's alert socket, and the customer's own indexer. The only external
thing is the Whisper API itself.

**Bring your own key.**
We never ship a key. The Whisper key is a per-organization secret; each deployer supplies their
own (env var for containers, a `640 root:wazuh` key file for VMs). It's deliberately kept out of
`ossec.conf` so it can't leak into a process command line.

**Heavy fields are opt-in; benign infrastructure stays quiet.**
Most enrichment fields are cheap and always on. A few (like the Cobalt-Strike TLS-fingerprint
signal) are opt-in because they're narrow. And every field is signal-gated — a clean IP doesn't
sprout empty threat blocks. We dropped several proposed fields entirely because, against the
live graph, they'd have misled an analyst more than helped.

---

## What an enrichment looks like

The connector writes one `data.whisper.*` object. Real capture for the Tor IP:

```json
"whisper": {
  "ioc": "185.220.101.1", "type": "ipv4",
  "verdict": "suspicious", "risk_score": 7.46, "level": "HIGH",
  "asn": { "number": 60729, "country": "DE" },
  "prefix": "185.220.101.0/24",
  "prefix_threat": { "level": "CRITICAL", "score": 14, "is_threat": true, "threat_neighbor_count": 151 },
  "geo": { "country": "DE", "city": "Brandenburg, DE" },
  "threat_feed": { "feeds": ["dan-tor-exit", "…"], "flags": ["isThreat","isTor","isSpam"], "sources_count": 6 },
  "tags": ["tor", "anonymizer", "spam"],
  "source_ref": { "rule_id": "5710", "field_path": "data.srcip" },
  "dedup_key": "ipv4|185.220.101.1|000"
}
```

`source_ref` links back to the alert that triggered it. `dedup_key` is what the cache keys on.
Nullable fields are stripped before sending — a clean indicator produces a small, quiet envelope.

---

## Where everything lives on the manager

```
  /var/ossec/integrations/custom-whisper            the connector wrapper (750 root:wazuh)
  /var/ossec/integrations/custom-whisper.py         the connector
  /var/ossec/integrations/whisper_client.py         shared client (640 root:wazuh)
  /var/ossec/integrations/whisper-investigate[.py]  the analyst CLI
  /var/ossec/etc/rules/whisper_rules.xml            verdict → alert level
  /var/ossec/etc/whisper.key                        your API key (640 root:wazuh)
  /var/ossec/var/whisper/dedup.db                   the dedup cache (0770)
  /var/ossec/etc/ossec.conf                         holds the <integration> trigger block
  <indexer>/_template/whisper                        the field-type template
```

For the full field-by-field mapping, the verdict gates, and the acceptance criteria, see
[`whisper-to-wazuh-mapping.md`](whisper-to-wazuh-mapping.md) and
[`mvp-acceptance-criteria.md`](mvp-acceptance-criteria.md).