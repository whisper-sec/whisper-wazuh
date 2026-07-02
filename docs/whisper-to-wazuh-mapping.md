# Whisper → Wazuh data & field mapping

**Status:** Milestone 0 — Requirement Analysis · target **Wazuh 4.14.5** · resolves
[#3](https://github.com/whisper-sec/whisper-wazuh/issues/3)

Wazuh has no STIX-native sink. This spec defines how results from the Whisper infrastructure
graph are projected onto Wazuh's own data model — specifically, onto the **alert JSON** that
`analysisd` indexes into `wazuh-alerts-*`. The connector (Pattern **A**, an `integratord`
custom script on the manager — see [#2](https://github.com/whisper-sec/whisper-wazuh/issues/2))
enriches a triggering alert's IOC and writes the enrichment back as a **new, analyst-visible
alert** whose payload lives under `data.whisper.*`. This document is the field-by-field
contract for that payload, the rule that renders it, where the data lives, and how re-running
enrichment stays idempotent.

It is grounded in three verified sources: the locked scope in
[#1](https://github.com/whisper-sec/whisper-wazuh/issues/1), the live Whisper graph
(node/edge schema + `explain()` output, checked 2026-07-02), and the in-tree Wazuh 4.14.5
reference integrations `integrations/virustotal.py`, `integrations/maltiverse.py` and
`ruleset/rules/0490-virustotal_rules.xml` / `0997-maltiverse_rules.xml`.

---

## 0. Quick tour (read this first)

**What this integration does, in one sentence:** when a Wazuh alert contains a public IP or a
domain, a small script on the manager asks the Whisper graph about it and posts the answer back
into Wazuh as a *new* alert the analyst sees next to the original.

```text
  Source alert (already in Wazuh)                      Whisper graph API
  ┌───────────────────────────────┐                  ┌─────────────────────┐
  │ rule 5710 "SSH brute force"   │                  │ explain(ioc)        │
  │ data.srcip: 185.220.101.1     │                  │ + targeted lookups  │
  └───────────────┬───────────────┘                  └──────────▲──────────┘
                  │ matches the <integration> filter            │
                  ▼                                             │ ③ look up
        wazuh-integratord ──runs──► custom-whisper script ──────┘
                                        │  ① extract the IOC (data.srcip)
                                        │  ② dedup check — if seen < TTL, stop here
                                        │  ④ build the data.whisper.* JSON
                                        ▼  ⑤ send one datagram
                        /var/ossec/queue/sockets/queue  (analysisd)
                                        │
                                        ▼
                NEW alert — rule 100201 "Whisper: … KNOWN BAD (HIGH)"
                data.integration = custom-whisper · data.whisper.*
                                        │
                                        ▼
                        wazuh-alerts-*  (native Alerts view)
```

**The one-minute version:**

- The original alert is **never modified** — Wazuh alerts are append-only, so the enrichment is
  a second, linked alert (§3).
- Everything Whisper says lives in **one JSON object, `data.whisper.*`**, with a fixed field
  contract (§4) and per-indicator mapping tables (§5).
- The **verdict** (`known_good` / `known_bad` / `suspicious` / `unknown`) is derived from
  *evidence* — what kind of feeds list the IOC — never copied from Whisper's raw score (§6).
  No data means `unknown`, not safe.
- A small on-disk **dedup cache** stops the same IOC producing duplicate enrichment alerts
  within a TTL (§7).
- Enrichment alerts sit in their **own rule group** that the trigger filter never watches, so
  the script can never re-trigger itself (§6, §8).

**Reading guide:**

| If you want to know… | Read |
|---|---|
| How Wazuh's alert plumbing works (socket, `data.*`, indexing) | §2 |
| Why the data lands where it lands (and what was rejected) | §3 |
| What the enrichment JSON looks like (with examples) | §4 — examples in §4.1 and §4.4 |
| Exactly which Whisper field maps to which Wazuh field | §5 |
| How good/bad/suspicious/unknown is decided, and alert severity | §6 |
| Why re-running never duplicates alerts | §7 |
| The correctness rules the implementation must obey | §8 |
| Which alert fields IOCs are extracted from | §9 |
| What's deferred, and what's still undecided | §10–§11 |

Everything below is the precise contract; each section opens with a one-line plain-English
summary so you can skim at the depth you need.

---

## 1. Purpose & scope

**Exit criteria (issue #3):** (a) a field-by-field mapping for each supported indicator type,
(b) a decision on where enriched data lives (side index vs. enrichment object vs. CDB list),
and (c) an idempotency / dedup strategy. All three are specified below.

**In scope (MVP):**

- **Direction:** alert **enrichment only** (Whisper → Wazuh). The threat-intel *feed* direction
  (Whisper → Wazuh, for detection) is post-MVP (§10, Pattern B).
- **Indicator triggers:** **IPv4, IPv6, Domain**, extracted from alert fields (§9). IPs are
  validated with stdlib `ipaddress`; **non-global IPs are skipped**.
- **ASN** is emitted as *context* inside IP enrichment — it is **not** a trigger.
- **Sink:** a new correlated alert via the `analysisd` queue socket, payload under
  `data.whisper.*` (§3, §4). **Not** a side index.

**Out of scope (MVP):** ASN/URL/hash/email *triggers*; CDB feed / detection direction; dashboard
plugin; backfill of historical alerts; multi-hop graph traversal. See §10.

---

## 2. Wazuh data model primer

> **In short:** a Wazuh alert is a JSON document; whatever an integration sends becomes
> `data.<name>.*`; new alerts are injected through a Unix socket with a tiny header; and the
> indexer freezes each field's type on first write — so we pin our types up front.

### 2.1 The alert JSON envelope

A Wazuh alert, as indexed into `wazuh-alerts-4.x-*`, has these top-level keys (not all are
always present):

| Key | Meaning |
|---|---|
| `timestamp` | ISO-8601 with ms + tz |
| `id` | alert id (unix-seconds.microseconds form); not used for dedup — see §7 |
| `rule` | `{id, level, description, groups[], mail, firedtimes, mitre, …}` |
| `agent` | `{id, name, ip}` — `agent.ip` absent when `agent.id == "000"` (manager) |
| `manager` | `{name}` |
| `cluster` | `{name, node}` — only when clustering is enabled |
| `decoder` | `{name, parent}` |
| `location` | log source path, or the integration location token for injected events |
| `full_log` | raw event text |
| `previous_output` | only on frequency/composite rules |
| `data` | **decoded dynamic fields** — where all custom/vendor content lives |

### 2.2 The `data.*` namespace — the one rule that governs everything

Decoder-extracted fields and JSON-decoded input keys are nested under the top-level **`data`**
object. When an integration sends a JSON event whose top-level key is `whisper`, `analysisd`
re-decodes it and the field appears in the indexed document as **`data.whisper.*`**.

> **The prefix rule (load-bearing — a common mistake):**
> In **rules XML** you match the field by its **un-prefixed** decoded name:
> `<field name="integration">…</field>`, `<field name="whisper.verdict">…</field>`.
> In **OpenSearch DSL / the dashboard** you query the **`data.`-prefixed** path:
> `data.integration`, `data.whisper.verdict`.
> The same field, two spellings depending on where you reference it.

### 2.3 Writing a new alert: the `analysisd` queue socket

The connector injects its enrichment by sending a UTF-8 datagram to the analysisd ingest socket.
Verified against `virustotal.py` / `maltiverse.py` @ v4.14.5:

- **Socket:** `AF_UNIX`, `SOCK_DGRAM`, path `{WAZUH_HOME}/queue/sockets/queue`
  (= `/var/ossec/queue/sockets/queue`). `connect → send → close`. No length prefix, **no trailing
  newline**.
- **Framing** — the string is `1:<location>:<json>`, where the leading `1` is the analysisd
  queue message-type header (a location-prefixed event). There are two forms, selected by the
  agent the enrichment is attributed to:

  ```text
  # Form A — manager / local (agent absent or agent.id == "000"):
  1:custom-whisper:{"integration":"custom-whisper","whisper":{…}}

  # Form B — real originating agent (agent.id != "000"):
  1:[001] (web01) 10.0.0.5->custom-whisper:{"integration":"custom-whisper","whisper":{…}}
  #    └─ location = "[{id}] ({name}) {ip|any}", then .replace('|','||').replace(':','|:')
  #       (colons inside the location are escaped as |:  so they don't collide with the
  #        framing delimiters)
  ```

  **Decision:** Whisper runs on the manager but enriches alerts whose `agent.id` is usually a
  real endpoint. Use **Form B** — stamp the enrichment onto the **originating agent** — so the
  new alert keeps its endpoint linkage in the native Alerts view. (Flagged for confirmation, §11.)

- **Size guard:** `maltiverse.py` sets `MAX_EVENT_SIZE = 65535`; an oversized datagram fails with
  `errno 90` ("Message too long"). This is the origin of scope §3.8's **60 KB payload guard**:
  budget the *entire framed string* under ~64 KB, and keep the JSON well under 60 KB, falling back
  to `payload_too_large` (§8) when a full payload would overflow.

- **Script contract** (verified empirically on 4.14.5): `integratord` executes
  `/var/ossec/integrations/custom-whisper` with positional args —
  `argv[1]` = path to a temp JSON file holding the single triggering alert (one line; requires
  `<alert_format>json</alert_format>`; unlinked after the script exits) ·
  `argv[2]` = API key (`''` when unset) ·
  `argv[3]` = hook URL (from `<hook_url>`; the script ignores it as `virustotal.py` does — it must
  **not** validate the URL) ·
  `argv[4]` = `debug` or `''` ·
  `argv[5]` = options tmp file (JSON from `<options>`, `''` when unset) ·
  `argv[6]` = timeout (default `10`) · `argv[7]` = retries (default `3`) ·
  plus a literal trailing `> /dev/null 2>&1` argument when debug is off — **read args
  positionally, never rely on `argc`.** The `<options>` JSON (argv[5]) is the config channel for
  `api_url` and `dedup_ttl`; resolution order: options → environment (`WHISPER_API_URL` /
  `WHISPER_DEDUP_TTL`) → built-in default. Scripts live in `/var/ossec/integrations/`, perms
  `750`, owner `root:wazuh`.

### 2.4 How `data.whisper.*` lands in the indexer

The wazuh-indexer (OpenSearch) applies `extensions/elasticsearch/7.x/wazuh-template.json`
(patterns `wazuh-alerts-4.x-*`, `wazuh-archives-4.x-*`). Relevant settings, verified @ v4.14.5:

- `index.mapping.total_fields.limit = 10000` (ample headroom — but keep `data.whisper.*` shallow).
- `date_detection = false` (date-looking strings are **not** auto-coerced to `date`).
- One dynamic template, **`string_as_keyword`**: any new string field maps to `keyword`
  (exact-match, no `.keyword` subfield). So **string `data.whisper.*` fields index with no template
  change** — this is how community custom integrations work.

> **Type-stability pitfall (must design around):** numbers/booleans are **not** covered by
> `string_as_keyword`; the first document to carry `data.whisper.risk_score` as a JSON number
> freezes it to `long`/`float` for the life of the index. A later document sending the same field
> as a **string** (or vice-versa) is rejected with `mapper_parsing_exception` — **and the whole
> alert can be dropped.** Wazuh's own template sidesteps this by typing VirusTotal's
> numeric-looking fields (`positives`, `total`, `malicious`) as `keyword`.
>
> **Rules for `data.whisper.*`:** (1) keep it **shallow**; (2) use **consistent types on every
> emitted alert** — never mix string/number for the same key; (3) arrays of **scalars** are fine,
> arrays of objects with *varying* keys are not; (4) if `risk_score` must be range-queried /
> aggregated, emit it as a real number **and** ship an explicit `data.whisper` mapping block in
> the indexer template **before first ingest** (§4.3). We ship that block rather than rely on
> dynamic mapping — it locks types and prevents first-write-wins conflicts.

---

## 3. Where enriched data lives — decision

Three sinks were considered. **Decision: (a) — the enrichment object as a new alert under
`data.whisper.*`.**

| Option | What it is | Verdict |
|---|---|---|
| **(a) Enrichment object in a new alert** `data.whisper.*` | Inject a new alert via the analysisd socket (§2.3); enrichment nests under `data.whisper.*`; original alert untouched; rendered by `whisper_rules.xml`. | **CHOSEN (MVP).** Idiomatic — exactly how in-tree `virustotal`/`maltiverse` enrich. Shows up in the native Alerts view; one store; correlatable in the dashboard. |
| **(b) Side / secondary index** (`whisper-enrichment-*`) | A standalone service reads/writes a separate indexer index. | **Rejected** (Pattern C, #2). Off the beaten path for Wazuh; enrichment would not surface as native alerts; a second store = two sources of truth. |
| **(c) CDB list** (`/var/ossec/etc/lists/…`) | Key:value lists Wazuh matches at decode/rule time. | **Post-MVP (Pattern B).** This is *detection* (match an IOC → raise a rule), a different capability from *enrichment*. Format captured in §10.1 for the feed milestone. |

The rest of this spec details option (a).

---

## 4. The enrichment envelope

> **In short:** one JSON object, `data.whisper.*`, with a fixed set of fields — the IOC's
> identity, the verdict plus its evidence, linkage back to the source alert, and bookkeeping
> (dedup key, truncation flags). Two worked examples: an IP (§4.1) and a domain (§4.4).

### 4.1 Injected JSON (what the script sends)

The script sends a flat top-level dict; its keys become `data.*`. Convention mirrors the in-tree
integrations (`{'integration': '<name>', '<name>': {…}}`):

```json
{
  "integration": "custom-whisper",
  "whisper": {
    "schema_version": "1.0",
    "ioc": "185.220.101.1",
    "type": "ipv4",
    "known": true,
    "available": true,
    "verdict": "suspicious",
    "risk_score": 7.35,
    "level": "HIGH",
    "advisory": null,
    "permalink": "https://graph.whisper.security/ip/185.220.101.1",
    "graph_node_id": "ipv4/185.220.101.1",
    "source_ref": {
      "rule_id": "5710",
      "alert_id": "1751414400.123456",
      "agent_id": "001",
      "field_path": "data.srcip",
      "original_full_log": "…first 512 chars of the source alert's full_log…"
    },
    "asn": { "number": 60729, "name": null },
    "prefix": "185.220.101.0/24",
    "geo": { "country": "DE", "city": null },
    "threat_feed": {
      "feeds": ["dan-tor-exit", "stamparm-ipsum", "tor-exit-nodes", "stopforumspam-listed-ip-7d"],
      "categories": ["TOR Network", "General Blacklists"],
      "flags": ["isThreat", "isTor", "isSpam", "isAnonymizer"],
      "sources_count": 4,
      "first_seen": "2026-06-22T19:25:52Z",
      "last_seen": "2026-06-29T12:11:13Z"
    },
    "tags": ["tor", "anonymizer", "spam"],
    "coverage": { "granularity": "ipv4", "shared_host": false, "data_coverage": null },
    "dedup_key": "ipv4|185.220.101.1|001",
    "unmapped_summary": null,
    "truncated": false
  }
}
```

Indexed, this becomes `data.integration = "custom-whisper"`, `data.whisper.verdict = "suspicious"`,
`data.whisper.threat_feed.feeds = [...]`, etc.

> **Why `suspicious`, not `known_bad`, at `level: HIGH`?** This is the core principle in action
> (§6): the Whisper score/level is *evidence*, not the verdict. Here the feeds are Tor /
> anonymizer / general-blocklist categories — no confirmed-bad category (C2, malware, phishing)
> — so despite a HIGH score the evidence-derived verdict is `suspicious`. A domain with a
> confirmed `known_bad` verdict is shown in §4.4.

### 4.2 Common envelope fields

These appear on **every** enrichment regardless of indicator type. (`ioc`, `type`, `known`,
`verdict`, `risk_score`, `permalink`, `graph_node_id`, `unmapped_summary`, `truncated` are the
fields locked in issue #1 §3.7; the rest are additions this spec introduces and flags in §11.)

| Field | Type | Description |
|---|---|---|
| `schema_version` | keyword | Envelope version (`"1.0"`). Lets rules/queries evolve without ambiguity. |
| `ioc` | keyword | The indicator value that was enriched. |
| `type` | keyword | `ipv4` \| `ipv6` \| `domain`. |
| `known` | boolean | Whisper has a node for this IOC (`graph_node_id` is non-null / `explain().found`). Distinct from `verdict`: "known" = *the graph knows it*, not *it is safe*. |
| `verdict` | keyword | `known_good` \| `known_bad` \| `suspicious` \| `unknown` — **evidence-derived** (§6). Never a raw copy of the Whisper score. |
| `risk_score` | float | Whisper `explain().score` (unbounded float, typ. 0–100+). **Evidence surfaced, never the sole verdict.** Emit consistently as a number (see §2.4 type rule). |
| `level` | keyword | Whisper `explain().level` enum (`NONE`…`CRITICAL`), verbatim. |
| `available` | boolean | Whisper `explain().available` — the scoring backend answered. `false` (degraded / `retryAfter`) forces `verdict = unknown` (§6, §11). |
| `advisory` | keyword \| null | The **top-level** `explain()` advisory (e.g. `allowlist-vouched`) — **not** a `coverage` sub-field. Signals an allowlist vouch that downgrades an otherwise-listed IP. |
| `permalink` | keyword | Deep link to the Whisper graph view for the IOC. |
| `graph_node_id` | keyword | Stable Whisper node id (e.g. `ipv4/185.220.101.1`). |
| `coverage` | object | `{granularity, shared_host, data_coverage}` — `granularity` ← `explain().coverage.granularity`, `shared_host` ← `explain().coverage.sharedHost`, `data_coverage` ← `explain().coverage.dataCoverage` (**hostname-only, optional/best-effort** — absent on IPs). Gates verdict — **no-data ≠ benign** (§6). |
| `source_ref` | object | Linkage back to the triggering alert: `rule_id`, `alert_id`, `agent_id`, `field_path` (the `SUPPORTED_FIELD_PATHS` entry that produced the IOC, recorded in `data.`-prefixed form, e.g. `data.srcip`), `original_full_log` (truncated). |
| `dedup_key` | keyword | The idempotency key that suppressed/allowed this alert (§7). |
| `unmapped_summary` | text \| null | One-line summary of Whisper data the connector saw but did **not** map (no silent drops, §8). `null` when nothing was dropped. |
| `truncated` | boolean | `true` if any list field was capped (§8). Per-list totals live beside each list. |

### 4.3 Indexer mapping block (typed fields, before first ingest)

`string_as_keyword` (§2.4) only covers *strings*. Ship an explicit mapping for the
numeric/boolean/date `data.whisper.*` fields to **lock their types and prevent the
first-write-wins conflict**. Install it on the wazuh-indexer (as a component/index-template
override on `wazuh-alerts-4.x-*`) **before the first enrichment alert**:

```json
{
  "mappings": {
    "properties": {
      "data": {
        "properties": {
          "whisper": {
            "properties": {
              "risk_score":  { "type": "float" },
              "known":       { "type": "boolean" },
              "available":   { "type": "boolean" },
              "truncated":   { "type": "boolean" },
              "threat_feed": {
                "properties": {
                  "sources_count": { "type": "integer" },
                  "first_seen":    { "type": "date" },
                  "last_seen":     { "type": "date" }
                }
              },
              "links": {
                "properties": {
                  "inbound_total":  { "type": "long" },
                  "outbound_total": { "type": "long" }
                }
              },
              "asn": { "properties": { "number": { "type": "long" } } }
            }
          }
        }
      }
    }
  }
}
```

Every other `data.whisper.*` field is a string or array-of-strings and maps to `keyword`
automatically. Keep the object shallow to stay well under `total_fields.limit` (§2.4). The exact
install API (legacy `_template` vs. composable/component template on the OpenSearch indexer) is an
open item — §11 Q9.

### 4.4 Worked example — domain (`known_bad`)

Illustrative payload for a phishing typosquat, exercising the richer domain shape (§5.2). Its
`verdict` **does** follow the §6 chain: `level HIGH` + a confirmed-bad `Phishing` category →
`known_bad`.

```json
{
  "integration": "custom-whisper",
  "whisper": {
    "schema_version": "1.0",
    "ioc": "paypa1-secure.example",
    "type": "domain",
    "known": true,
    "available": true,
    "verdict": "known_bad",
    "risk_score": 62.4,
    "level": "HIGH",
    "advisory": null,
    "permalink": "https://graph.whisper.security/domain/paypa1-secure.example",
    "graph_node_id": "hostname/paypa1-secure.example",
    "source_ref": {
      "rule_id": "62123",
      "alert_id": "1751418000.987654",
      "agent_id": "004",
      "field_path": "data.dns.question.name",
      "original_full_log": "…"
    },
    "dns": {
      "a": ["203.0.113.77"], "aaaa": [], "cname": ["cdn.hosting.example"],
      "ns": ["ns1.cheap-dns.example", "ns2.cheap-dns.example"], "mx": ["mail.cheap-dns.example"]
    },
    "whois": {
      "registrar": "NameCheap, Inc.", "previous_registrar": null,
      "registered_by": "WhoisGuard Protected",
      "email": ["abuse@whoisguard.example"], "phone": ["+1.6613102107"]
    },
    "spf": { "include": ["_spf.cheap-dns.example"], "a": [], "mx": [], "ip": [], "redirect": null, "exists": [] },
    "links": {
      "inbound": [], "inbound_total": 0,
      "outbound": ["paypal.com", "cdn.hosting.example"], "outbound_total": 2
    },
    "variants": [
      { "variant": "paypa1-secure.example", "method": "homoglyph", "confidence": 0.9 }
    ],
    "threat_feed": {
      "feeds": ["openphish", "phishtank"], "categories": ["Phishing"],
      "flags": ["isThreat", "isPhishing"], "sources_count": 2,
      "first_seen": "2026-06-30T08:14:00Z", "last_seen": "2026-07-01T22:40:00Z"
    },
    "tags": ["phishing"],
    "coverage": { "granularity": "hostname", "shared_host": false, "data_coverage": null },
    "dedup_key": "domain|paypa1-secure.example|004",
    "unmapped_summary": "2 CT observations not mapped",
    "truncated": false
  }
}
```

---

## 5. Field-by-field mapping tables

> **In short:** each row says "this fact from Whisper lands in this `data.whisper.*` field".
> Read the *Whisper source* column as *where the fact comes from* (a node property, a graph
> traversal, or the `explain()` verdict call) and the arrow column as *where it goes*.

Notation for the **Whisper source** column:

- `node.<prop>` — a property read directly off the anchored node.
- `explain().<field>` — from `CALL explain(ioc)` (the authoritative threat verdict).
- A Cypher pattern — an **anchored, directional** traversal (one per category; §8).

> **Threat evidence comes from `explain().sources[]`, not Cypher `LISTED_IN`.** Verified
> 2026-07-02: for some IOCs (e.g. `8.8.8.8`) the `(:IPV4)-[:LISTED_IN]->(:FEED_SOURCE)` edges
> resolve to empty/uncategorised feed nodes, while `explain().sources[]` correctly returns the
> feeds with `{feedId, weight, firstSeen, lastSeen}`. Populate `threat_feed.feeds[]` from
> `explain().sources[]`; use `LISTED_IN → BELONGS_TO → CATEGORY` only as *best-effort* category
> labelling on top.

### 5.1 IPv4 & IPv6 (identical mapping)

`type` = `ipv4` / `ipv6`. IPv6 has the **same** node property set as IPv4, with one difference:
IPv6 has **no `HAS_COUNTRY` edge** — its country comes via `LOCATED_IN → CITY` or via its ASN.

| Whisper source | → `data.whisper.*` | Type | Notes |
|---|---|---|---|
| `explain().score` / `.level` | `risk_score` / `level` | float / keyword | Verdict derived in §6, not copied. |
| `explain().sources[].feedId` | `threat_feed.feeds[]` | keyword[] | Authoritative feed list. |
| `explain().sources[]` count | `threat_feed.sources_count` | integer | `len(sources)`. |
| `min/max explain().sources[].firstSeen/lastSeen` | `threat_feed.first_seen` / `last_seen` | date (ISO-8601) | ISO-8601 from `sources[]` (node `threatFirstSeen/LastSeen` are epoch-ms — do **not** mix; §11). |
| `node.is*` (true only) — `isThreat,isTor,isC2,isMalware,isPhishing,isSpam,isBruteforce,isScanner,isBlacklist,isAnonymizer,isProxy,isVpn,isBotnet,isDga,isExfilDestination,isOfacSanctioned,isStateActor,isReputation,isWhitelist` | `threat_feed.flags[]` | keyword[] | **Positive flags only** (omit false — avoids a noisy 19-col table). Raw Whisper flag names = stable keys. |
| feed `CATEGORY` names (best-effort) | `threat_feed.categories[]` | keyword[] | Via `LISTED_IN → BELONGS_TO → CATEGORY` where materialised; needs a static `feedId → category` map for feeds the graph doesn't categorise (§11). |
| normalised from flags + categories | `tags[]` | keyword[] | Lowercased convenience tags (`tor`, `c2`, `phishing`, …) derived from `flags[]`/`categories[]`. |
| `(ip)-[:BELONGS_TO]->(:PREFIX)<-[:ROUTES]-(:ASN)`; `asn.name` → int after `AS` | `asn.number` | integer | **No direct IP→ASN edge.** `ROUTES` is directed `ASN→PREFIX`. `asn.name` e.g. `AS15169` → `15169`. |
| `(asn)-[:HAS_NAME]->(:ASN_NAME).name` | `asn.name` | keyword | Human label, e.g. `GOOGLE - Google LLC`. (Not `ASN.name`, which is the number; not `REGISTERED_BY`.) May be **absent** — some ASNs have no `HAS_NAME` edge (verified: AS60729). |
| `(ip)-[:HAS_COUNTRY]->(:COUNTRY).name` (IPv4) / `(ip)-[:LOCATED_IN]->(:CITY)` (IPv6) | `geo.country` | keyword | ISO country code. Best-effort — anycast IPs report the operator HQ, not the edge (§11). |
| `(ip)-[:LOCATED_IN]->(:CITY).name` | `geo.city` | keyword | e.g. `Mountain View, US`. Absent for anycast. |
| `(ip)-[:BELONGS_TO]->(:PREFIX).name` | `prefix` | keyword | RIR/announced prefix (CIDR). |
| reverse `RESOLVES_TO` / co-host | `related.neighbors[]` + `related.neighbors_total` | object[] + int | **Deferred / best-effort — see §11.** A plain reverse `MATCH (h:HOSTNAME)-[:RESOLVES_TO]->(ip {name})` is rejected as an unanchored 2.6 B-node scan; needs a co-hosting workflow or passive-DNS path. Omit (with a note in `unmapped_summary`) if unavailable. |

### 5.2 Domain

`type` = `domain`. Each category is a **separate anchored, directional** query builder (§8), never
one broad `-[r]-`. Edge directions verified live on `google.com`, 2026-07-02.

| Category | Whisper source (directional Cypher) | → `data.whisper.*` | Type | Notes |
|---|---|---|---|---|
| A | `(d:HOSTNAME{name})-[:RESOLVES_TO]->(:IPV4)` | `dns.a[]` | keyword[] | May be empty (split-horizon/private DNS). |
| AAAA | `(d)-[:RESOLVES_TO]->(:IPV6)` | `dns.aaaa[]` | keyword[] | |
| CNAME | `(d)-[:ALIAS_OF]->(:HOSTNAME)` | `dns.cname[]` | keyword[] | |
| NS | `(d)<-[:NAMESERVER_FOR]-(ns:HOSTNAME)` | `dns.ns[]` | keyword[] | **`<-` direction** — NS/MX edges point neighbour→seed. Wrong direction silently returns the domains the seed *serves*, not its own records. |
| MX | `(d)<-[:MAIL_FOR]-(mx:HOSTNAME)` | `dns.mx[]` | keyword[] | **`<-` direction** (as NS). |
| Registrar | `(d)-[:HAS_REGISTRAR]->(:REGISTRAR)` | `whois.registrar` | keyword | Query **before** previous-registrar (ordering is load-bearing). |
| Previous registrar | `(d)-[:PREV_REGISTRAR]->(:REGISTRAR)` | `whois.previous_registrar` | keyword | Same `REGISTRAR` node can appear under both; current-state (`HAS_REGISTRAR`) wins by first-writer dedup (§8). |
| Registered by | `(d)-[:REGISTERED_BY]->(:ORGANIZATION)` | `whois.registered_by` | keyword | Registrant org. |
| WHOIS email | `(d)-[:HAS_EMAIL]->(:EMAIL)` | `whois.email[]` | keyword[] | Sparse; absent (not empty) when unknown. |
| WHOIS phone | `(d)-[:HAS_PHONE]->(:PHONE)` | `whois.phone[]` | keyword[] | Sparse. |
| SPF | `(d)-[:SPF_INCLUDE\|SPF_A\|SPF_MX\|SPF_IP\|SPF_REDIRECT\|SPF_EXISTS]->(…)` | `spf` | object | `{include[], a[], mx[], ip[], redirect, exists[]}` — the policy graph, not a raw record string. |
| Links (out) | `(d)-[:LINKS_TO]->(:HOSTNAME)` | `links.outbound[]` + `links.outbound_total` | keyword[] + int | **Cap displayed to N (e.g. 25); total is a bounded count** — hub domains exceed 1 M links and cannot be exact-counted (§8). |
| Links (in) | `(d)<-[:LINKS_TO]-(:HOSTNAME)` | `links.inbound[]` + `links.inbound_total` | keyword[] + int | As above. Many inbound links from legit sites = trust signal. |
| Variants | in-process generator + existence check (see note) | `variants[]` | object[] | `{variant, method, confidence}`. Registered look-alikes only (`exists ≠ malicious`). |
| Threat feed | `explain().sources[]` + `node.is*` | `threat_feed.{feeds[],categories[],flags[],sources_count,first_seen,last_seen}` | object | As §5.1. Domain first/last-seen come from `explain().sources[]` (HOSTNAME nodes lack `threatFirstSeen/LastSeen`). Evidence only. |
| Verdict | `explain().level`/`.score` + Popularity/Trust feeds | `verdict` / `risk_score` / `level` | — | §6. |

> **Variants source:** the graph has no `LOOKALIKE_OF` edge, and the connector can only speak
> Cypher to `/api/query`. Mirror the opencti approach: generate typosquat candidates in-process
> (`homoglyph` 0.9, `omission`/`transposition`/`repetition` 0.7, `tld-swap` 0.5, `hyphenation`
> 0.3), then confirm registration with a single `UNWIND` existence query. (The richer
> `CALL whisper.variants(domain)` returns `{variant, method, exists, confidence, confidenceLabel}`
> but is a procedure, not available via plain Cypher in the same way — see §11.)

### 5.3 ASN (context only, emitted inside IP enrichment)

Never a standalone trigger. Emitted under `data.whisper.asn` when enriching an IP.

| Whisper source | → `data.whisper.asn.*` | Type | Notes |
|---|---|---|---|
| `asn.name` → int after `AS` | `number` | integer | e.g. `AS15169` → `15169`. |
| `(asn)-[:HAS_NAME]->(:ASN_NAME).name` | `name` | keyword | e.g. `GOOGLE - Google LLC`. |
| `(asn)-[:HAS_COUNTRY]->(:COUNTRY).name` | `country` | keyword | |
| `explain(asn).breakdown` | `reputation` | object | `{threatDensityScore, graphMetricsScore, historicalScore, prefixAgeScore}` + the reputation phrase. **Use `breakdown`/`explanation`, not the top-level `score`** — for ASNs the top-level `score` reflects only direct feed listing (often 0) while the actionable reputation is in `breakdown`. |

---

## 6. `explain()` → verdict / level / rule-level

> **In short:** Whisper's score is treated as *evidence*, never as the answer. The verdict comes
> from *what kind* of feeds list the IOC (phishing feed ≠ Tor list ≠ top-sites list), and "no
> data" always means `unknown` — never "safe". The verdict then sets the alert's severity.

The Whisper score is **evidence**. The connector derives `data.whisper.verdict` from the
`explain().level` enum **plus feed polarity plus coverage** — never from the score alone, and
never by parsing the human `explanation` string (the enum and the explanation text can disagree,
e.g. `level: HIGH` with explanation "Informational").

**Verdict derivation:**

| Condition (evaluated in order — first match wins) | `verdict` |
|---|---|
| `available == false` **or** `explain().found == false` **or** `coverage.shared_host == true` **or** `coverage.data_coverage == "no-data"` *(when present)* | `unknown` |
| (Popularity/Trust feeds only, e.g. `tranco-top1m` / `cloudflare-radar-top1m`) **or** `advisory == "allowlist-vouched"` **or** `node.isWhitelist` | `known_good` |
| `explain().level ∈ {HIGH, CRITICAL}` **and** ≥1 confirmed-bad feed category (C2, Malware, Phishing, Brute Force, Attack Sources, …) | `known_bad` |
| `explain().level ∈ {LOW, MEDIUM}`, or a mix of bad + trust feeds, or bad flags backed only by weak/low-quality feeds | `suspicious` |

> Ordering matters: the `unknown` gate is evaluated **first** so a `shared_host` apex or a
> `no-data` / backend-unavailable result can never be reported as `known_good`. Only
> `granularity`, `shared_host`, `found` and `available` are guaranteed present on every
> `explain()` row; `data_coverage` (hostname-only) is treated as best-effort.

> **Coverage gate — no-data ≠ benign.** A `NONE`/clean result means "not listed at this
> granularity", not "safe". A `shared_host` apex (multi-tenant, e.g. `*.s3.amazonaws.com`) does
> **not** clear a specific object under it. When coverage is `no-data`/`structural-only` or
> `shared_host` is true, the verdict is `unknown`, not `known_good`.
>
> **"Listed in N feeds" is not itself bad.** Feed *polarity* comes from the category, and
> reliability from the per-feed `weight` — `tranco` (weight 1) is good, `stamparm-ipsum`
> (weight 1.2) is bad. Gate on category + weight, not raw feed count.

**Rule level in `whisper_rules.xml`** — a base classifier at level 0 plus verdict-keyed children,
mirroring `0490-virustotal_rules.xml` (VT uses level 12 for malicious, 3 for benign):

```xml
<group name="whisper,whisper_enrichment,">

  <!-- Base classifier: level 0 = no alert, just tag the decoded event -->
  <rule id="100200" level="0">
    <decoded_as>json</decoded_as>
    <field name="integration">custom-whisper</field>
    <description>Whisper enrichment event</description>
  </rule>

  <rule id="100201" level="12">
    <if_sid>100200</if_sid>
    <field name="whisper.verdict" type="pcre2">^known_bad$</field>
    <description>Whisper: $(whisper.ioc) is KNOWN BAD ($(whisper.level)) — $(whisper.tags)</description>
  </rule>

  <!-- Escalate a known_bad to level 14 when the graph level is CRITICAL -->
  <rule id="100205" level="14">
    <if_sid>100201</if_sid>
    <field name="whisper.level" type="pcre2">^CRITICAL$</field>
    <description>Whisper: $(whisper.ioc) is KNOWN BAD (CRITICAL)</description>
  </rule>

  <rule id="100202" level="7">
    <if_sid>100200</if_sid>
    <field name="whisper.verdict" type="pcre2">^suspicious$</field>
    <description>Whisper: $(whisper.ioc) is SUSPICIOUS ($(whisper.level))</description>
  </rule>

  <rule id="100203" level="3">
    <if_sid>100200</if_sid>
    <field name="whisper.verdict" type="pcre2">^known_good$</field>
    <description>Whisper: $(whisper.ioc) is known good</description>
  </rule>

  <rule id="100204" level="3">
    <if_sid>100200</if_sid>
    <field name="whisper.verdict" type="pcre2">^unknown$</field>
    <description>Whisper: no graph data for $(whisper.ioc)</description>
  </rule>

</group>
```

| `verdict` | rule level | rationale |
|---|---|---|
| `known_bad` | 12; **14** when `level == CRITICAL` (rule 100205) | 12 = VT-malicious parity; 14 is a Whisper-specific escalation, not a VT precedent |
| `suspicious` | 7 | analyst-review band |
| `known_good` | 3 | low-noise informational |
| `unknown` | 3 (set to 0 to suppress — a noise-policy call, §11 Q8) | informational |

Two matching subtleties, both handled above:

- **`<field>` matches by substring (osmatch), not exact.** The four verdict literals are mutually
  non-substring today, but they are anchored with `type="pcre2">^…$` so a future verdict value —
  or a stray `explanation` string — can never false-match.
- The field names carry **no `data.` prefix** (§2.2). Children omit `<decoded_as>` (only the base
  rule 100200 needs it) — matching the in-tree VT/maltiverse rule pattern.

The `whisper_enrichment` group and rule-id range `100200+` (native rules stay below 100000) matter
for feedback-loop prevention (§8).

---

## 7. Idempotency & dedup strategy

> **In short:** Wazuh alerts can't be updated, only appended — so instead of "overwrite the old
> answer" the script checks a small on-disk cache *before sending*: if this IOC was enriched
> recently (within the TTL), it stays silent. Same IOC, 500 hits, one enrichment alert.

**The core asymmetry with the sister connector.** `whisper-opencti` is idempotent by
**upsert**: STIX SCOs get spec-deterministic IDs from their key properties and SDOs/relationships
get deterministic `generate_id` UUIDv5s, so re-enriching produces the *same* IDs and OpenCTI
*updates in place*. **Wazuh has no upsert.** An injected alert is a new, immutable event appended
to `wazuh-alerts-*`; you cannot "re-write" a prior enrichment. Therefore idempotency here is
achieved by **dedup-before-emit**, not by stable IDs after the fact. Note the Wazuh alert `id`
(§2.1) is **not** the dedup key — it is unique per emitted event, so it could never *suppress* a
duplicate; dedup keys on IOC identity (`dedup_key`, below).

**Strategy:**

1. **Stable structure → stable key.** Deterministic field ordering and values (the same IOC +
   graph state always serialises identically) is what makes the dedup key itself stable. This is
   the Wazuh analogue of opencti's stable-ID guarantee.
2. **Dedup key:** `dedup_key = "{type}|{ioc}|{agent_id}"`. `agent_id` is **config-gated**:
   include it for per-endpoint dedup (the same IOC on two hosts = two analyst-relevant events);
   drop it for org-wide dedup. (Compare: opencti keys SCO IDs off value(+type); the Whisper
   Splunk add-on caches keyed by `indicator + type`, TTL 3600 s.)
3. **Check first — before the Whisper lookup.** On each triggering alert, compute `dedup_key`;
   if it is present and unexpired in the cache, **skip the enrichment entirely — no Whisper API
   call, no socket send** (saves API budget and makes the skip observable as a single log line).
   Otherwise enrich, emit, and record the key with a timestamp. This directly satisfies issue #1
   AC #8: *"re-running within the dedup TTL produces no duplicate enrichment alerts."*
4. **TTL:** default 3600 s (Splunk-add-on parity). After expiry a fresh enrichment alert is
   allowed — intentional re-surfacing of still-relevant context.
5. **Persistent cache — required.** `integratord` **spawns the script per matching alert**, so an
   in-process dict does **not** persist between alerts and would never dedup. The cache **must** be
   cross-invocation: a small file / SQLite / on-disk KV at **`/var/ossec/var/whisper/dedup.db`**
   (normative path), pruned by TTL. It must also be **flushable** (a plain file delete resets
   state) and the **TTL configurable** via the `<options>` channel (§2.3) — both are
   acceptance-test requirements. **This is a firm design requirement, called out here because it
   is easy to get wrong.**
6. `schema_version` lets the dedup/rules contract evolve without silently colliding old and new
   payload shapes.

---

## 8. Determinism guarantees (opencti #61)

> **In short:** the same input must always produce the same output — every graph query is
> precise and directional, nothing is dropped silently, every capped list says how much was cut,
> and the payload always fits the socket. These rules make the enrichment predictable and the
> dedup key stable.

Carried over from the sister connector's determinism work and issue #1 AC #4–7:

- **Category-specific directional builders.** One anchored query per category (§5.2), never a
  broad undirected `MATCH (n)-[r]-(m)`. Each query already knows which end is the neighbour, so
  no column-order direction reconstruction is needed.
- **Correct edge direction.** `RESOLVES_TO` domain→IP; `ALIAS_OF` domain→CNAME; **`NAMESERVER_FOR`
  and `MAIL_FOR` read with `<-`** (neighbour→seed). Getting these backwards silently returns wrong
  data.
- **Stable, human-readable keys.** `whois.registrar` vs `whois.previous_registrar`, `dns.mx` vs
  `dns.ns` — never raw Whisper edge names. When one node qualifies for two keys, resolve
  deterministically (current-state wins; **query `registrar` before `previous_registrar`**;
  dedup edges by `(source, target, type)` first-writer-wins).
- **No silent drops.** Whisper data the connector sees but does not map is summarised in
  `unmapped_summary` (e.g. `"3 CT observations, 2 TLS fingerprints not mapped"`), never dropped
  silently. (This *reverses* opencti's silent-drop default for unmappable STIX labels.)
- **Explicit truncation.** Every capped list emits both the displayed slice **and** a total:
  `links.inbound[]` + `links.inbound_total`, plus a top-level `truncated: true`. Because hub-domain
  `LINKS_TO` fan-out exceeds 1 M (exact `count()` errors), totals are **bounded counts**
  (count-up-to-ceiling), not guaranteed exact — the ceiling is documented, not hidden.
- **Cypher safety.** Whisper's endpoint does **not** support bound parameters; the IOC must be
  **JSON-escaped and inlined** as a quoted Cypher string literal (integers inlined as integers).
  This is both a correctness and an **injection-safety** requirement.
- **Payload guard.** Serialised `data.whisper.*` is budgeted well under 60 KB; on overflow the
  connector drops the largest optional lists first and sets `unmapped_summary` +
  `verdict`/core fields, falling back to a `payload_too_large` marker rather than a failed send
  (§2.3 size limit).

---

## 9. IOC extraction — `SUPPORTED_FIELD_PATHS`

IOCs are pulled from a maintained table of dotted alert-field paths, each with a type hint;
IPs are validated with stdlib `ipaddress` and **non-global IPs are skipped**. An IP arriving via
a "domain" path is still treated as an IP (normalise with `ipaddress` first).

> This table has **no sister-connector precedent** (OpenCTI hands the connector a typed
> observable; it never parses alert JSON). The starter set below is inferred from Wazuh 4.14.x
> decoder conventions and **must be validated against a real 4.14.5 alert corpus** from the dev
> stack (issue #8 agent) before it is locked — see §11.

| Path (rules-XML name; query as `data.…`) | Hint | Notes |
|---|---|---|
| `srcip`, `dstip`, `src_ip`, `dst_ip` | ip | Core network decoders. |
| `win.eventdata.ipAddress`, `win.eventdata.sourceIp`, `win.eventdata.destinationIp` | ip | Windows/Sysmon. |
| `aws.sourceIPAddress`, `gcp.jsonPayload.sourceIP`, `office365.ClientIP` | ip | Cloud audit. |
| `audit.remote_ip`, `remote_ip` | ip | Linux audit / generic. |
| `agent.ip` | ip | Usually internal → skipped by the public-IP guard. |
| `dns.question.name`, `win.eventdata.queryName` | domain | DNS / Sysmon event 22. |
| `win.eventdata.destinationHostname`, `http.hostname`, `url` (host component) | domain | Proxy / web. |
| `syscheck.path`, `syscheck.sha256_after` | (context) | **Documented-but-inactive** — hash triggers are out of MVP scope; listed for the future. |

MVP triggers are **only** IPv4/IPv6/Domain (issue #1 §3.1). URL/hash/email paths are recorded
but not extracted.

---

## 10. Post-MVP & the CDB sink

### 10.1 CDB list format (Pattern B — feed / detection direction)

For the post-MVP feed milestone, Whisper indicators are pushed into **CDB lists** for real-time
matching (detection, not enrichment):

- **On disk:** plain text, one `key:value` per line, under `/var/ossec/etc/lists/<name>`
  (no extension); Wazuh compiles it to a `.cdb` binary on load. Value may be empty (`key:`).
  Keys containing colons are quoted (`"a0:a0:…":`). IP subnet keys use a trailing-dot dotted-quad
  prefix (`192.168.:` = /16, `10.1.1.1:` = /32) with `lookup="address_match_key"`.
- **Register:** `ossec.conf` → `<ruleset><list>etc/lists/<name></list>`.
- **Match in rules:** `<list field="srcip" lookup="address_match_key">etc/lists/whisper-bad-ip</list>`
  (lookups: `match_key`, `not_match_key`, `address_match_key`, `match_key_value`,
  `not_match_key_value` + `check_value`). Restart `wazuh-manager` after edits.

### 10.2 Other post-MVP items

Dashboard "enrich this" plugin (Pattern D); ASN/URL/hash/email triggers (as graph coverage
allows); historical-alert backfill (indexer-side reader); optional upstream to `wazuh/integrations`.

---

## 11. Open questions

Flagged by the research pass; to resolve before/while implementing:

1. **`SUPPORTED_FIELD_PATHS` validation.** The §9 table is inferred, not corpus-validated.
   Validate against real 4.14.5 alerts from the dev-stack agent before locking.
2. **Dedup cache backend & scope.** Confirm the persistent store (file/SQLite under `/var/ossec`),
   the TTL value, and whether `agent_id` is in the key by default (per-endpoint vs org-wide).
3. **Agent attribution (Form A vs B).** This spec recommends **Form B** (stamp onto the
   originating agent). Confirm — it affects how the enrichment alert correlates in the dashboard.
4. **`related.neighbors[]` for IPs.** Reverse `RESOLVES_TO` / co-host enumeration is rejected as an
   unanchored scan. Decide the source (a Whisper co-hosting/attack-surface workflow, or
   passive-DNS/PTR) or mark the field deferred.
5. **Feed polarity map.** `explain().sources[]` gives `feedId` + `weight` but not category inline,
   and `LISTED_IN → CATEGORY` is inconsistent. Ship a static `feedId → category/polarity` map
   (from the feed-catalog / feed-categories docs) so §6 can classify good vs bad reliably.
6. **`owner` / `business_unit` (IP).** Issue #1 §3.5 lists these, but there is **no Whisper graph
   source** for them — they are asset-inventory (Wazuh-side) data. Either wire them from an asset
   list or mark them deferred. (`tags[]` **is** derivable from Whisper flags/categories and is
   kept.)
7. **Timestamp units.** Emit `threat_feed.first_seen`/`last_seen` as **ISO-8601** (from
   `explain().sources[]`); note that node `threatFirstSeen/LastSeen` are epoch-ms — never mix the
   two into the same keyword/date field (§2.4 type rule).
8. **`unknown` verdict level.** Level 3 (informational) vs 0 (suppress) is a team noise-policy
   call.
9. **Indexer template install path.** Confirm whether 4.14.5's wazuh-indexer uses a legacy
   `_template`, a composable index template, or component templates, so the explicit `data.whisper`
   mapping block (§2.4) is installed correctly **before first ingest**.
10. **IPv4/IPv6/domain `threat_feed` parity.** Issue #1 put `flags[]` under domain and `tags[]`
    under IP; this spec harmonises both types to the same `threat_feed.*` + `tags[]` shape for
    consistency and idempotency. Confirm the harmonisation is acceptable.

---

## Change log / provenance

- **v1.1 (2026-07-03):** acceptance-plan alignment (from the #5 verification pass): dedup check
  now explicitly runs **before** the Whisper lookup (§0 diagram + §7.3 agreed); §2.3 script
  contract extended with the empirically-verified `argv[5..7]` (options file / timeout / retries)
  and the `<options>`-driven `api_url`/`dedup_ttl` knobs; §7.5 cache path made normative
  (`/var/ossec/var/whisper/dedup.db`, flushable, TTL configurable); §4.1 example updated with the
  real AS60729 values (and `asn.name` noted as nullable — no `HAS_NAME` edge, verified live).
- **v1.0 (2026-07-02):** initial mapping spec. Derived from the locked decisions in
  [#1](https://github.com/whisper-sec/whisper-wazuh/issues/1) (scope, `data.whisper.*` schema),
  [#2](https://github.com/whisper-sec/whisper-wazuh/issues/2) (Pattern A) and
  [#4](https://github.com/whisper-sec/whisper-wazuh/issues/4) (target 4.14.5); the sister connector
  [`whisper-opencti`](https://github.com/whisper-sec/whisper-opencti) (idempotency/determinism
  model); the live Whisper graph (node/edge schema + `explain()` output, verified 2026-07-02); and
  Wazuh 4.14.5 source (`integrations/virustotal.py`, `integrations/maltiverse.py`,
  `ruleset/rules/0490-virustotal_rules.xml`, `0997-maltiverse_rules.xml`,
  `extensions/elasticsearch/7.x/wazuh-template.json`).