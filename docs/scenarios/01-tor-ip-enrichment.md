# Scenario 01 — Tor exit IP enrichment

A captured, reproducible walk-through of the connector's end-to-end path: a benign-looking SSH
alert carries a public IP; the connector recognises it, asks the Whisper graph about it, and
writes back a **new** alert enriched with `data.whisper.*`.

> **Values drift, the shape must not.** The feeds, scores, and neighbour counts below were
> captured live on **2026-07** and will change as the graph updates. What this scenario pins is
> the *shape* of each stage — an implementation that reproduces the shape is correct.

Reproduce it (connector installed, a real key in `/var/ossec/etc/whisper.key`):

```sh
make dev-demo-enrich                 # default IOC = 185.220.101.1
make dev-demo-enrich IOC=8.8.8.8     # try another
```

---

## 1. Seed — the indicator

`185.220.101.1` — a **Tor exit node**. It is listed in several threat feeds, and its announced
prefix `185.220.101.0/24` is itself flagged (CRITICAL, with 151 threat-listed neighbours in the
same /24). It is deliberately *not* a confirmed-bad C2/malware host — which is exactly why it
exercises the evidence-derived verdict (below).

Why this seed and not `203.0.113.45`? The latter is TEST-NET-3 (non-global); the connector's
public-IP guard skips it by design, so it would produce no enrichment.

## 2. Trigger event — the alert that fires the integration

A stock SSH failed-password line, decoded by Wazuh as `sshd` rule **5710**, carrying the IP in
`data.srcip`. `make dev-demo-enrich` injects this onto the manager's analysisd queue:

```
1:whisper-demo:Jul  7 22:35:44 host sshd[9]: Failed password for invalid user demo from 185.220.101.1 port 4444 ssh2
```

integratord runs `custom-whisper` on the alert; the connector extracts the global IP from
`data.srcip` and enriches it. Log evidence (`/var/ossec/logs/integrations.log`, `debug` on):

```
whisper: invoke ioc=185.220.101.1 type=ipv4 dedup_key=ipv4|185.220.101.1|000
whisper: api url=https://graph.whisper.online ms=137
whisper: emit dedup_key=ipv4|185.220.101.1|000 payload_bytes=1385
```

## 3. Real captured Whisper response — the injected envelope

The connector builds one `data.whisper.*` envelope and writes it back onto the queue as a new
event (`integration = custom-whisper`). Captured shape (nulls stripped before send):

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
    "risk_score": 7.46,
    "level": "HIGH",
    "asn": { "number": 60729, "country": "DE", "reputation": { "threatDensityScore": 30 } },
    "prefix": "185.220.101.0/24",
    "prefix_threat": { "level": "CRITICAL", "score": 14, "is_threat": true, "threat_neighbor_count": 151 },
    "geo": { "country": "DE", "city": "Brandenburg, DE" },
    "threat_feed": {
      "feeds": ["dan-tor-exit", "stamparm-ipsum", "tor-exit-nodes", "greensnow"],
      "categories": ["TOR Network", "General Blacklists"],
      "flags": ["isThreat", "isTor", "isSpam", "isAnonymizer"],
      "sources_count": 4
    },
    "tags": ["tor", "anonymizer", "spam"],
    "coverage": { "granularity": "ipv4" },
    "dedup_key": "ipv4|185.220.101.1|000",
    "source_ref": { "rule_id": "5710", "field_path": "data.srcip" }
  }
}
```

> **Why `suspicious`, not `known_bad`, at `level: HIGH`?** The verdict is derived from *evidence*,
> not the raw score (mapping §6): the feeds are Tor / anonymizer / general-blocklist categories —
> no confirmed-bad category (C2, malware, phishing) — so despite a HIGH level the verdict is
> `suspicious`. The granular `prefix_threat` (the /24 is CRITICAL) rides along as context.

## 4. Resulting enrichment alert — as indexed

analysisd re-decodes the injected JSON, the whisper rules map the verdict to a severity, and the
alert lands in `wazuh-alerts-*`. **analysisd stringifies every value**; the indexer template
(`whisper-template.json`) coerces the numeric/boolean fields back at index time, so a range query
on `data.whisper.prefix_threat.score` works even though `_source` shows the string. Captured
`_source` (subset):

```json
{
  "rule": { "id": "100202", "level": 7, "description": "Whisper: 185.220.101.1 is SUSPICIOUS (HIGH)" },
  "data": {
    "integration": "custom-whisper",
    "whisper": {
      "verdict": "suspicious",
      "prefix": "185.220.101.0/24",
      "prefix_threat": { "level": "CRITICAL", "score": "14", "is_threat": "true", "threat_neighbor_count": "151" },
      "asn": { "number": "60729" }
    }
  }
}
```

Field mapping: `data.whisper.prefix_threat.score` indexes as `float`, `threat_neighbor_count` as
`long`, `is_threat` as `boolean`, `level` as `keyword` — verified with a live range query
(`score >= 10 AND is_threat: true` matched this alert).

---

**Loop guard.** The enrichment alert carries the `whisper_enrichment` group, which the
`<integration>` trigger filter never watches — so a re-decoded enrichment alert can never
re-invoke the connector (mapping §8).