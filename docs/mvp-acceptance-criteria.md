# whisper-wazuh MVP — success criteria & acceptance tests

**Status:** met in **v1.0.0** — all criteria verified on **Wazuh 4.14.5** · resolves
[#5](https://github.com/whisper-sec/whisper-wazuh/issues/5)

Defines what **done** means for the MVP connector: the functional acceptance criteria, the test
case matrix, non-functional targets, and the demo/validation plan. Companion to the
[mapping spec](whisper-to-wazuh-mapping.md) (the *what*); this document is the *proof* — every
criterion below is verifiable with a runnable command against the [dev stack](../dev/README.md).

Structure mirrors the sister project's QA handoff (`whisper-opencti/docs/qa-handoff.md`), as
issue #5 asks, adapted to Wazuh: pinned test seeds → test-case matrix → known limitations →
severity guide → sign-off checklist. Wazuh-side mechanics (log lines, latencies, restart
semantics) were **verified empirically on the live 4.14.5 dev stack** on 2026-07-02.

---

## 0. Definition of done (summary)

The MVP is **done** when, on a fresh dev stack (`make dev-up` + `install.sh`):

1. **TC-01 … TC-22 all pass** (§3).
2. **The demo scenario reproduces** (§7) — live graph values will drift; *shape and types must
   match* the captured example.
3. **Zero open S1/S2 bugs**; every open S3/S4 has a follow-up ticket and an owner (§6).
4. **No real API key** exists anywhere in the repo or in `ossec.conf` (TC-19).

This is the Wazuh version of opencti's 4-item sign-off; it is restated — and extended with the
doc-level exit items (mapping-question resolution, product-owner approval) — in §8.

---

## 1. Test environment & sanity check

### 1.1 Setup

```bash
make dev-init && make dev-up          # stack: manager + indexer + dashboard (+ optional agent)
cd integrations/whisper && ./install.sh   # copies files, patches ossec.conf, restarts manager
```

Facts the suite must respect (verified on this stack):

| Fact | Consequence for tests |
|---|---|
| `wazuh-control restart` ≈ **11–15 s** to alert-generating | budget 20 s after any config/rule change; prefer in-container restart over `docker restart` (30–90 s) |
| integratord tails `alerts.json` **from EOF** | inject trigger events only **after** `Enabling integration for: 'custom-whisper'.` appears in `ossec.log`; alerts fired while the manager restarts are *permanently* skipped |
| `ossec.conf` must stay `root:wazuh 660`; scripts `root:wazuh 750` | any tooling that rewrites these files must restore ownership/mode (a `root:root` conf **breaks the manager**) |
| script debug output goes to `/var/ossec/logs/integrations.log` **only when** integratord debug is on | test runs enable it once: `docker exec wazuh-single-node-wazuh.manager-1 sh -c "echo 'integrator.debug=2' >> /var/ossec/etc/local_internal_options.conf"` then `wazuh-control restart` (a bare `echo >>` inside `docker exec` redirects on the **host** and silently does nothing) |
| script argv (empirical) | `argv[1]`=alert tmp file (JSON, one line) · `argv[2]`=api_key · `argv[3]`=hook_url · `argv[4]`=`debug`/`''` · `argv[5]`=options tmp file/`''` · `argv[6]`=timeout (default `10`) · `argv[7]`=retries (default `3`) — read positionally, never rely on `argc` |
| dedup cache lives at `/var/ossec/var/whisper/dedup.db` (SQLite, normative — mapping §7.5) | **reset between stateful TCs:** `docker exec wazuh-single-node-wazuh.manager-1 rm -f /var/ossec/var/whisper/dedup.db*` — the `*` also clears any `-journal` left by a crashed mid-write; TC-01/09/12/17 start from a clean cache |
| config knobs `api_url`, `dedup_ttl`, `dedup_scope` resolve `<options>` JSON (argv[5]) → env (`WHISPER_API_URL`/`WHISPER_DEDUP_TTL`/`WHISPER_DEDUP_SCOPE`) → default (mapping §2.3) | required implementation knobs — TC-10/TC-13 are untestable without them (§5 item 6) |
| the indexer template (`whisper-template.json`, legacy `_template/whisper` at order 1 — mapping §4.3) applies to **new indices only**, and `wazuh-alerts-4.x-*` roll daily | install the template **before** the first enrichment TC, then delete the current day's alerts index so it re-creates typed — else `risk_score` range queries (TC-20-family) silently hit `keyword` fields |

### 1.2 Sanity check (green path, before any TC)

1. `docker exec wazuh-single-node-wazuh.manager-1 grep "Enabling integration for: 'custom-whisper'" /var/ossec/logs/ossec.log` → **≥ 1 line** (emitted on every integratord start; the load-bearing assertion is *presence after the most recent restart*, not count).
2. Inject a trigger alert (no agent needed — manager-only socket injection):
   ```bash
   docker exec wazuh-single-node-wazuh.manager-1 /var/ossec/framework/python/bin/python3 -c \
   "import socket,time; s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.connect('/var/ossec/queue/sockets/queue'); \
   s.send(('1:whisper-test:'+time.strftime('%b %e %H:%M:%S')+' host sshd[9]: Failed password for invalid user admin from 185.220.101.1 port 4444 ssh2').encode())"
   ```
   (fires rule **5710**; `invalid user` matters — `for root` fires 5760 instead).
3. Within ~2 s integratord invokes the script (1 s poll loop); within **60 s** the enrichment
   alert is searchable:
   ```bash
   curl -sk -u admin:SecretPassword "https://localhost:9200/wazuh-alerts-*/_search?filter_path=hits.total,hits.hits._source" \
     -H 'Content-Type: application/json' -d '{"query":{"bool":{"filter":[
       {"term":{"data.integration":"custom-whisper"}},
       {"term":{"data.whisper.ioc":"185.220.101.1"}},
       {"range":{"timestamp":{"gte":"now-2m"}}}]}},"sort":[{"timestamp":"desc"}],"size":1}'
   ```
4. The hit has `rule.id` in the 10050x range, populated `data.whisper.*`, and `agent`/`source_ref`
   linkage.
5. The dashboard (*Security events*, filter `data.integration:custom-whisper`) shows the alert.
6. **Seed pre-flight:** before running the matrix, `explain()` each §2 seed and compare its
   category/advisory profile against the pinned table; on drift, **re-pin the seed** (a plan
   update, S4) instead of failing TCs — so TC failures are attributable to the connector, not
   the live graph.

Measured baseline: socket send → searchable in **7.6–17 s** idle (analysisd <1 s, filebeat 1–3 s,
index refresh 5 s). Tests **poll every 1–2 s with a 60 s ceiling** — never assert a fixed latency.
Negative assertions (no alert expected) use the **same 60 s ceiling** before declaring pass.
`rule.id` is a **keyword string** in the wazuh template — in DSL use quoted values
(`{"terms":{"rule.id":["100501","100502"]}}`), never a numeric range query.

---

## 2. Test data — pinned seeds

Stable, real-world seeds with expected outcomes (mirroring opencti §2's discipline). Expected
verdicts follow the mapping spec §6 evidence rules — they are part of the contract.

| Seed | Type | Whisper state (2026-07-02) | Expected outcome |
|---|---|---|---|
| `185.220.101.1` | IPv4 | Tor exit; 4 feeds (Tor/blacklist categories); level HIGH | enrich → **`suspicious`** (rule 100502, level 7). *Not* `known_bad` — Tor/anonymizer is not a confirmed-bad category. Validates evidence-based verdicts. |
| `8.8.8.8` | IPv4 | DNS-filter feeds only; `advisory: allowlist-vouched` | enrich → **`known_good`** (rule 100503, level 3) |
| `google.com` | Domain | Popularity/Trust feeds only (tranco, cloudflare-radar); rich DNS/WHOIS/SPF/links | enrich → **`known_good`**; exercises every mapping-§5.2 category incl. >1 M `LINKS_TO` truncation |
| `2001:4860:4860::8888` | IPv6 | clean, graph-known | enrich → `known_good`/`unknown` per coverage; proves IPv6 parity |
| `this-should-never-exist-12345.invalid` | Domain | guaranteed absent (reserved TLD) | enrich → **`unknown`**, `known:false` (rule 100504). RFC 5737 IPs are **not** reliable no-data seeds — Whisper has BGP/DNS coverage for them. |
| `10.0.0.5`, `192.168.1.10` | IPv4 | private (RFC 1918) | **skipped** — no Whisper call, no enrichment alert |
| `203.0.113.45` | IPv4 | TEST-NET-3 → `ipaddress.is_global == False` | **skipped** — ⚠ this is the current `make dev-agent-demo` IOC; see §5 item 2 |

Seed profiles **drift with the live graph** (feed listings churn; the allowlist advisory is a
live property). The §1.2 step-6 pre-flight catches drift before the matrix runs; a drifted seed
is re-pinned as a plan update (S4), never filed as a connector bug.

---

## 3. Functional acceptance criteria & test-case matrix

Wazuh has no work-item status string (opencti's primary QA observable). The machine-readable
contract here is threefold: **(a)** the emitted enrichment alert's fields, **(b)**
`integrations.log` lines (debug on), **(c)** `ossec.log` integratord lines. Every *Expected*
below keys off those.

**Failure-line vocabulary** (from `integrator.c`, exact): script non-zero exit →
`Unable to run integration for custom-whisper -> integrations` + `Exit status was: <N>`; script
missing → `Unable to enable integration for: 'custom-whisper'. File not found inside 'integrations'.`

**Script log-line vocabulary** — *normative for the implementation*. The script must emit these
grep-able lines to `/var/ossec/logs/integrations.log` (gated on `argv[4]=='debug'`, the
`virustotal.py` convention); they are what the TCs below grep for:

| Line (grep token) | Emitted when |
|---|---|
| `whisper: invoke ioc=<v> type=<t> dedup_key=<k>` | every invocation that extracted an IOC |
| `whisper: skip reason=non-global ioc=<v>` | public-IP guard fired |
| `whisper: skip reason=dedup dedup_key=<k>` | dedup suppression — **no API call, no send** |
| `whisper: skip reason=no-ioc` | filter-matched alert where **no** supported field path held any value (a path holding a non-IOC value is *present* and gets a debug line instead) |
| `whisper: skip reason=unsupported-type field=<path>` | inactive hash/path candidate ignored (out of MVP scope) |
| `whisper: skip reason=self-alert` | input alert already carries `data.integration=custom-whisper` — loop guard #3 (defense in depth behind the filter + rule-group separation) |
| `whisper: api url=<api_url> ms=<n>` | each Whisper HTTP call |
| `whisper: error class=<auth\|transport\|query\|socket> detail=<…>` | failure taxonomy (opencti's classes + `socket` for analysisd-socket failures, #16) |
| `whisper: emit dedup_key=<k> payload_bytes=<n>` | datagram sent to the analysisd socket |

**Domain trigger mechanism** (used by TC-02/03-fallback/06/15/22): raw syslog lines cannot yield
a domain field, so domain TCs inject a **JSON event** and match it with a **dev-only test rule**
shipped by `install.sh --dev` (`whisper_test_rules.xml`, rule id `100290`, matching a
`whisper_test` **sentinel** field — `<field name="whisper_test" type="pcre2">^1$</field>` — so it
can never fire on real DNS logs; the injected event also carries `dns.rrname` (the Q1-validated
domain path) for the connector to extract; level 3, group `whisper_test` — included in the
`<integration>` filter's `<group>` **only** in dev mode). Injection:

```bash
docker exec wazuh-single-node-wazuh.manager-1 /var/ossec/framework/python/bin/python3 -c \
"import socket; s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.connect('/var/ossec/queue/sockets/queue'); \
s.send(b'1:whisper-test:{\"whisper_test\":\"1\",\"dns\":{\"rrname\":\"google.com\"}}')"
```

Stateful TCs (01/09/12/17) begin with the **dedup reset** from §1.1
(`rm -f /var/ossec/var/whisper/dedup.db*`) — without it, earlier runs of the same seed suppress
the expected alert and produce false failures.

| ID | Scenario | Steps | Expected |
|---|---|---|---|
| TC-01 | Green path — threat IPv4 | **Reset dedup**, then sanity-check injection with `185.220.101.1` | Enrichment alert ≤60 s: `rule.id:"100502"` (level 7), `data.whisper.verdict:suspicious`, `asn.number > 0` (= 60729; `asn.name` may be null — AS60729 has no `HAS_NAME` edge, verified), `geo.country:"DE"`, `threat_feed.{feeds[≥1],flags[],sources_count,first_seen,last_seen}`, `source_ref.rule_id:"5710"`, `dedup_key` set |
| TC-02 | Green path — domain | Inject the pinned JSON domain event (§3 mechanism) with `google.com` | Enrichment alert: `type:domain`, `verdict:known_good`, `dns.{a[],aaaa[],ns[],mx[]}` non-empty, `whois.registrar` set, `spf` object, `links.*_total` present, `variants[]` schema-valid |
| TC-03 | Green path — IPv6 | Inject the §1.2 sshd line with `2001:4860:4860::8888` as the source | Enrichment alert: `type:ipv6`; same envelope as IPv4; `geo` via CITY/ASN (IPv6 has no `HAS_COUNTRY`). **Verify-once:** if the 4.14.5 sshd decoder does not capture an IPv6 `srcip`, route through the §3 JSON mechanism with an ip-hinted field instead |
| TC-04 | Private IP skipped | Inject 5710 with `10.0.0.5` | `whisper: skip reason=non-global` line (immediate, load-independent); **no `whisper: api` line**; indexer `_count == 0` at **T+60 s** |
| TC-05 | TEST-NET IP skipped | Inject with `203.0.113.45` | Same as TC-04 — documents that the stock `dev-agent-demo` IOC does **not** enrich (public-IP guard, `is_global == False`) |
| TC-06 | No-data seed | Inject the §3 JSON domain event with `this-should-never-exist-12345.invalid` | Enrichment alert `rule.id:"100504"` (level 3): `known:false`, `verdict:unknown`, `graph_node_id:null`; **no crash**. *Note: this pins mapping §11 Q8 as level 3 (alert, not suppress) — amending Q8 later means amending this TC and TC-16* |
| TC-07 | Known-good | Inject with `8.8.8.8` | **Evidence-dependent verdict** (this is the point of the TC): `known_good` (rule 100503) *while* the IP is listed only in trust/DNS-filter feeds — driven by `advisory:allowlist-vouched`. If the live graph later adds *threat* evidence (a blacklist/anonymizer flag), the verdict correctly downgrades to `suspicious` — **trust never overrides threat** (§6). *(As of 2026-07 the live `8.8.8.8` carries an `isBlacklist` flag → `suspicious`; the QA runner therefore asserts the stable invariants: `advisory:allowlist-vouched` + `asn.number:15169` + an evidence-derived verdict, not a hard `known_good`.)* |
| TC-08 | Evidence-based verdict | Compare TC-01 vs TC-07 artifacts | Two concrete cross-artifact assertions: TC-01 has `level:HIGH` yet `verdict:suspicious` (not `known_bad`); TC-07 has `threat_feed.sources_count ≥ 1` yet `verdict:known_good`. The design property "verdict is never a score copy" is code-review-verified (scope AC#3) |
| TC-09 | Dedup within TTL | **Reset dedup**, fire the TC-01 injection **twice**, 10 s apart | Run 1: `invoke` + `api` + `emit` lines. Run 2: `invoke` + `whisper: skip reason=dedup` — **no `api` line, no `emit` line**. Indexer `_count == 1` at T+60 s (scope AC#8) |
| TC-10 | Dedup expiry | Set `dedup_ttl` to a test value via `<options>` (§1.1 knob), fire, wait TTL+ε, fire again | Two enrichment alerts — re-surfacing after expiry is intentional |
| TC-11 | Feedback-loop prevention | After TC-01's enrichment alert lands, wait ≥10 s | **No new `whisper: invoke` line** for the enrichment alert and no second 10050x alert. integratord evaluates *every* `alerts.json` line with **no origin exclusion** — only the filter + distinct `whisper_enrichment` group prevents the loop |
| TC-12 | Bad API key | **Reset dedup** (else dedup short-circuits before the API call and the script exits 0), set an invalid key, restart, inject TC-01's seed | `whisper: error class=auth` line; script exits non-zero; `ossec.log` shows `Exit status was:` ≠0; **no enrichment alert**; manager healthy |
| TC-13 | Whisper API unreachable | Set `<options>{"api_url":"https://localhost:1/"}` (§1.1 knob), restart, inject | Bounded retries/backoff honouring argv timeout(10)/retries(3); `whisper: error class=transport` line (auth ≠ transport ≠ query); no enrichment alert; no integratord hang |
| TC-14 | Degraded scoring (`available:false`) | **Unit tier:** feed fixture `tests/fixtures/explain_unavailable.json` (`available:false` + `retryAfter`) through the verdict/envelope builder (pytest + `responses`) | Built payload has `available:false`, `verdict:unknown`; backoff honours `retryAfter`. Degraded-but-answering ≠ unreachable (TC-13). Live reproduction not required |
| TC-15 | Payload guard | Uses the TC-02 event (`google.com`, >1 M links) | Enrichment alert present **and** no `Exit status was:` line (an `errno 90` overflow would crash the send); `len(links.inbound[]/outbound[]) ≤` documented cap; `*_total` present; `truncated:true`; `whisper: emit … payload_bytes=<n>` with `n < 61440` (scope AC#7) |
| TC-16 | Rules render all verdicts | **After install.sh**, run one `wazuh-logtest` invocation per event (verified stdin mode), e.g. `printf '%s\n' '{"integration":"custom-whisper","whisper":{"verdict":"known_bad","level":"CRITICAL","ioc":"x"}}' \| docker exec -i wazuh-single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest` — 5 events: known_bad, known_bad+CRITICAL, suspicious, known_good, unknown | Pass grep per event: Phase 3 shows the expected rule id and `**Alert to be generated.` — 100501→12, 100505→14, 100502→7, 100503→3, 100504→3. **Scope:** these are the five verdict→level rules; the opt-in TLS rule 100506 (`whisper.tls.family=cobalt-strike-default`→12) is off by default and exercised via the `tls_fingerprint` enrichment path, not this verdict matrix. **Caveat:** logtest loads rules fresh from disk — a pass does *not* prove live analysisd has them; TC-01 covers live |
| TC-17 | Determinism / stable structure | Run TC-01, **reset dedup**, run again; diff the two `data.whisper` objects | Identical key set and types (values may drift with the live graph); truncated lists always carry totals; `unmapped_summary` populated when data was dropped (scope AC#6) |
| TC-18 | install.sh end-to-end | Fresh manager (`make dev-reset` + up), run `install.sh` | Files land with `root:wazuh 750`; `ossec.conf` patched **and still `root:wazuh 660`**; restart OK; sanity check §1.2 passes (scope AC#9) |
| TC-19 | Secrets handling | Scan repo + `ossec.conf` for the key-format regex (real keys are UUID-shaped, e.g. `[0-9a-f]{8}-[0-9a-f]{4}-…`); the shipped placeholder literal is `WHISPER_API_KEY_PLACEHOLDER`. During an injection, sample `/proc/<pid>/cmdline` of the running script in a tight loop | No regex hit anywhere in repo/conf; key resolves env → `/var/ossec/etc/whisper.key` (`640 root:wazuh`) → argv. **Note:** if `<api_key>` *is* set in `ossec.conf`, integratord passes it as `argv[2]` and it **will** appear in the process cmdline — which is exactly why the recommended tiers leave it as the placeholder; cmdline sampling must show only empty/placeholder (scope AC#10) |
| TC-20 | uninstall.sh + type stability | Run `uninstall.sh`; then reinstall and enrich **two different seeds** (`185.220.101.1`, then `8.8.8.8` — same-seed pairs collide with dedup) | Uninstall: integration files removed, `ossec.conf` restored, manager restarts clean. Reinstall: **both** alerts findable by `dedup_key` in the indexer, and zero hits for `mapper_parsing_exception` in the manager's filebeat log over the test window (types locked by the mapping §4.3 template block) |
| TC-21 | No extractable IOC | Inject a filter-matched alert containing **no** `SUPPORTED_FIELD_PATHS` hit | `whisper: invoke`-less run: `whisper: skip reason=no-ioc` line, exit 0, no `api` line, `_count == 0` at T+60 s |
| TC-22 | Out-of-scope IOC types | Inject a filter-matched alert whose only candidates are hash/path fields (`syscheck.sha256_after` / `syscheck.path` — the inactive rows, mapping §9). *Note `data.url` is ACTIVE (host component of absolute URLs) and is covered by TC-02-family tests, not this one.* | `whisper: skip reason=unsupported-type` line per field; no lookup, no enrichment alert |

Each TC maps back to the scope's acceptance criteria (issue #1 §4) — traceability table in §9.

---

## 4. Non-functional targets

| Area | Target | Rationale / source |
|---|---|---|
| End-to-end latency | Enrichment alert **searchable ≤ 60 s** after the trigger alert (observed 7.6–17 s idle); alert→script ≤ ~2 s | Measured on the dev stack; 60 s is the poll ceiling, not an SLO — mirrors opencti's "no hard SLO, bounded observation" stance |
| Volume gating | The `<integration>` filter (`<group>`/`<rule_id>`/`<level>`) is **mandatory** in every shipped config example; never level-only | Feedback-loop + API-load guard (mapping §6/§8) |
| Dedup | Default TTL 3600 s; cache **persistent across invocations** (integratord spawns the script per alert) under `/var/ossec/` | Mapping §7; Splunk-add-on parity |
| API budget & backoff | Honour argv `timeout`(10 s)/`retries`(3); backoff on 429/5xx honouring `Retry-After`; respect `retryAfter` from degraded `explain()`; quota introspectable via `whisper.quota()`. 429/`Retry-After` behaviour is verified in the **mocked unit tier** (pytest + `responses`), not by a live TC — the opencti pattern | opencti client policy (30 s/3/0.5 backoff) adapted to integratord's argv contract |
| TLP filtering | **Not applicable** — Wazuh alerts carry no TLP markings. The Wazuh analog of opencti's `max_tlp` skip-gate is the integration filter + the public-IP guard (TC-04/05). Stated explicitly because issue #5 names TLP. | opencti TC-18/19 have no Wazuh equivalent |
| Robustness | A failing script must never destabilise the manager (TC-12/13); oversized payloads degrade per mapping §8, never fail the send | `MAX_EVENT_SIZE` 65535; integrator.c error paths |
| Test tooling | Python 3.10 (the manager's interpreter; CI also runs 3.12), plain `pytest` (unit tier mocks HTTP — `responses` lib, opencti pattern); lint per CONTRIBUTING (`ruff`) — note opencti actually uses isort/black/flake8 (its README's "ruff" is stale), so ruff here is a **fresh choice, not a mirror** | opencti CI has no coverage gate; we mirror that (no % threshold for MVP) |

---

## 5. Known limitations / non-goals (don't file bugs against these)

1. **Alerts fired while the manager/integratord restarts are never enriched** — integratord tails
   `alerts.json` from EOF. Permanent skip; they still index normally.
2. **`make dev-agent-demo`'s stock IOC (`203.0.113.45`) is skipped by design** (TEST-NET-3 →
   non-global). The demo needs a parameterised IOC (§7); tracked as an implementation task.
3. **A `wazuh-logtest` pass does not mean live analysisd has the rules** — logtest reloads the
   ruleset per session; the live pipeline requires a manager restart (TC-16 caveat).
4. **No cross-invocation rate-limit bucket** — each invocation retries/backs off independently
   (mirrors opencti limitation #7).
5. **`related.neighbors[]` (IP co-hosting) and `owner`/`business_unit` are deferred** — mapping
   §11 Q4/Q6.
6. **Three implementation knobs are required by this plan** (untestable without them):
   `dedup_ttl` and `api_url` configurable via the `<options>` JSON (argv[5]) → env → default
   (TC-10, TC-13), and a **flushable** dedup cache at `/var/ossec/var/whisper/dedup.db`
   (TC-01/09/12/17). Normative in mapping §2.3/§7.5.
7. **No backfill of historical alerts; no CDB/feed direction** — post-MVP (mapping §10).
8. **No CI coverage-percentage gate** for the MVP (deliberate opencti parity).

Each item above gets a follow-up ticket when the implementation issues are opened (the opencti
"every intentional gap is tracked" discipline).

---

## 6. Bug severity guide

| Severity | Definition | Example |
|---|---|---|
| **S1** | Manager destabilised, integratord crash-loop, or corrupt/dropped alerts | `ossec.conf` left `root:root` after install; `mapper_parsing_exception` drops alerts |
| **S2** | Green path fails for a supported type, or wrong enrichment content | TC-01 fails; verdict copied from raw score; MX/NS direction reversed |
| **S3** | A TC fails with a workaround, or correct behaviour with misleading logs | dedup-skip not logged; truncation total missing on one list |
| **S4** | Cosmetic | doc typo, log formatting |

Every report: seed value, the injection command, `integrations.log` + `ossec.log` tails, the
indexer query + response. S1/S2 additionally: image tags (`docker compose images`), connector
version, Whisper API endpoint.

---

## 7. Demo / validation plan

Format mirrors opencti's scenario docs (seed → what happens → real captured artifacts →
"values drift, shape must match").

**Demo script** (~5 min, no agent required):

1. `make dev-up` + `install.sh` — show `Enabling integration for: 'custom-whisper'.` in ossec.log.
2. **Threat IP:** inject rule-5710 with `185.220.101.1` (§1.2) → dashboard shows the level-7
   *SUSPICIOUS* enrichment with Tor evidence (`threat_feed.flags`, ASN, geo) next to the original.
3. **Dedup:** re-inject the same line → one script log, **no** second alert.
4. **Known-good:** inject with `8.8.8.8` → level-3 *known good* (allowlist-vouched).
5. **Guard:** inject with `10.0.0.5` → nothing (private IP skipped) — show the log line.
6. Close with the indexer query (§1.2 step 3) as the machine-readable proof.

**Deliverables (shipped):** the parameterised `make dev-demo-enrich IOC=<value>` target
(manager-only socket injection; the agent overlay stays optional), and the captured scenario doc
[`docs/scenarios/01-tor-ip-enrichment.md`](scenarios/01-tor-ip-enrichment.md) following the opencti
4-part layout (seed / trigger event / real Whisper response / resulting enrichment alert JSON).

**CI:** unit tier on every PR (pytest, mocked HTTP). The end-to-end acceptance runner shipped too —
`tests/e2e/run_acceptance.py` (`make dev-acceptance`) drives TC-01..TC-22 against a live
single-node stack (the same compose Wazuh runs in its own GitHub Actions: ubuntu-22.04, GH-hosted
runners already ship `vm.max_map_count=262144`, manager+indexer only, poll-based waits, ~4–6 min
startup). **Manual QA per §3 remains the release gate**, with the runner automating the repeatable
checks.

---

## 8. Sign-off checklist (exit criterion for #5)

Signed off with the v1.0.0 release (QA on a fresh Wazuh 4.14.5 stack):

- [x] TC-01 … TC-22 pass on a fresh `make dev-up` + `install.sh`
- [x] Demo scenario doc reproduces against the live graph (shape/types match)
- [x] Zero open S1/S2; all S3/S4 ticketed with owners
- [x] No real API key in repo or config (TC-19)
- [x] Blocking mapping-spec questions resolved: §11 Q1 (field paths validated on real alerts),
      Q2 (dedup backend/TTL — cache path and knobs now pinned by this plan), Q3 (Form A vs B
      attribution). *This plan already resolves Q8: `unknown` → level 3, alert not suppress
      (TC-06/TC-16).*
- [x] Product owner approval on this document

---

## 9. Traceability — TC ↔ scope acceptance criteria ↔ mapping spec

| Scope AC (issue #1 §4) | Covered by | Mapping spec |
|---|---|---|
| AC1 — enrichment alert appears, populated, within seconds | TC-01/02/03 | §2.3, §4 |
| AC2 — non-global IPs not looked up | TC-04/05 | §9 |
| AC3 — verdict evidence-derived, score never sole verdict | TC-06/07/08, TC-14 | §6 |
| AC4 — category-specific directional builders | TC-02 (+ code review) | §5.2, §8 |
| AC5 — MAIL_FOR/NAMESERVER_FOR correct direction | TC-02 (`dns.ns`/`dns.mx` content) | §5.2 |
| AC6 — stable keys; unmapped summarized | TC-17 | §4.2, §8 |
| AC7 — truncation totals | TC-15 | §8 |
| AC8 — no duplicate within TTL | TC-09/10 | §7 |
| AC9 — install.sh clean e2e | TC-18/20 | — |
| AC10 — no real key; env/file resolution | TC-19 | — |
| (new) feedback-loop prevention | TC-11 | §6, §8 |
| (new) rules render verdict→level | TC-16 | §6 |
| (new) failure taxonomy / robustness | TC-12/13/14 | §4.2 (`available`) |
| (new) extractor guards — no IOC / out-of-scope types | TC-21/22 | §9 (scope §3.1) |

---

## Change log / provenance

- **v1.2 (2026-07-11):** #17 alignment: §1.1 gains the indexer-template fact (install before
  first enrichment; daily-roll caveat); note analysisd **stringifies all values** (mapping
  §2.4) — assertions on `data.whisper.*` values in the indexer compare against *strings*
  unless the field is typed by the template.
- **v1.1 (2026-07-06):** scaffold alignment (#13 review + #12 Q1): vocabulary adds
  `skip reason=self-alert` and the `socket` error class; `no-ioc` semantics clarified
  (path-presence, not value-validity); TC-22 narrowed to the inactive hash/path rows
  (`data.url` is an active url-host trigger); `dedup_scope` added to the knob row.
- **v1.0 (2026-07-03):** initial acceptance plan. Mirrors `whisper-opencti/docs/qa-handoff.md`
  (structure, seeds discipline, severity ladder, sign-off) per issue #5; Wazuh mechanics verified
  empirically on the 4.14.5 dev stack (integratord argv/log lines, socket injection, latencies,
  restart semantics, logtest-vs-live behaviour); grounded in the
  [mapping spec](whisper-to-wazuh-mapping.md) and the scope ACs (issue #1 §4).