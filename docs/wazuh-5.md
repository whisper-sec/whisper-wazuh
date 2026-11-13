# Wazuh 5.0 compatibility

**Status (Wazuh 5.0.0-rc2, observed 2026-11-11): not compatible.** On a 5.0.0-rc2 manager the
bundle (tested at v1.2.1; v1.2.2 changes nothing here) enriches nothing: the installer refuses to run, the XML rules are not
loaded, and the manager's configuration schema rejects the `<integration>` hook the connector is
triggered from. Nothing here is a GA result; the claims are scoped to the tag below and need
re-checking when 5.0 is released. **Today, stay on Wazuh 4.x**: the 4.x line is still maintained
(4.14.10 was published 2026-11-09) and this bundle is verified on **4.14.5**.

A spike of a hook-free enrichment path (option (b), [below](#option-b-spike)) worked on the same
rc2 stack on 2026-11-12: an enrolled agent produced a finding with a public IP, and a poller on
the indexer API stored its Whisper enrichment with no manual step. It is a prototype, not a
shipped feature, and the decision is still to hold at 4.x ([Decision](#decision)).

## What 5.0 changes

From the 5.0-rc documentation: events are normalised by decoders and KVDBs, and a detection
engine in the Wazuh indexer matches a ruleset
([log data analysis](https://documentation.wazuh.com/5.0-rc/user-manual/capabilities/log-data-collection/log-data-analysis.html)).
Rules are written in Sigma format with Wazuh extensions and organised by integration in the
Content Manager ([rules](https://documentation.wazuh.com/5.0-rc/user-manual/data-analysis/rules.html));
decoders are YAML, managed from the Ruleset Management dashboard
([decoders](https://documentation.wazuh.com/5.0-rc/user-manual/data-analysis/decoders.html)).
Those pages do not mention XML rules, `/var/ossec/etc/rules`, `if_sid` or `if_group`, and the
[configuration reference index](https://documentation.wazuh.com/5.0-rc/user-manual/reference/ossec-conf/index.html)
lists no `integration` section. The measurements below confirm this on a running manager.

## Test environment

- Stack: [`wazuh/wazuh-docker`](https://github.com/wazuh/wazuh-docker) tag `v5.0.0-rc2`,
  `single-node/`, vendored under [`dev/wazuh-5-single-node/`](../dev/README.md#wazuh-50-assessment-stack).
  Run with `make dev5-up`.
- Images (all `5.0.0-rc2`, pulled 2026-11-11, linux/arm64):
  - `wazuh/wazuh-manager@sha256:a20c0323016f757543293dab8adaf8ac0ba497301b070ce8e253436b7d3b5d28`
  - `wazuh/wazuh-indexer@sha256:ee3950aeb755eca4042cdbc701562de8c5307f0d37f0ebea147f0d6ca5c8e4b5`
  - `wazuh/wazuh-dashboard@sha256:277f74ecc206f135ad220d62f606e4611cd72f116e96efb54ccc88e6ca7022f9`
- Manager `VERSION.json`: `5.0.0`, stage `rc2`, commit `0a951d0`. Indexer: OpenSearch 3.6.0.
- Host: Docker on aarch64 (Apple silicon), 8 GB, `vm.max_map_count = 262144`.
- TLS material: `make dev5-certs`, which runs Wazuh's rc2 certificate tool in a throwaway
  container with no network, after its SHA-256 matches the pin in the `Makefile`.
- Bundle under test: this repository at v1.2.1, unmodified. No agent was enrolled for the results
  above (the [spike](#option-b-spike) later enrolled one) and no Whisper key was used (the
  connector is keyless).

## Results

| Dependency | On 4.14.5 | On 5.0.0-rc2 (observed) | Verdict |
|---|---|---|---|
| Installer (`install.sh`) | finds `/var/ossec/bin/wazuh-control`, edits `ossec.conf`, restarts | `install.sh: ERROR: wazuh-control not found under /var/ossec` (exit 1) before any change | **Rejected** |
| XML rules (`whisper_rules.xml`) | loaded from `/var/ossec/etc/rules/`, alerts 1005xx | No `/var/ossec` and no rules directory. The file was copied into `/var/wazuh-manager/data/ruleset/` and the manager restarted: file present, no mention in the manager log, no error, no 1005xx alert | **Ignored** |
| `<integration>` hook running `custom-whisper` | integratord invokes the script per matching alert | `wazuh-manager-conf validate` on a copy of the config with the block added: `(1244): Invalid configuration at '/integration': unknown option`, exit 1. No `wazuh-integratord` binary ships in the manager image | **Rejected** |
| `data.whisper.*` indexer template (`PUT _template/whisper`) | accepted; matches `wazuh-alerts-4.x-*` | PUT returned HTTP 200 `{"acknowledged":true}`, but its `index_patterns` are `wazuh-alerts-4.x-*` and `wazuh-archives-4.x-*` and no 5.0 index or template matches them (see below) | **Accepted, inert** |
| `--logs` tier: `<localfile>` json | tailed by logcollector | `Invalid configuration at '/localfile': unknown option`, exit 1 | **Rejected** |
| `--logs` tier: `<wodle name="command">` | runs the poller | `Invalid configuration at '/wodle': unknown option`, exit 1 | **Rejected** |

### Evidence

Installer (`make dev5-whisper-install`, which copies the bundle into the manager container and
runs `sh install.sh --dev --group sshd`):

```text
install.sh: ERROR: wazuh-control not found under /var/ossec
make: *** [dev5-whisper-install] Error 1
```

The `.deb`/`.rpm` packages and the one-line installer activate through this same script
(`whisper-wazuh-install` and `bootstrap.sh` both run `install.sh`), so they stop at the same check.

Layout. The manager lives under `/var/wazuh-manager` (binaries include `wazuh-manager-control`,
`wazuh-manager-analysisd`, `wazuh-manager-remoted`, `wazuh-manager-modulesd`; there is no
`wazuh-integratord`, `wazuh-logcollector` or `wazuh-execd`). Its configuration is
`/etc/wazuh-manager/wazuh-manager.conf`, validated against `wazuh-manager.schema.json` by
`wazuh-manager-conf validate`, which is silent and exits 0 on the stock file. There is no
`ossec.conf`.

Configuration probes. Each block was appended to a scratch copy of the stock config and run
through `wazuh-manager-conf -f <copy> validate`:

```text
<integration>...custom-whisper...</integration>  (1244): Invalid configuration at '/integration': unknown option (does not satisfy 'additionalProperties') [schema /].   rc=1
<localfile>...</localfile>                       (1244): Invalid configuration at '/localfile': unknown option ...   rc=1
<wodle name="command">...</wodle>                (1244): Invalid configuration at '/wodle': unknown option ...   rc=1
<ruleset><rule_dir>...</rule_dir></ruleset>      (1244): Invalid configuration at '/ruleset': unknown option ...   rc=1
```

So a manager config carrying the hook is rejected by the validator, and the hook can only be
added by an installer that already failed above. The second-hand report in the issue (XML rule
files ignored without an error while the config check passes) holds for the rule files, as shown
next. What it leaves out is that the check passes only while the config does not name the old
sections: the rc2 validator fails closed on unknown ones.

XML rules. `whisper_rules.xml` was copied into the only ruleset directory that exists
(`/var/wazuh-manager/data/ruleset/`, empty in the stock image) and the manager container was
restarted. The file stayed there, the manager came back healthy, its log showed no reference to
the file and no error, and no rule 1005xx fired. That directory is not a place the manager reads
rule files from: it is where content synchronised from the Content Manager lands. On first start
the log reports `[CMSync] No active routes available. Incoming events will be discarded until
content synchronization completes`, then about 30 seconds later `[CMSync] Event processing is
now active`, and the directory then holds a `cmsync_standard_*` folder of JSON content
(`decoders/`, `integrations/`, `kvdbs/`, `policy.json`). The indexer holds the content as
documents too (`wazuh-threatintel-rules-*`, beside `-decoders-*`, `-integrations-*` and
`-kvdbs-*` indices), which fits the documentation's description of detection running in the
indexer. The manager exposes no `ossec.log` or `alerts.json`; the indexer has
`wazuh-findings-v5-*` streams for findings instead (empty here, with no agent enrolled). No event
could be injected: with no agent enrolled and no logcollector or logtest in the image, there was
no input to push the `dev-demo-enrich` sshd event through. The Ignored verdict therefore rests
on the file being present, the absence of any error, and the absence of any whisper rule in the
log. It is not an end-to-end event test.

Indexer template and indices. The PUT used the admin credential from the generated credentials
file through curl's stdin config; it never reached argv or a log.

```text
PUT _template/whisper  (whisper-template.json, index_patterns [wazuh-alerts-4.x-*, wazuh-archives-4.x-*])
-> {"acknowledged":true}  HTTP 200
_cat/indices/wazuh-alerts*,wazuh-archives*  -> (no rows)
```

The 5.0 indexer holds `wazuh-events-v5-<category>` and `wazuh-findings-v5-<category>` data
streams (the same eight categories for both: access-management, applications, cloud-services,
network-activity, other, security, system-activity, unclassified), a `wazuh-events-raw-v5`
stream and `wazuh-states-*` inventory indices, with matching `wazuh-events-v5-*-template` and
`wazuh-findings-v5-*-template` index templates. No `wazuh-alerts-*` or `wazuh-archives-*` index
exists and no template other than `whisper` names them, so the `whisper` template would map
nothing. A 5.0 build would need its own field mapping against the findings and events streams.

## Open research items

Updated 2026-11-12 from Wazuh's own sources at `v5.0.0-rc2` and the spike below. None of this is
a GA result.

- **integratord.** Its removal is a listed 5.0 breaking change, not an rc gap: upstream's release
  notes (`docs/ref/release-notes.md`) list `wazuh-integratord` as no longer shipped, and its
  migration guide (`docs/guide/migration/integratord-notifications.md`) says enrichment
  integrations that re-inject an alert have "no equivalent mechanism in 5.x". Do not plan on it
  returning.
- **Custom content without the dashboard.** The 5.0-rc documentation describes a Content Manager
  REST API on the indexer, under `/_plugins/_content_manager/`. That is the documented route for
  custom rules and decoders. It has not been exercised here and is confirmed or not on GA in
  [#68](https://github.com/whisper-sec/whisper-wazuh/issues/68).
- **Whether GA changes any of the above.** Open, tracked in #68. Re-run `make dev5-up` against the
  GA tag (a new tag needs a new reviewed pin in the `Makefile`).

## Build options

Decided on [issue #65](https://github.com/whisper-sec/whisper-wazuh/issues/65) on 2026-11-11; see
[Decision](#decision). The options as assessed:

- **(a) Re-express the rules as Sigma/YAML Content Manager content.** The 13 production rules
  (plus one dev-only test rule) would be flattened. For: matches how 5.0 loads detections. Against: still needs a trigger (the
  connector currently runs from the removed hook), and its content route, the Content Manager
  REST API, has not been exercised here.
- **(b) A different trigger.** Indexer-side or API-driven enrichment of findings, since the
  manager no longer runs scripts per alert. For: independent of whether integratord returns.
  Against: a new component to build and operate, a new data path into the findings indices, and
  a 5.0 template. Tested in the spike below.
- **(c) Hold at 4.x until GA.** For: no work against a moving rc, and 4.x stays maintained.
  Against: partners moving to 5.0 get no enrichment and no signal; this document and the README
  status are the only mitigation.

## Option (b) spike

Observed 2026-11-12 on the stack above plus two overlays (`make dev5-agent-up`,
`make dev5-spike-setup`, `make dev5-spike-up`; see [`dev/README.md`](../dev/README.md#spike-a-hook-free-enrichment-path-option-b-issue-67)).
Everything is rc2 and dev-only; the shipped bundle under `integrations/whisper/` is unchanged.

- Agent: `wazuh/wazuh-agent@sha256:f28f472f47b6f18b89549d2ab13a8f0202b10d9300356026547fae1377222774`
  (tag `5.0.0-rc2`, multi-arch index, pulled 2026-11-12, linux/arm64).
- Poller runtime: `python:3.11-slim@sha256:a5b427ace4900267d93db34138e512325c6fa6af84ad5e4ed5f3b36258cc4142`,
  a separate container. The manager image does bundle a Python (3.12.14 at
  `/var/wazuh-manager/framework/python`, used by its API), so a poller could run there too. It was
  kept out of the manager so the spike changes nothing in it and the poller holds only its own
  credential.
- Whisper: the public keyless tier at `graph.whisper.online`, no key.

### 1. A finding with a public IP

**Enrolment.** The agent enrolls with a token only; there is no password enrolment on rc2. The token
comes from the manager API (`POST /agents/enrollment-tokens`, body
`{"address": "wazuh.manager", "embed_ca": true, "max_uses": 1, "ttl": "600s"}`; `ttl` is a string,
and a bare number is rejected with HTTP 400). One `make` recipe mints it and passes it to the agent
as `WAZUH_ENROLLMENT_TOKEN` through the environment, so it is never printed or put on a command
line. Docker keeps it in the agent container's config until the container is removed; it allows
one enrolment and expires after 10 minutes. The agent was named `whisper-spike-agent` and got id `001`. The agent logged
`Token bootstrap: enrollment succeeded`, and the manager logged the token minted and used (1/1).
`wazuh.manager` is already in the SAN of the manager's `remoted.pem`, so no certificate change was
needed.

**Producing the event.** The stock agent config already tails
`/var/ossec/logs/active-responses.log` (syslog), so `make dev5-agent-demo` appends an sshd line
there. Two lines were tried, both naming `185.220.101.1` (a public address; `203.0.113.45`, the 4.x
demo IP, is TEST-NET and the connector's guard skips it):

| Line | Result |
|---|---|
| `sshd[1234]: Failed password for invalid user admin from 185.220.101.1 port 4444 ssh2` | Decoded by `system-auth` into one event in `wazuh-events-v5-system-activity` (`source.ip` set, with geo and AS fields). **No finding**: no stock rule matches it, and none appeared in the 12 minutes it was watched |
| `sshd[1235]: Connection closed by invalid user admin 185.220.101.1 port 4444 [preauth]` | Event, then a **finding** in `wazuh-findings-v5-system-activity` from the stock rule "SSH connection closed before authentication" (level `low`, MITRE T1046), about 2 minutes later |

The delay is the detector schedule: the stock `linux` detector runs every 2 minutes. No custom rule
was added; the finding comes from stock content, so this does not test option (a).
Of the 8 stock `linux` rules in the indexer, two match sshd events: this one and a successful
root password login.

The finding (trimmed; `_id` `JsDGEat4QqhaplO7jpIakQ`, index `.ds-wazuh-findings-v5-system-activity-000001`),
found with a search on `wazuh-findings-v5-*`:

```json
{
  "@timestamp": "2026-11-12T21:30:52.247924889Z",
  "source": { "ip": "185.220.101.1", "port": 4444, "as": { "number": 60729 } },
  "related": { "ip": ["185.220.101.1"], "user": ["admin"] },
  "event": { "action": "connection-closed", "outcome": "failure",
             "index": ".ds-wazuh-events-v5-system-activity-000001", "doc_id": "Osqr0aEBEnYaY41PyeJu" },
  "message": "Connection closed by invalid user admin 185.220.101.1 port 4444 [preauth]",
  "wazuh": {
    "agent": { "id": "001", "name": "whisper-spike-agent" },
    "rule": { "id": "7ea5c859-c7c2-5ba9-bffa-fdf4f7aa2fda", "level": "low",
              "title": "SSH connection closed before authentication - 185.220.101.1" }
  }
}
```

The IP is at `source.ip` (ECS-shaped; `related.ip` aggregates every address of the event). The
finding carries the originating event's `@timestamp`, not the time the finding was written, and
holds no ingest timestamp (see the cursor note below). The finding `_id` and its backing index are
what any enrichment has to link to.

### 2. The enrichment path: a poller on the indexer API

**Trigger.** A long-running process polls `wazuh-findings-v5-*` every 30 seconds (a CLI flag) over
the indexer's HTTPS API. For each finding it takes the IPs and domains at `source.ip`,
`destination.ip`, `client.ip`, `server.ip`, `dns.question.name` and `url.domain` (only `source.ip`
was observed; the rest are ECS names) and runs them through the shipped connector, loaded as it is:
its own `_classify` (the public-IP guard, so private, loopback and TEST-NET addresses are skipped
with the same `skip reason=non-global` log line) and its own `enrich()`, with no key. The poller
needs no manager access and no hook: it reads findings the indexer already holds.

**What has to run.** One long-running process with Python 3.10+ (the poller is stdlib-only), network access to the indexer (`:9200`) and to
`graph.whisper.online`, and one indexer credential. Nothing runs on the manager or the agent.

**Indexer permissions.** `make dev5-spike-setup` creates one role, one internal user and one role
mapping with the indexer admin credential (a one-shot container; the poller never sees it). The
role `whisper_spike_enricher`, exactly as the indexer returned it:

| Scope | Allowed |
|---|---|
| cluster | `cluster_composite_ops_ro`, `indices:data/write/bulk` |
| `wazuh-findings-v5-*`, `.ds-wazuh-findings-v5-*` | `read` (the stock action group). No write |
| `whisper-enrichment-v5*` | `read`, `indices:data/write/index`, `indices:data/write/bulk*`, `indices:admin/mapping/put` |

These were found by running the poller and adding what the indexer refused, in this order:
`_mget` and `_search` needed the composite cluster permission; the first write was refused for
`indices:data/write/bulk` (a single-document write is routed through the bulk action); the next
for `indices:admin/mapping/put` (dynamic mapping of `whisper.*` fields the template does not name).
Whether the `wazuh-findings-v5-*` pattern alone would cover the data stream's backing indices
without the `.ds-` one was not tested. Index creation is not granted: setup creates the index.
The user's password is generated into a gitignored file under `config/`.

**Where the enrichment is stored.** Its own index, `whisper-enrichment-v5`; the findings are never
modified. One document per finding and IOC, with `_id = sha256("<finding _id>|<ioc>")` and written
with `PUT whisper-enrichment-v5/_create/<id>`, so a re-run or an overlapping poll gets HTTP 409
instead of a duplicate. Restarting the poller produced `exists: 1`, no second Whisper call and no
second document. The link to the finding is `finding.id` and `finding.index`:

```json
{
  "@timestamp": "2026-11-12T21:39:55.121Z",
  "finding": { "id": "JsDGEat4QqhaplO7jpIakQ", "index": ".ds-wazuh-findings-v5-system-activity-000001",
               "timestamp": "2026-11-12T21:30:52.247924889Z", "rule": { "id": "7ea5c859-..." }, "agent": { "id": "001" } },
  "ioc": "185.220.101.1", "ioc_type": "ipv4", "field_path": "source.ip",
  "whisper": { "verdict": "suspicious", "risk_score": 13.44, "level": "LOW", "known": true,
               "coverage": { "granularity": "ipv4", "data_coverage": "ambiguous" },
               "threat_feed": { "feeds": ["stamparm-ipsum", "tor-exit-nodes", "..."], "sources_count": 8 },
               "tags": ["anonymizer", "blacklist", "proxy", "spam", "threat", "tor"],
               "unmapped_summary": "context enrichment degraded (query)" }
}
```

The `whisper` object is the connector's payload, unchanged. `unmapped_summary` shows that, on the
keyless tier, the optional context queries degraded; the verdict and feed data are intact.

**Mapping.** An index template for `whisper-enrichment-v5*`
([`dev/wazuh-5-spike/whisper-enrichment-template.json`](../dev/wazuh-5-spike/whisper-enrichment-template.json)):
`finding.id`, `finding.index`, `ioc` and `whisper.verdict` as `keyword`, `@timestamp` and
`finding.timestamp` as `date`, strings dynamically mapped to `keyword`, and the `whisper.*`
numerics, booleans and dates typed as in the shipped `whisper-template.json` (a unit test keeps the
two in sync). It is a new template: the shipped 4.x one matches no 5.0 index.

**The query that returns it** (`make dev5-spike-query FINDING=<finding _id>` runs this as the
enricher user):

```text
POST whisper-enrichment-v5/_search
{ "query": { "term": { "finding.id": "JsDGEat4QqhaplO7jpIakQ" } } }
```

**End to end, with no manual step.** With the poller already running, `make dev5-agent-demo
IOC=185.220.101.2` was run at 21:41:22 UTC. The finding appeared and its enrichment (`verdict:
known_bad`) was stored by 21:43:07, about 1 minute 45 seconds, which is the detector schedule plus
at most one 30-second poll. A second run the same day, from fresh volumes, repeated the whole path:
the line for `185.220.101.1` was appended at 22:13:38 UTC and its enrichment (`verdict:
suspicious`) was stored at 22:15:39.

**Things the spike found.**

- **A cursor on `@timestamp` is unsafe.** A finding is written about 2 minutes after the event and
  keeps the event's `@timestamp`, so a high-water mark on it would skip a finding that arrives
  late. The poller therefore re-reads a lookback window (default 60 minutes) every poll and uses
  the enrichment index itself as its state: one `_mget` of the candidate ids, then only the missing
  ones are enriched. This needs no persisted cursor and survives restarts. Limits: at most 10,000
  findings per window (the default `max_result_window`), and a finding the detector writes more
  than one lookback late is missed. A production design would want an ingest-time watermark, which
  findings do not carry.
- **Verdicts are cached for 5 minutes per IOC** in the process, so ten findings for one IP make one
  set of API calls.
- **Write-back to the finding.** `PUT /_plugins/_security_analytics/findings/_update` exists on rc2
  and takes `{"findings": [{"_id": ..., "_index": <backing index>, "case": {...}}]}`. It updates
  only the finding's `wazuh.case` object (title, description, status, severity, priority, TLP,
  tags, comments), so it cannot hold the enrichment and the separate index stays. With the
  enricher role it answered 207 with a per-item 403 for `indices:data/write/update` and
  `indices:data/write/bulk[s]` on the finding's backing index, so tagging needs write access to
  findings, which the role does not have. With the admin user a probe set
  `wazuh.case.tags: ["whisper:suspicious"]` and the finding stored it (the data stream name is not
  accepted as `_index`, only the backing index). It is not part of the poller.
- **The webhook path was not built.** An Alerting monitor with a webhook would still need a
  receiver service with the same write credentials, and the 5.0-rc documentation says the
  Notifications module denies loopback and private addresses by default, so a receiver on a
  private network needs that relaxed. The issue rules out a second path once one works; this is
  from the documentation only and was not run.

**Recommendation for (b): feasible on rc2; no build now.** The poller shows enrichment can run
without integratord, on documented indexer APIs, with a least-privilege role and no change to the
manager. What a build would still have to settle: where the poller runs and who operates it (a
sidecar service, or inside the manager's bundled Python), the ingest watermark above, where the 5.0 detections come from
(option (a)), and a 5.0 dashboard view of `whisper-enrichment-v5` joined to findings. None of that
is committed before the GA re-run. If GA keeps no integratord, (b) is the leading candidate for the
trigger.

## Decision

Decided on [issue #65](https://github.com/whisper-sec/whisper-wazuh/issues/65) on 2026-11-11:
option (c), hold at Wazuh 4.x until 5.0 is GA, and test option (b) in a spike before any 5.0
build is committed.

- **Now: (c).** No 5.0 build; the supported target stays Wazuh 4.x, verified on 4.14.5.
- **Candidate: (b).** Tested in [#67](https://github.com/whisper-sec/whisper-wazuh/issues/67); the
  result is the section above.
- **(a)** is revisited in [#68](https://github.com/whisper-sec/whisper-wazuh/issues/68). It still
  needs a trigger.
- **Timing.** No 5.0 build is committed before the assessment is re-run on the 5.0 GA images
  (#68). rc2, released 2026-10-30, is still the newest 5.0 tag.
