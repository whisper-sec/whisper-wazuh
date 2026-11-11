# Wazuh 5.0 compatibility

**Status (Wazuh 5.0.0-rc2, observed 2026-11-11): not compatible.** On a 5.0.0-rc2 manager the
current bundle (v1.2.1) enriches nothing: the installer refuses to run, the XML rules are not
loaded, and the manager's configuration schema rejects the `<integration>` hook the connector is
triggered from. Nothing here is a GA result; the claims are scoped to the tag below and need
re-checking when 5.0 is released. **Today, stay on Wazuh 4.x**: the 4.x line is still maintained
(4.14.10 was published 2026-11-09) and this bundle is verified on **4.14.5**.

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
- Bundle under test: this repository at v1.2.1, unmodified. No agent was enrolled and no Whisper
  key was used (the connector is keyless).

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

- Whether 5.0 keeps any form of integratord. The rc2 image ships none; whether it returns before
  GA is unknown.
- How custom content gets into the Content Manager without the dashboard (API or file drop).
  This decides whether an installer like `install.sh` is still possible on 5.0. On rc2 the stock
  content arrives by synchronisation at start-up, and the manager discards events until that
  completes. How custom content joins that route is the open point.
- Whether GA changes any of the above. Re-run `make dev5-up` against the GA tag (a new tag needs
  a new reviewed pin in the `Makefile`).

## Build options

These are not decided here.

- **(a) Re-express the rules as Sigma/YAML Content Manager content.** The 13 production rules
  (plus one dev-only test rule) would be flattened. For: matches how 5.0 loads detections. Against: still needs a trigger (the
  connector currently runs from the removed hook), and it depends on the open content-delivery
  question.
- **(b) A different trigger.** Indexer-side or API-driven enrichment of findings, since the
  manager no longer runs scripts per alert. For: independent of whether integratord returns.
  Against: a new component to build and operate, a new data path into the findings indices, and
  a 5.0 template.
- **(c) Hold at 4.x until GA.** For: no work against a moving rc, and 4.x stays maintained.
  Against: partners moving to 5.0 get no enrichment and no signal; this document and the README
  status are the only mitigation.

## Recommendation (not yet decided)

This section is a recommendation for the owner, not a decision; the decision and its timing are
tracked on [issue #65](https://github.com/whisper-sec/whisper-wazuh/issues/65).

Hold at 4.x now (c), and start (b), a different trigger, as a spike. It is the only option that
does not depend on integratord returning, and the findings above show the manager-side
mechanisms the bundle relies on are gone in rc2. Revisit (a) once the Content Manager content
route is documented and the 5.0 GA is out, and re-run this assessment against the GA tag before
committing to a build.
