# Installation & configuration

How to install the Whisper integration on a Wazuh manager, give it a key, point it at the right
alerts, and confirm it's working. If you just want the one-liner, it's in the
[README](../README.md#install) — this is the full reference for when something doesn't behave.

For *how* it all fits together, see [architecture.md](architecture.md). For the field-by-field
detail, see [whisper-to-wazuh-mapping.md](whisper-to-wazuh-mapping.md).

---

## What you need

The integration runs entirely on the manager — you don't touch your agents.

| | | why |
|---|---|---|
| A **Wazuh manager, 4.x** (single-node or cluster) | as **root** | it edits `ossec.conf`, drops files into `/var/ossec`, and restarts the manager |
| The manager's **bundled Python 3.10** | already there | the connector is stdlib-only — nothing to `pip install` |
| **TLS egress** to `graph.whisper.online` | from the manager | the enrichment API. For the on-demand CLI, also `mcp.whisper.security` |
| Your **indexer reachable** from the install host | default `https://localhost:9200`, user `admin` | the installer pushes a field-type template there first |
| *(optional)* A **Whisper API key** | yours (BYOK) | **not needed for enrichment** — the graph is queried keyless. Required only for the *keyed* features: the [agent-activity log source](#the-agent-activity-log-source---logs) and the [on-demand CLI](#the-on-demand-cli). Get a key / compare tiers at [whisper.security/pricing](https://www.whisper.security/pricing) |

Agents are optional — the connector reacts to *alerts*, wherever they come from.

**Two tiers.** The always-on **enrichment** connector queries the public Whisper graph and needs
**no key**. The **keyed** features — the agent-activity log source and the on-demand CLI — read
*your* tenant's private data, so they need a Whisper API key ([pricing](https://www.whisper.security/pricing)).

---

## Install

Three ways, all landing at the same `install.sh`. Pick the one that fits your setup.

### A — one-liner (quickest)

```bash
curl -sSL https://raw.githubusercontent.com/whisper-sec/whisper-wazuh/main/bootstrap.sh \
  | sudo sh -s -- --group sshd --api-key-file /path/to/your-whisper-key.txt
```

`bootstrap.sh` downloads the latest release bundle and runs its `install.sh` with the args you
pass. Pin a version with `WHISPER_WAZUH_VERSION=v1.0.0`, or point at a mirror / local file with
`WHISPER_WAZUH_URL=…`.

Piping to `sudo sh` runs remote code as root — if that makes you uneasy, use method B and read
`install.sh` first. The bootstrap does nothing more than download, unpack, and run it.

### B — download the tarball (inspect first)

```bash
curl -sSL https://github.com/whisper-sec/whisper-wazuh/releases/latest/download/whisper-wazuh.tar.gz | tar xz
cd whisper-wazuh-*
# read install.sh if you like, then:
sudo sh install.sh --group sshd --api-key-file /path/to/your-whisper-key.txt
```

### C — OS package (`.deb` / `.rpm`)

For teams that manage software with `apt`/`yum` or config management. Grab the package for your
distro from the [Releases page](https://github.com/whisper-sec/whisper-wazuh/releases), then:

```bash
sudo dpkg -i whisper-wazuh_<ver>_all.deb        # Debian/Ubuntu
sudo rpm  -i whisper-wazuh-<ver>-1.noarch.rpm   # RHEL/Alma/Rocky

# the package only STAGES the files — activate it explicitly:
sudo whisper-wazuh-install --group sshd --api-key-file /path/to/your-whisper-key.txt
```

The package installs everything to `/usr/share/whisper-wazuh` and adds `whisper-wazuh-install` /
`whisper-wazuh-uninstall` commands. It does **not** auto-activate — activation patches
`ossec.conf` and restarts the manager, which is an explicit admin step, not something a package
should do behind your back.

### What the installer does (in order)

```
  1. PUT the field-type template to the indexer   (FIRST — if the indexer is unreachable it
                                                    aborts here, before touching the manager)
  2. copy the files to /var/ossec/integrations/   (executables 750, modules 640, root:wazuh)
  3. install the rules to /var/ossec/etc/rules/
  4. create the dedup cache dir /var/ossec/var/whisper (0770)
  5. patch ossec.conf with the <integration> block (with a rollback trap — any failure
                                                     restores your original ossec.conf)
  6. restart the manager and verify integratord enabled the integration
```

It's idempotent — run it again with different flags and it re-renders the block in place.

---

## The API key (bring your own)

**Enrichment doesn't need a key** — you can skip this whole section if that's all you want. The key
unlocks the **keyed features**: the [agent-activity log source](#the-agent-activity-log-source---logs)
and the [on-demand CLI](#the-on-demand-cli), which read your tenant's private data. To get a key or
compare tiers, see [whisper.security/pricing](https://www.whisper.security/pricing).

The key is a per-organization secret — **you supply your own**, it never ships with the integration.
When present, every tier resolves it in this order:

```
   WHISPER_API_KEY  (env)   →   /var/ossec/etc/whisper.key   →   argv
```

**On a VM / bare-metal manager** — use the key file, ideally via the installer so the perms are
right:

```bash
sudo sh install.sh --group sshd --api-key-file /path/to/key.txt   # writes /var/ossec/etc/whisper.key, 640 root:wazuh
```
Or set it yourself: `printf '%s' 'YOUR-KEY' | sudo tee /var/ossec/etc/whisper.key >/dev/null &&
sudo chown root:wazuh /var/ossec/etc/whisper.key && sudo chmod 640 /var/ossec/etc/whisper.key`.
The file is read each time it's used, so **rotating the key needs no restart** — just replace the
file.

**On a containerized manager** — inject `WHISPER_API_KEY` as a container-env secret (Kubernetes
secret, Docker/Swarm secret, `.env`). It wins over the file.

> **Never put the key in `ossec.conf`.** If you do, integratord passes it as `argv`, and it shows
> up in the connector's `/proc/<pid>/cmdline` (i.e. `ps`). The `<integration>` block the installer
> writes deliberately has no `<api_key>` for exactly this reason. The shipped placeholder never
> counts as a real key, so an un-keyed install fails cleanly instead of sending garbage.

---

## Choosing trigger groups

The `--group` list decides **which alerts get enriched** — it's your cost and noise dial. Every
alert in a trigger group that carries a public IP or domain becomes one Whisper lookup (deduped by
the cache).

```bash
sudo sh install.sh --group sshd                 # just sshd (a good place to start)
sudo sh install.sh --group sshd,web,attack      # widen deliberately
```

Start narrow and widen as you learn the volume. Never use a group that the *enrichment* alerts
themselves carry — the installer rejects that, because it would loop.

---

## Option reference

### `install.sh`

| flag | what it does |
|---|---|
| `--group <csv>` | rule groups that trigger enrichment (default `sshd`) |
| `--api-key-file <path>` | install the key from a file into `/var/ossec/etc/whisper.key` (640 root:wazuh); the key never touches a command line |
| `--logs` | also install the **agent-activity log source** (the keyed tier — see [below](#the-agent-activity-log-source---logs)) |
| `--skip-template` | don't push the indexer template (you manage it yourself) |
| `--indexer-url/-user/-pass` | point the template PUT at a remote indexer (default `https://localhost:9200`, `admin`; the password goes via stdin, never on the command line) |
| `--dev` | dev only — also install a test rule for exercising *domain* enrichment without a real DNS log |
| `--refresh-index` | dev only — delete today's alerts index so it re-creates with the right field types (destructive to today's alerts) |

### `uninstall.sh`

```bash
sudo sh uninstall.sh            # remove the block, files, rules; restart; leaves the key + dedup cache
sudo sh uninstall.sh --purge    # also remove the key file and the dedup cache
```

## Optional tuning (`<options>`)

The `<integration>` block can carry an `<options>` JSON string. All optional — the defaults are
sensible. Changing it needs a `wazuh-control restart`.

```xml
<options>{"dedup_ttl": 3600, "dedup_scope": "endpoint", "extra_enrichments": ["tls_fingerprint"]}</options>
```

| option | default | meaning |
|---|---|---|
| `dedup_ttl` | `3600` (s) | how long a repeat indicator is suppressed before re-enriching |
| `dedup_scope` | `endpoint` | `endpoint` = dedup per agent; `org` = dedup globally |
| `api_url` | `https://graph.whisper.online` | a different API base URL (include the scheme — it's used verbatim) |
| `extra_enrichments` | *(none)* | opt into heavier fields — currently `"tls_fingerprint"` (the Cobalt-Strike JARM signal → rule 100206) |

---

## Verify it works

Turn on the connector's debug log, trigger something, and read the log:

```bash
echo 'integrator.debug=2' | sudo tee -a /var/ossec/etc/local_internal_options.conf
sudo /var/ossec/bin/wazuh-control restart
sudo grep whisper: /var/ossec/logs/integrations.log
```

A healthy enrichment is three lines — **`invoke` → `api` → `emit`**:

```
whisper: invoke ioc=185.220.101.1 type=ipv4 dedup_key=ipv4|185.220.101.1|000
whisper: api url=https://graph.whisper.online ms=137
whisper: emit dedup_key=ipv4|185.220.101.1|000 payload_bytes=1385
```

Then in the dashboard (**Discover → `wazuh-alerts-*`**) search `data.whisper.ioc:<the IP>` — you'll
see a new enrichment alert (e.g. *"Whisper: … is SUSPICIOUS (HIGH)"*, rule 100202) next to the
original. Note there are **two** alerts per event: the trigger, and the enrichment linked to it by
`source_ref` — see [architecture.md](architecture.md) for why.

### When nothing happens — the log tells you exactly why

| line | means | fix |
|---|---|---|
| `emit …` after `invoke`+`api` | ✅ working | — |
| `skip reason=non-global` | the indicator was a private / TEST-NET IP | expected — nothing to do |
| `skip reason=dedup` | same indicator seen within the TTL | expected — reset `dedup.db` to re-test |
| `skip reason=no-ioc` | the alert carried no supported indicator | check it actually has a public IP/domain |
| `error class=auth` | key missing / placeholder / wrong | fix `/var/ossec/etc/whisper.key` or the env var |
| `error class=transport` | can't reach `graph.whisper.online` | check egress / DNS / TLS from the manager |
| **no `invoke` line at all** | the alert never reached the connector | its rule group isn't in your `--group` list, or integratord isn't enabled |

Sanity that integratord even loaded it:
```bash
sudo grep "Enabling integration for: 'custom-whisper'" /var/ossec/logs/ossec.log
```

---

## The on-demand CLI

Alongside the automatic connector, `whisper-investigate` runs a heavy Whisper *workflow* (a deep
multi-step investigation) on one indicator and prints a report — for when an analyst wants to go
deeper than the per-alert enrichment. It installs into `/var/ossec/integrations/` too.

```bash
/var/ossec/integrations/whisper-investigate 185.220.101.1
/var/ossec/integrations/whisper-investigate evil.example --workflow attack-surface --format json --out report.json
```

It reads the same API key, but **flag-first** (a CLI convention — the reverse of the connector): an
explicit `--api-key` wins, otherwise `$WHISPER_API_KEY`, otherwise the key file. It needs egress to
`mcp.whisper.security`. `/var/ossec/integrations/` isn't on `PATH`, so use the full path (or add the
dir to your `PATH`).

---

## The agent-activity log source (`--logs`)

Everything above is the **enrichment** half: it pulls threat context *into* Wazuh about the IPs and
domains your alerts already touch, and it needs no key for the graph lookups. The log source is the
**other half** — the *keyed* tier. If you're a Whisper customer running agents through the platform,
it pulls **your own agents' activity** back out of the Whisper control plane and drops it into Wazuh:
what each agent resolved (DNS allow/refused), what it connected out to, and when it was allocated an
identity. Two tiers: intel comes *in* (enrichment), your activity comes *out* (log source). See
[architecture.md](architecture.md#the-agent-activity-log-source-the-keyed-tier) for the shape of it.

It's **opt-in and additive** — enable it with `--logs`, and the enrichment path is left byte-for-byte
identical:

```bash
sudo sh install.sh --group sshd --api-key-file /path/to/key.txt --logs
```

That installs a small poller (`whisper-logs`), its rules (`whisper_agent_rules.xml`), and a **60-second
`command`-wodle scheduler** plus a JSON spool the logcollector tails — all in a **separate**
`whisper-logs` block in `ossec.conf`, so it never touches the enrichment `<integration>`. Because it's
the keyed tier, it **needs your tenant API key** (`WHISPER_API_KEY` env → `/var/ossec/etc/whisper.key`,
provisioned exactly as [above](#the-api-key-bring-your-own); get one at
[whisper.security/pricing](https://www.whisper.security/pricing)); without a real key the poller just
logs a message and does nothing.

Each poll writes `data.whisper_agent.*` alerts that these rules render:

| rule | fires on | level |
|---|---|---|
| `100211` | DNS the agent's policy **refused** (a block) | 6 |
| `100212` | DNS the agent **allowed** (informational — set level 0 to silence) | 3 |
| `100213` | egress **connection** (open/closed) | 3 |
| `100214` | new agent **identity** allocated | 4 |
| `100215` | **telemetry gap** — a poll hit its row limit and truncated the window | 8 |

The agent-activity rules carry a `whisper_agent_activity` group that's **disjoint** from the enrichment
groups, so these alerts can never loop back and re-trigger enrichment (`install.sh` also rejects
`--group whisper_agent_*`).

### Tuning it (`WHISPER_LOGS_*`)

The poller is configured by environment variables on the manager (all optional). Since it runs from the
wodle, set them where the manager reads its environment, then `wazuh-control restart`:

| variable | default | meaning |
|---|---|---|
| `WHISPER_LOGS_SINK` | `logcollector` | `logcollector` (append to the JSON spool, tailed) or `socket` (inject on the analysisd queue directly) |
| `WHISPER_LOGS_LIMIT` | `1000` (cap `10000`) | rows pulled per poll; hitting it raises the gap alert (rule 100215) — raise this or shorten the interval |
| `WHISPER_LOGS_KINDS` | `all` | restrict to a CSV subset of `dns,conn,alloc` |
| `WHISPER_LOGS_AGENT` | *(none)* | restrict to a single agent id |
| `WHISPER_LOGS_SPOOL` | `/var/ossec/logs/whisper-agent-activity.json` | the NDJSON spool path |
| `WHISPER_LOGS_CURSOR` | `/var/ossec/var/whisper/logs-cursor` | the incremental watermark (delete it to re-baseline to newest) |

### Verify it

```bash
sudo grep whisper-logs: /var/ossec/logs/whisper-logs.log     # expect  poll complete: emitted=N sink=logcollector
```

Then search `data.whisper_agent.kind:*` in **Discover → `wazuh-alerts-*`** for the decoded agent-activity
alerts. Common lines in `whisper-logs.log`:

| line | means |
|---|---|
| `poll complete: emitted=N` | ✅ N agent-activity events ingested |
| `no API key resolved …` | the keyed tier needs the tenant key — set `WHISPER_API_KEY` / the key file |
| `auth error (terminal)` | the key is wrong/expired for `op:logs` |
| `poll hit the limit of N rows …` | truncated window — a gap alert (100215) was raised; raise `WHISPER_LOGS_LIMIT` |

To exercise it on the dev stack: `make dev-logs-install` then `make dev-logs-smoke`.

---

## Removing it

```bash
sudo sh uninstall.sh --purge          # from the tarball/bootstrap install
sudo whisper-wazuh-uninstall --purge  # from the package install
```

Removes the `<integration>` block (restoring `ossec.conf` in place), the files, and the rules, and
restarts the manager — and the `whisper-logs` block too if you installed `--logs` (symmetric, a no-op
if it isn't there). `--purge` also deletes the key file and the dedup cache.