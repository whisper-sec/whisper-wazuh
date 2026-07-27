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
| **TLS egress** to `graph.whisper.security` | from the manager | the enrichment API. For the on-demand CLI, also `mcp.whisper.security` |
| Your **indexer reachable** from the install host | default `https://localhost:9200`, user `admin` | the installer pushes a field-type template there first |
| A **Whisper API key** | yours (BYOK) | for live enrichment. Without one the integration installs fine but every lookup auth-fails |

Agents are optional — the connector reacts to *alerts*, wherever they come from.

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

The key is a per-organization secret — **you supply your own**, it never ships with the
integration. The connector looks for it in this order, on every lookup:

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
The file is read on each enrichment, so **rotating the key needs no restart** — just replace the
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
| `api_url` | `https://graph.whisper.security` | a different API base URL (include the scheme — it's used verbatim) |
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
whisper: api url=https://graph.whisper.security ms=137
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
| `error class=transport` | can't reach `graph.whisper.security` | check egress / DNS / TLS from the manager |
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

## Removing it

```bash
sudo sh uninstall.sh --purge          # from the tarball/bootstrap install
sudo whisper-wazuh-uninstall --purge  # from the package install
```

Removes the `<integration>` block (restoring `ossec.conf` in place), the files, and the rules, and
restarts the manager. `--purge` also deletes the key file and the dedup cache.