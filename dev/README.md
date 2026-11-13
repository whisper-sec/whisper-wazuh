# Local Wazuh dev stack

A single-node Wazuh stack (manager + indexer + dashboard) for developing and testing the
whisper-wazuh integration locally. Single-node is intentional — it exposes the same APIs as a
production cluster while staying light enough for a laptop.

## Provenance

The files under [`wazuh-single-node/`](wazuh-single-node/) are vendored from the official
[`wazuh/wazuh-docker`](https://github.com/wazuh/wazuh-docker) repository at tag **`v4.14.5`**
(`single-node/` directory). Those upstream files are licensed **GPLv2** (see the header in each
compose file). This pins our target Wazuh version — see issue #4.

**Local modifications** (for the dev reverse proxy + a tidier cert layout):
- `docker-compose.yml` — dashboard host port moved `443` → `5601` so Traefik can own `:443`;
  cert mounts repointed to `config/certs/`.
- `generate-indexer-certs.yml` — certs are generated into `config/certs/`.
- Added (not upstream): `docker-compose.traefik.yml`, `config/traefik/`, `scripts/dev-init.sh`,
  `docker-compose.agent.yml`, `config/wazuh_agent/`, and a repo-root `Makefile`.

All TLS material — the Wazuh cluster certs **and** the Traefik `*.whisper-wazuh-dev.localhost`
wildcard — lives under `config/certs/` and is gitignored.

## Prerequisites

- Docker Engine + Docker Compose (v2+).
- The indexer is OpenSearch and needs `vm.max_map_count >= 262144`:
  - **Linux:** `sudo sysctl -w vm.max_map_count=262144` (persist in `/etc/sysctl.conf`).
  - **macOS (Docker Desktop):** the value lives inside the Docker VM. If the indexer crash-loops
    on startup, run:
    ```bash
    docker run --rm --privileged --pid=host alpine sysctl -w vm.max_map_count=262144
    ```
    (not persistent across Docker Desktop restarts).

## Start

```bash
cd dev/wazuh-single-node

# 1. Generate the self-signed TLS certs (output is gitignored)
docker compose -f generate-indexer-certs.yml run --rm generator

# 2. Bring up the stack
docker compose up -d
```

First start takes ~1–2 minutes and pulls several GB of images; expect transient connection
errors in the logs until the indexer is ready.

## Access

| Service | URL / endpoint | Default credentials |
|---|---|---|
| Dashboard | https://localhost:5601 | `admin` / `SecretPassword` |
| Indexer API | https://localhost:9200 | `admin` / `SecretPassword` |
| Manager API | https://localhost:55000 | `wazuh-wui` / `MyS3cr37P450r.*-` |

The certs are self-signed, so browsers and `curl` will warn (`curl -k`).

> ⚠️ These are upstream **default** dev passwords. Change them before any non-local use — see
> the Wazuh docs on changing default passwords.

## Domain access (Traefik)

A [Traefik](https://traefik.io/) reverse proxy can front all three services on `:443` with
friendly hostnames, so you don't juggle ports. It terminates TLS with a single
`*.whisper-wazuh-dev.localhost` wildcard cert signed by the Wazuh root CA (no browser warnings
once the CA is trusted).

```bash
cd dev/wazuh-single-node

# One-time: issue the dev cert, add /etc/hosts entries, trust the CA (uses sudo)
./scripts/dev-init.sh

# Bring the stack up WITH the Traefik overlay
docker compose -f docker-compose.yml -f docker-compose.traefik.yml up -d
```

| Service | Domain (`:443`) | Default credentials |
|---|---|---|
| Dashboard | https://dashboard.whisper-wazuh-dev.localhost | `admin` / `SecretPassword` |
| Indexer API | https://indexer.whisper-wazuh-dev.localhost | `admin` / `SecretPassword` |
| Manager API | https://manager.whisper-wazuh-dev.localhost | `wazuh-wui` / `MyS3cr37P450r.*-` |

Traefik's own dashboard (debugging): http://127.0.0.1:8080/dashboard/ (localhost only).
The direct `localhost:5601/9200/55000` endpoints above still work alongside the domains.

## Stop / reset

```bash
docker compose down        # stop, keep data volumes
docker compose down -v     # stop and wipe all data volumes (full reset)
```

If you started the stack with the Traefik overlay, pass both files to `down` as well:
`docker compose -f docker-compose.yml -f docker-compose.traefik.yml down`.

After a `down -v`, re-run the cert generation step before the next `up`.

## Ports

| Port | Purpose |
|---|---|
| 1514/tcp | Agent events |
| 1515/tcp | Agent enrollment |
| 514/udp | Syslog |
| 55000/tcp | Wazuh Manager API |
| 9200/tcp | Indexer (OpenSearch) API |
| 5601/tcp | Dashboard (HTTPS, direct) |
| 443/tcp | Traefik (HTTPS, domain routing) |
| 8080/tcp | Traefik dashboard (localhost only) |

## Make shortcuts

From the **repo root**, `make help` lists everything. Common flow:

```bash
make dev-init   # one-time: dev cert + /etc/hosts + trust CA (sudo)
make dev-up     # start with Traefik domain access
make dev-ps     # status
make dev-down   # stop (keep data)   |   make dev-reset = wipe volumes
```

`make dev-up-basic` starts the stack without Traefik (localhost ports only).

## Agent (test data)

The base stack has no agents, so little flows in. Add one enrolled agent to generate **real
alerts** (file-integrity, config-assessment, and on-demand IOC events) to explore and to test
the connector against:

```bash
make dev-agent-up      # enroll a `dev-agent` with the manager (passwordless authd)
make dev-agent-demo    # inject a sample SSH brute-force -> rule 5710 with data.srcip=203.0.113.45
make dev-agent-logs    # follow the agent
make dev-agent-down    # remove the agent
```

`dev-agent-demo` appends a line to `/var/log/wazuh-demo.log` inside the agent (monitored via
`config/wazuh_agent/ossec.conf`). On the **first** run after `dev-agent-up`, give the log
collector ~1 min to pick up the new file; it's immediate after that. Watch alerts land in the
dashboard (*Security events*) or query the indexer:

```bash
curl -sk -u admin:SecretPassword "https://localhost:9200/wazuh-alerts-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"query_string":{"query":"203.0.113.45"}},"size":1}'
```

The agent is containerized, so it monitors the container (not your host) — fine for generating
alerts and connector test data.
## Whisper connector

Install the `custom-whisper` integration into the dev manager and exercise it:

```bash
make dev-whisper-install       # install (dev mode: test rule + template + refresh index)
make dev-whisper-smoke         # inject a public IP + two guarded IPs, print the log evidence
make dev-demo-enrich           # inject one IOC (IOC=<value>, default a graph-listed Tor IP) and show the enrichment
make dev-acceptance            # run the e2e acceptance suite (TC-01..TC-22) against the live stack (needs a real key)
make dev-whisper-uninstall     # remove it and restore ossec.conf
```

The keyed **agent-activity log source** (`--logs`) has its own targets — it needs a real tenant key
in `/var/ossec/etc/whisper.key` (or `WHISPER_API_KEY` in the manager env) to authenticate `op:logs`:

```bash
make dev-logs-install          # install the whisper.online agent-activity log source (dev mode, with --logs)
make dev-logs-smoke            # run the poller once; show the spool + decoded data.whisper_agent.* alerts
```

### Whisper API key

The connector resolves its key in this order: **`WHISPER_API_KEY` env → `/var/ossec/etc/whisper.key` → argv**.
Two ways to set it on the dev stack:

- **`.env` (recommended)** — set it once; it survives `make dev-reset`. Copy the example and edit:

  ```bash
  cp dev/wazuh-single-node/.env.example dev/wazuh-single-node/.env
  # edit .env: WHISPER_API_KEY=<your key>
  make dev-up            # (re)create the manager so it picks up the key from .env
  ```

  `.env` lives in `dev/wazuh-single-node/` (where `docker compose` reads it) and is gitignored.
  It's injected into the manager container's environment (`docker-compose.yml`
  `WHISPER_API_KEY=${WHISPER_API_KEY:-}`), which the connector reads first.

- **Key file** — put the key directly in the (in-container) key file. Simpler, but wiped by
  `make dev-reset`:

  ```bash
  docker exec wazuh-single-node-wazuh.manager-1 sh -c \
    'umask 137; printf "%s\n" "<your key>" > /var/ossec/etc/whisper.key; chown root:wazuh /var/ossec/etc/whisper.key'
  ```

No restart is needed after changing the key — the script reads it fresh on the next alert.
Without a valid key the connector reaches the API but gets `403` (anonymous); guards, dedup and
alert rendering still work. The stock `dev-agent-demo` IOC (`203.0.113.45`) is TEST-NET and the
connector **deliberately skips it** — use a public IOC to see enrichment.

## Wazuh 5.0 assessment stack

[`wazuh-5-single-node/`](wazuh-5-single-node/) is a **separate**, pinned Wazuh **5.0.0-rc2** stack
(manager + indexer + dashboard). It exists only to assess whether the bundle works on Wazuh 5.0
(see [`docs/wazuh-5.md`](../docs/wazuh-5.md)); the supported target stays 4.14.5 above.

**Provenance.** Vendored from [`wazuh/wazuh-docker`](https://github.com/wazuh/wazuh-docker) at tag
**`v5.0.0-rc2`** (GPLv2, headers kept): `single-node/docker-compose.yml`,
`tools/utils/deployment/certificates-conf.sh`, `tools/utils/deployment/credentials-conf.sh` and
`build-docker-images/shared/password-policy.sh` (which `credentials-conf.sh` sources). The cert
tool (`wazuh-certs-tool.sh`) is downloaded at run time from the pre-release location named in
upstream's `single-node` deployment doc and is not vendored. `certs-config.yml` is the tracked
node layout (upstream's step 4, at the same tag); `make dev5-certs` copies it to `config.yml`,
which the tool rewrites and which is gitignored.

**Local modifications.** None to the vendored files. The helper scripts sit under `tools/` and
`build-docker-images/` inside `wazuh-5-single-node/` so their upstream relative paths resolve.
The 5.0 layout differs from 4.x (`config/root-ca/`, `config/wazuh_manager/`, Docker secrets from
`config/credentials/*.env`, manager under `/var/wazuh-manager`), which is why the existing
`dev-*` targets are not reused.

**Prerequisites.** `vm.max_map_count >= 262144` (see above; on Docker Desktop re-set it after each
restart) and about 8 GB for Docker. No `sudo` on any platform: `make dev5-certs` verifies the
tool's pinned SHA-256 (`WAZUH5_CERTS_TOOL_SHA256` in the `Makefile`) and then runs it only inside a
throwaway `wazuh/wazuh-manager:5.0.0-rc2` container with `--network none`. A mismatch stops
before anything runs. On Linux the container runs as root, so the generated files
(`config/credentials/*.env`, `wazuh-ca/`) are root-owned: reading or deleting them needs root.

**Run.** The two stacks share host ports (1514, 1515, 1517, 55000, 443): stop the 4.14.5 stack first.

```bash
make dev-down                # stop the 4.14.5 stack (keeps its volumes)
make dev5-certs              # download the cert tool, issue certs, generate credentials
make dev5-up                 # start the 5.0 rc2 stack
make dev5-whisper-install    # run the unchanged install.sh; see docs/wazuh-5.md for the result
make dev5-reset              # stop and delete the 5.0 stack's volumes
```

Generated and gitignored, never commit: `config/` (certs and `credentials/*.env`, plaintext
passwords), `wazuh-ca/` (the root CA private key), `wazuh-certificates/`, `wazuh-certificates-tool.log`,
`config.yml` and the downloaded `wazuh-certs-tool.sh`. `make dev5-certs` is a no-op while
`config/root-ca/certs/root-ca.pem` or `wazuh-certificates/` exists; to regenerate, delete those
paths first.

The manager logs a warning that `remoted.pem` carries no name an agent could dial. That is
expected on a stack with no agent. `certs-config.yml` lists `127.0.0.1` and `wazuh.manager`, and
`wazuh.manager` is what the spike agent below dials over the compose network (enrolment worked
with no certificate change on 2026-11-12). To enroll an agent from another host, add that host's
address to the manager node in `certs-config.yml` and regenerate the certificates.

### Spike: a hook-free enrichment path (option (b), issue #67)

An optional pair of overlays adds an enrolled 5.0.0-rc2 agent and a finding enricher to the 5.0
stack. They exist to test whether Whisper enrichment can run on 5.0 without the `<integration>`
hook (see [`docs/wazuh-5.md`](../docs/wazuh-5.md#option-b-spike)). Nothing here ships and the
shipped bundle is unchanged.

```bash
make dev5-agent-up               # mint an enrollment token on the manager API, start the agent
make dev5-agent-demo             # append an sshd pre-auth close from 185.220.101.1 (IOC=<ip> to change)
make dev5-spike-setup            # enrichment template, index, least-privilege role and user
make dev5-spike-up               # start the poller (polls wazuh-findings-v5-* every 30 s)
make dev5-spike-query FINDING=<finding _id>
make dev5-agent-down             # remove the agent container (dev5-down and dev5-reset stop everything)
```

The finding appears about 2 minutes after the log line (the detector runs on a schedule) and the
enrichment within one poll after that. The files:

- [`wazuh-5-single-node/docker-compose.agent.yml`](wazuh-5-single-node/docker-compose.agent.yml):
  the `wazuh/wazuh-agent:5.0.0-rc2` pre-release image, pinned by digest. It mounts no config: the
  stock agent config already tails `/var/ossec/logs/active-responses.log`, where the demo target
  appends.
- [`wazuh-5-single-node/docker-compose.spike.yml`](wazuh-5-single-node/docker-compose.spike.yml):
  `python:3.11-slim` (pinned by digest) running
  [`wazuh-5-spike/finding_enricher.py`](wazuh-5-spike/finding_enricher.py), which loads the
  connector read-only. No host ports.

The enricher reads these optional environment overrides: `WHISPER_SPIKE_INDEXER_URL`,
`WHISPER_SPIKE_CA`, `WHISPER_SPIKE_ADMIN_CREDENTIALS`, `WHISPER_SPIKE_OUT_DIR`,
`WHISPER_SPIKE_CREDENTIALS`, `WHISPER_SPIKE_CONNECTOR_DIR`, `WHISPER_SPIKE_STATE_DIR` and
`WHISPER_API_URL`. The compose overlay sets the paths; none of them holds a secret value.

**The enrollment token is a credential.** `make dev5-agent-up` authenticates to the manager API
with the credential from `config/credentials/manager.env` (through curl's stdin config, not argv),
mints a one-use token that expires after 10 minutes and hands it to `docker compose up` through
the environment of that one recipe. It is never echoed or put on a command line. Docker keeps it
in the agent container's config until `make dev5-agent-down` removes the container. The agent's `/var/ossec/etc` lives in the
`wazuh_agent_etc` volume; `make dev5-reset` deletes it.

Generated and gitignored, never commit: `config/whisper-enricher/enricher.env` (the enricher
user's generated password, `0600`). `make dev5-spike-setup` runs one throwaway container that reads
the indexer admin credential from Docker secrets, creates the role and user, and writes that file;
the long-running poller sees only its own credential. On Linux the generated file is root-owned.
