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
