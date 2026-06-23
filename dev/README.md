# Local Wazuh dev stack

A single-node Wazuh stack (manager + indexer + dashboard) for developing and testing the
whisper-wazuh integration locally. Single-node is intentional — it exposes the same APIs as a
production cluster while staying light enough for a laptop.

## Provenance

The files under [`wazuh-single-node/`](wazuh-single-node/) are vendored **verbatim** from the
official [`wazuh/wazuh-docker`](https://github.com/wazuh/wazuh-docker) repository at tag
**`v4.14.5`** (`single-node/` directory). Those upstream files are licensed **GPLv2** (see the
header in each compose file) and are kept unmodified so they're easy to re-sync on a version
bump. This pins our target Wazuh version — see issue #4.

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
| Dashboard | https://localhost (`:443`) | `admin` / `SecretPassword` |
| Indexer API | https://localhost:9200 | `admin` / `SecretPassword` |
| Manager API | https://localhost:55000 | `wazuh-wui` / `MyS3cr37P450r.*-` |

The certs are self-signed, so browsers and `curl` will warn (`curl -k`).

> ⚠️ These are upstream **default** dev passwords. Change them before any non-local use — see
> the Wazuh docs on changing default passwords.

## Stop / reset

```bash
docker compose down        # stop, keep data volumes
docker compose down -v     # stop and wipe all data volumes (full reset)
```

After a `down -v`, re-run the cert generation step before the next `up`.

## Ports

| Port | Purpose |
|---|---|
| 1514/tcp | Agent events |
| 1515/tcp | Agent enrollment |
| 514/udp | Syslog |
| 55000/tcp | Wazuh Manager API |
| 9200/tcp | Indexer (OpenSearch) API |
| 443/tcp | Dashboard (HTTPS) |