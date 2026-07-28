# whisper-wazuh

Whisper integration for [Wazuh](https://wazuh.com/) — enrich Wazuh alerts and indicators
with relationship context from the Whisper infrastructure graph.


## Status

**Released — v1.0.0.** Milestones 1 (MVP), 2 (Enrichment Expansion), and 3 (Release &
Distribution) are complete: a working per-alert connector plus an on-demand investigation CLI,
verified end-to-end on **Wazuh 4.14.5**, and shipped as a tarball, `.deb`/`.rpm` packages, and a
one-line installer (see [Install](#install) and the [changelog](CHANGELOG.md)).
See the [milestones](https://github.com/whisper-sec/whisper-wazuh/milestones) and
[issues](https://github.com/whisper-sec/whisper-wazuh/issues) for what's next.

## Documentation

- [**Architecture**](docs/architecture.md) — how the whole solution fits together (start here).
- [**Installation & configuration**](docs/installation.md) — the full admin guide: install methods, the API key, trigger groups, verify, and troubleshooting.
- [Whisper→Wazuh mapping](docs/whisper-to-wazuh-mapping.md) — the field-by-field mapping, verdict gates, and enrichment envelope.
- [MVP acceptance criteria](docs/mvp-acceptance-criteria.md) — the TC-01..TC-22 test matrix and definition of done.

## Install

On your Wazuh manager (4.x, as root). Pick whichever fits — all three run the same `install.sh`.

**A — one-line bootstrap** (easiest):
```bash
curl -sSL https://raw.githubusercontent.com/whisper-sec/whisper-wazuh/main/bootstrap.sh \
  | sudo sh -s -- --group sshd --api-key-file /path/to/your-whisper-key.txt
```

**B — download the tarball** (inspect before running as root):
```bash
curl -sSL https://github.com/whisper-sec/whisper-wazuh/releases/latest/download/whisper-wazuh.tar.gz | tar xz
cd whisper-wazuh-*
sudo sh install.sh --group sshd --api-key-file /path/to/your-whisper-key.txt
```

**C — OS package** (`.deb`/`.rpm`, for `apt`/`yum` + config management):
```bash
# grab the package for your distro from the Releases page, then:
sudo dpkg -i whisper-wazuh_<ver>_all.deb        # Debian/Ubuntu  (RHEL: rpm -i …noarch.rpm)
sudo whisper-wazuh-install --group sshd --api-key-file /path/to/your-whisper-key.txt
```
The package stages the files to `/usr/share/whisper-wazuh` and adds a `whisper-wazuh-install`
command; it does **not** auto-activate (activation patches `ossec.conf` and restarts the manager,
so it's an explicit admin step).

All three push the indexer template, drop the files, patch `ossec.conf` (with rollback), restart,
and verify. Enrichment starts on the next alert in a trigger group that carries a public IP or
domain.

**Prerequisites:** a Wazuh manager 4.x (root), TLS egress to `graph.whisper.security`, and your
own Whisper API key (BYOK). Running a **containerized** manager? Skip `--api-key-file` and inject
`WHISPER_API_KEY` as a container-env secret instead.

**Verify:**
```bash
grep whisper: /var/ossec/logs/integrations.log   # expect  invoke → api → emit
```
then search `data.whisper.ioc:<the IP>` in the dashboard — a new enrichment alert appears next to
the original. See [Architecture](docs/architecture.md) for how it all fits together, and
[`uninstall.sh`](integrations/whisper/uninstall.sh) to remove it cleanly.

## Branching

- `main` — release-only, stable.
- `develop` — default integration branch; feature branches open PRs here.

## Local development

A single-node Wazuh stack (manager + indexer + dashboard) for local testing lives under
[`dev/`](dev/). From the repo root:

```bash
make dev-init      # one-time: TLS cert + /etc/hosts + trust CA (sudo)
make dev-up        # start, with Traefik domain access
make dev-agent-up  # add an agent that generates real test alerts
make help          # list all dev targets
```

See [dev/README.md](dev/README.md) for the full guide (domains, ports, agent/test data, reset).

## License

Apache-2.0 — see [LICENSE](LICENSE).
