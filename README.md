# whisper-wazuh

Whisper integration for [Wazuh](https://wazuh.com/) — enrich Wazuh alerts and indicators
with relationship context from the Whisper infrastructure graph.

Sister project to [`whisper-opencti`](https://github.com/whisper-sec/whisper-opencti).

## Status

🚧 **Milestone 0 — Requirement Analysis.** Scope, integration pattern, and the
Whisper→Wazuh data mapping are being finalized before implementation begins.
See the [milestones](https://github.com/whisper-sec/whisper-wazuh/milestones) and
[issues](https://github.com/whisper-sec/whisper-wazuh/issues) for current work.

## Branching

- `main` — release-only, stable.
- `develop` — default integration branch; feature branches open PRs here.

## Local development

A single-node Wazuh stack (manager + indexer + dashboard) for local testing lives under
[`dev/`](dev/). From the repo root:

```bash
make dev-init   # one-time: TLS cert + /etc/hosts + trust CA (sudo)
make dev-up     # start, with Traefik domain access
make help       # list all dev targets
```

See [dev/README.md](dev/README.md) for the full guide (domains, ports, reset, etc.).

## License

Apache-2.0 — see [LICENSE](LICENSE).