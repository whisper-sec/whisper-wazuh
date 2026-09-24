# Contributing to whisper-wazuh

Thanks for contributing! The integration is shipping (v1.0.0) — a per-alert enrichment connector,
an on-demand investigation CLI, and the install/release tooling. If you're new here, read
[docs/architecture.md](docs/architecture.md) for how it all fits together, then skim
[docs/whisper-to-wazuh-mapping.md](docs/whisper-to-wazuh-mapping.md) for the field-level detail.

## Branching model

We use a Git Flow style with two long-lived branches:

- **`main`** — release-only, always stable. Protected.
- **`develop`** — default integration branch; all feature work merges here first. Protected.

Day-to-day work happens on short-lived branches cut from `develop`:

```
develop ──┬─► feat/<short-name>   ─► PR ─► develop
          ├─► fix/<short-name>    ─► PR ─► develop
          └─► docs/<short-name>   ─► PR ─► develop
```

Releases flow `develop` → `main` via a PR.

Suggested branch prefixes: `feat/`, `fix/`, `docs/`, `chore/`, `refactor/`, `test/`.

## Workflow

1. Find or open an issue describing the change. Work is tracked under the
   [milestones](https://github.com/whisper-sec/whisper-wazuh/milestones).
2. Branch off `develop`: `git checkout develop && git pull && git checkout -b feat/my-change`.
3. Make focused commits (see commit style below).
4. Open a PR **targeting `develop`** (never push directly — protected branches reject it).
5. Resolve all review conversations; CI must be green (ruff lint + format, pytest on 3.10 and 3.12).
6. Squash or merge per the PR; delete the branch after merge.

## Branch protection (what to expect)

Both `main` and `develop` are protected:

- Direct pushes are rejected — changes must go through a pull request.
- Force-pushes and branch deletion are blocked.
- All review conversations must be resolved before merge.
- Stale approvals are dismissed when new commits are pushed.
- `main` requires **1 approving review** from a non-admin author; `develop` is PR-gated with
  no required approvals while the team is small.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short summary>

<optional body explaining the why>
```

Common types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`.

## Dev setup

The connector is **stdlib-only Python** (targets 3.10, the version the Wazuh manager ships) and
POSIX-sh install scripts — no runtime dependencies. You only need dev tooling to lint and test:

```bash
pip install ruff==0.6.9 pytest        # ruff pinned exactly as CI does; pytest unpinned
ruff check . && ruff format --check . && pytest -q
```

Run that before you open a PR — it's exactly what CI runs. `ruff` is configured in
[pyproject.toml](pyproject.toml) (py310, line length 110, single quotes).

To exercise the integration against a real stack, there's a single-node Wazuh (manager + indexer +
dashboard) under [`dev/`](dev/). `make help` lists every target; `make dev-up` brings the stack up
and `make dev-whisper-smoke` runs a quick connector check. See [dev/README.md](dev/README.md).

## Code style

Match the surrounding code. Keep the connector dependency-free (stdlib only) so it runs on an
unmodified manager, and keep the shell scripts POSIX `sh` (they run under `dash`/`busybox`) — the
test suite parses them with `sh -n` to enforce it.

## Reporting issues

Open a GitHub issue with enough context to reproduce or act on it. For security-sensitive
reports, contact the maintainers privately rather than filing a public issue.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).