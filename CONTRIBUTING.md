# Contributing to whisper-wazuh

Thanks for contributing! This project currently sits in
**Milestone 0 — Requirement Analysis**, so scope, the integration pattern, and the
Whisper→Wazuh data mapping are still being finalized. Some sections below (dev setup, tests)
will firm up once Milestone 0 closes.

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

1. Find or open an issue describing the change. Requirement-analysis work is tracked under
   [Milestone 0](https://github.com/whisper-sec/whisper-wazuh/milestones).
2. Branch off `develop`: `git checkout develop && git pull && git checkout -b feat/my-change`.
3. Make focused commits (see commit style below).
4. Open a PR **targeting `develop`** (never push directly — protected branches reject it).
5. Resolve all review conversations; CI (once added) must be green.
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

## Code style

The implementation language and tooling will be finalized as Milestone 0 closes (expected
Python 3.12 with `ruff` for lint/format and `pytest` for tests). Until then, keep
contributions limited to docs and requirement-analysis artifacts.

## Reporting issues

Open a GitHub issue with enough context to reproduce or act on it. For security-sensitive
reports, contact the maintainers privately rather than filing a public issue.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).