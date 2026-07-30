# Submission package for `wazuh/integrations`

This directory stages the **community-listing** version of the Whisper enrichment connector for the
official Wazuh integrations repository ([`wazuh/integrations`](https://github.com/wazuh/integrations)),
formatted to that repo's conventions. It is a **listing for ecosystem visibility** — the source of
truth and full distribution (packaging, the keyed log source, the CLI, the dev stack) stay in *this*
repo.

`whisper/` contains exactly what would go into `wazuh/integrations/integrations/whisper/`:

| File | Notes |
|---|---|
| `README.md` | in the `wazuh/integrations` README format (Introduction / Install / Wazuh config / Manual tests / Sources) |
| `custom-whisper`, `custom-whisper.py` | the connector wrapper + script |
| `whisper_client.py` | the shared HTTP/TLS client the connector imports |
| `whisper_rules.xml` | the verdict→level rules |
| `whisper-template.json` | the indexer field-type template |

Scope is the **enrichment connector only** (keyless, always-on — the natural fit for the community
repo). The keyed tier (log source, CLI) and the packaged installers are described in the README and
linked back to this repo.

## Keeping it in sync

The five connector files here are **copies** of `integrations/whisper/*`. Re-copy them before each
submission so the listing doesn't drift:

```bash
cp integrations/whisper/{custom-whisper,custom-whisper.py,whisper_client.py,whisper_rules.xml,whisper-template.json} \
   contrib/wazuh-integrations/whisper/
```

## Submitting (when approved)

1. Fork `wazuh/integrations`.
2. Copy `contrib/wazuh-integrations/whisper/` into the fork as `integrations/whisper/`.
3. Open a PR to `wazuh/integrations` following their `CONTRIBUTING.md`.

## ⚠️ License — read before submitting

`wazuh/integrations` is licensed **AGPL-3.0**; this project is **Apache-2.0**. Contributing these
files means the copy that lives in `wazuh/integrations` is distributed under **AGPL-3.0** (Apache-2.0
is one-way compatible into AGPL-3.0, so this is permitted — but it is a deliberate relicensing of the
contributed copy). This repository's copy stays Apache-2.0.

For a commercial product, **get sign-off from whoever owns licensing** before opening the PR. This is
a business/legal decision, not a technical one — it does not affect how the integration runs.