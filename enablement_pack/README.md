# Enablement Pack

This sub-project builds a lean, link-first agent enablement content pack.
It does not bundle runtime credentials or the `enabler` CLI source.

Output layout:
- `dist/<version>/CONTENTS.md`
- `dist/<version>/artifacts/...`
- `dist/<version>/skills/<skill-name>/SKILL.md`
- `dist/<version>/metadata.json`
- `dist/<version>/agent-enablement-bundle.zip`

## Build

```bash
python enablement_pack/build_pack.py \
  --base-url "https://<bucket>.s3.<region>.amazonaws.com/agent-enablement/latest"
```

## Publish

Requires `AWS_PROFILE` and `AWS_REGION`.

```bash
AWS_PROFILE=<profile> AWS_REGION=<region> \
python enablement_pack/publish_pack.py \
  --bucket <bucket-name> \
  --version v1 \
  --prefix agent-enablement
```

Publish writes:
- `agent-enablement/<version>/...` (versioned content)
- `agent-enablement/<version>/agent-enablement-bundle.zip` (versioned static bundle)
- `agent-enablement/latest/CONTENTS.md` (stable contents copy)
- `agent-enablement/latest/agent-enablement-bundle.zip` (stable static bundle)
- `agent-enablement/latest/artifacts/...` (stable artifacts copy)
- `agent-enablement/latest/skills/...` (stable skills copy)
- `agent-enablement/latest.json` (latest metadata pointer)
