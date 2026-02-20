# Enablement Pack Access

## Purpose
Fetch enablement pack content by URL when you only have `credentials.json` and no local bundle ZIP.

## When To Use
Use as a fallback in credentials-only mode when local `skills/` and `artifacts/` are missing.

## Inputs
- `credentials.json` from `POST /v1/credentials`.
- `references.enablement.indexUrl`.
- `references.enablement.skillsRootUrl`.
- `references.enablement.artifactsRootUrl`.

## Workflow
1. Extract URLs:

```bash
INDEX_URL="$(jq -r '.references.enablement.indexUrl' credentials.json)"
SKILLS_ROOT="$(jq -r '.references.enablement.skillsRootUrl' credentials.json)"
ARTIFACTS_ROOT="$(jq -r '.references.enablement.artifactsRootUrl' credentials.json)"
```

2. Download the contents guide:

```bash
curl -sS "$INDEX_URL" -o CONTENTS.md
sed -n '1,120p' CONTENTS.md
```

3. Fetch one skill and one artifact:

```bash
curl -sS "${SKILLS_ROOT%/}/shortlinks/SKILL.md" -o shortlinks.SKILL.md
curl -sS "${ARTIFACTS_ROOT%/}/README.md" -o README.enablement.md
```

4. Optional: mirror pack fragments locally:

```bash
mkdir -p skills/shortlinks artifacts
mv shortlinks.SKILL.md skills/shortlinks.SKILL.md
mv README.enablement.md artifacts/README.md
```

## Outputs
- Local `CONTENTS.md`.
- Downloaded skill and artifact files.

## Guardrails
- Prefer HTTPS links from `references.enablement.*`; do not invent keys.
- Treat any presigned URLs as bearer secrets.
- Re-fetch after bundle version changes.

## References
- `../../artifacts/README.md`
