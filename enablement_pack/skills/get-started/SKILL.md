# Get Started

## Purpose
Bootstrap from the content-only bundle, persist `connection.json`, and fetch short-lived credentials for runtime commands.

## When To Use
Use immediately after receiving bootstrap values (username, password, API key, bundle endpoint).

## Inputs
- `enabler` binary in your environment.
- Bootstrap values:
  - `ENABLER_COGNITO_USERNAME`
  - `ENABLER_COGNITO_PASSWORD`
  - `ENABLER_API_KEY`
  - `ENABLER_BUNDLE_ENDPOINT`
- Optional credentials endpoint override: `ENABLER_CREDENTIALS_ENDPOINT`.

## Workflow
1. Fetch bundle metadata and download the ZIP (also writes `.enabler/connection.json`):

```bash
./enabler bundle
```

2. Fetch credentials (writes `.enabler/credentials.json`):

```bash
./enabler credentials --summary
```

3. Verify local caches:

```bash
ls -l .enabler/connection.json .enabler/credentials.json
jq '.shortlinks, .taskboard, .files, .ssmKeys, .cognito' .enabler/connection.json
jq '.principal, .credentials.expiration, .references.messages' .enabler/credentials.json
```

4. Continue with task-focused skills:
   - `skills/files-basic-ops/SKILL.md`
   - `skills/messages-basic-ops/SKILL.md`
   - `skills/shortlinks/SKILL.md`
   - `skills/ssm-key-access/SKILL.md`
   - `skills/provisioning-cfn-mode/SKILL.md`

## Outputs
- `.enabler/connection.json` from `POST /v1/bundle`.
- `.enabler/credentials.json` from `POST /v1/credentials`.
- Downloaded bundle ZIP under `.enabler/bundles/` (unless `--out` is set).

## Guardrails
- Bundle ZIP is content-only; never expect secrets inside it.
- Treat `.enabler/credentials.json` as sensitive.
- Refresh credentials when expired; no refresh token is returned.

## References
- `../../artifacts/README.md`
- `../../artifacts/agent_note.md`
