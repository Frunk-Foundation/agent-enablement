# Agent Enablement

This repo provides a bundle-first agent bootstrap flow with two CLIs:

- `./enabler`: agent/runtime workflow (`bundle`, `credentials`, `files`, `messages`, `shortlinks`, `taskboard`)
- `./enabler-admin`: admin/control-plane workflow (`stack-output`, `ssm`, `cognito`, `agent`, `pack-build`, `pack-publish`)

## API Surface

- `POST /v1/bundle`: returns `bundleUrl` plus non-secret `connection` metadata
- `POST /v1/credentials`: returns short-lived STS credentials and runtime references
- `POST /v1/links`: creates shortlinks (Cognito bearer)
- `GET /l/{code}`: resolves shortlinks
- `/v1/taskboard/*`: taskboard operations (Cognito bearer)

## Agent Quickstart

1. Provide bootstrap env vars:

```bash
export ENABLER_COGNITO_USERNAME='<username>'
export ENABLER_COGNITO_PASSWORD='<password>'
export ENABLER_API_KEY='<shared-api-key>'
export ENABLER_BUNDLE_ENDPOINT='<bundle-endpoint-url>'
# optional when not derivable from bundle auth metadata
export ENABLER_CREDENTIALS_ENDPOINT='<credentials-endpoint-url>'
```

2. Download bundle and persist connection metadata:

```bash
./enabler bundle
```

3. Fetch runtime credentials and persist credentials cache:

```bash
./enabler credentials
```

4. Use runtime commands:

```bash
./enabler files share ./artifact.txt
./enabler messages send --to teammate --text "ready"
./enabler shortlinks create "https://example.com/path/file.txt"
./enabler taskboard create --name "Sprint"
```

`./enabler files share` prints the public CloudFront URL by default. Use `--json` to include `s3Uri` and other metadata.

## Credentials Output Modes

- Default: human-readable artifact locations + freshness status.
- Full payload JSON: `--json`.
- Every run writes shell-compatible STS env file(s):
  - `.enabler/sts.env` for the active runtime set.
  - One file per credential set when present
    (for example `.enabler/sts-agentenablement.env` and `.enabler/sts-agentawsworkshopprovisioning.env`).
- Every run writes Cognito token env file: `.enabler/cognito.env`.

Examples:

```bash
# Default location output
./enabler credentials

# Full response JSON
./enabler credentials --json

# Files are written on every run:
# - .enabler/sts.env
# - .enabler/sts-<credential-set>.env (if credential sets exist)
# - .enabler/cognito.env
```

## Shortlinks Output Modes

- Default: two human-readable lines (`code` and `shortURL`).
- JSON mode: use `--json` for the full response payload (`--plain-json` for compact JSON).

Examples:

```bash
# Human-readable default output
./enabler shortlinks create "https://example.com/path/file.txt"

# Full JSON response
./enabler shortlinks create "https://example.com/path/file.txt" --json
```

## Local Cache Model

- Credentials cache: `.enabler/credentials.json` (or `--creds-cache` / `ENABLER_CREDS_CACHE`)
- Connection cache: `.enabler/connection.json` (written by `enabler bundle`)
- Bundle ZIP downloads: `.enabler/bundles/`

`enabler` strictly reads runtime endpoints from explicit env/flags or `.enabler/connection.json`.

## Taskboard Output Modes

- Default: human-readable summaries/tables for fast terminal scanning.
- JSON mode: prepend `--json` at the taskboard group level for raw API payloads.

Examples:

```bash
# Human-readable default output
./enabler taskboard list <board-id> --status pending --limit 25

# Raw JSON output (pretty by default; combine with global --plain-json for compact)
./enabler taskboard --json list <board-id> --status pending --limit 25
```

## Admin CLI

### Stack and Shared Secrets

```bash
./enabler-admin stack-output
./enabler-admin ssm api-key
./enabler-admin ssm base-paths
./enabler-admin ssm put-shared sample-key --value 'value' --overwrite
./enabler-admin ssm get-shared sample-key
```

### Cognito and Agent Onboarding

```bash
./enabler-admin cognito create-user --username <u> --password <p>
./enabler-admin cognito remove-user <u>
./enabler-admin agent onboard <username> <password>
./enabler-admin agent decommission <username>
./enabler-admin agent handoff create --username <u> --password <p> --out handoff.json
./enabler-admin agent handoff print-env --file handoff.json
```

### Enablement Pack Build/Publish

```bash
./enabler-admin pack-build
./enabler-admin pack-publish --version v1
```

`pack-publish` uses `--bucket` when provided; otherwise it resolves the bucket from stack output `CommsSharedBucketName`.

## Enablement Pack Layout

`enablement_pack/build_pack.py` produces:

- `enablement_pack/dist/<version>/CONTENTS.md`
- `enablement_pack/dist/<version>/metadata.json`
- `enablement_pack/dist/<version>/artifacts/...`
- `enablement_pack/dist/<version>/skills/...`
- `enablement_pack/dist/<version>/agent-enablement-bundle.zip`

The bundle is content-only. Credentials and secrets are never embedded in bundle artifacts.

## Tests

```bash
just test
```

System tests (requires deployed stack + AWS access):

```bash
just test-system
```
