# aws-toolkit-4-agents (Operator Skill)

This repository implements a bundle-first agent bootstrap system:

1. `POST /v1/bundle` returns a presigned ZIP URL and `connection` metadata.
2. `POST /v1/credentials` returns short-lived credentials and runtime references.

## Core Rules

- Treat `credentials.json` as sensitive.
- Use CloudFormation for provisioning workflows.
- Keep endpoint/token preflight strict in both CLIs.
- Keep `enabler` (agent) and `enabler-admin` (admin) surfaces separated.

## Current CLI Surfaces

### Agent CLI (`./enabler`)
- `bundle`
- `credentials`
- `files`
- `messages`
- `shortlinks`
- `taskboard`

### Admin CLI (`./enabler-admin`)
- `stack-output`
- `ssm`
- `cognito`
- `agent`
- `pack-build`
- `pack-publish`

## Runtime Data Model

### `.enabler/connection.json` (from bundle)
Contains non-secret service connectivity and auth references, including:
- `auth`
- `shortlinks`
- `taskboard`
- `files`
- `cognito`
- `ssmKeys`

### `.enabler/credentials.json` (from credentials)
Contains issued STS credentials and runtime references, including:
- `principal`
- `credentials`
- `cognitoTokens`
- `grants`
- `constraints`
- `references` (for `messages`, `s3`, `ssmKeys`, `provisioning`, etc.)

## Enablement Pack

Pack content is generated from `enablement_pack/manifest.yaml` and published under:
- `agent-enablement/<version>/...`
- `agent-enablement/latest/...`
- `agent-enablement/latest.json`

Legacy multi-prefix publishing is intentionally removed.

## Operator Shortcuts

```bash
./enabler-admin --help
./enabler --help
./enabler-admin pack-build
./enabler-admin pack-publish --version v1
just test
```
