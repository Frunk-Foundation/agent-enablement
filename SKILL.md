# aws-toolkit-4-agents (Operator Skill)

This repository now uses a credentials + MCP runtime model:

1. `POST /v1/credentials` returns short-lived STS credentials and runtime references.
2. `./enabler-creds` manages credential lifecycle and AWS `credential_process` output.
3. `./enabler-mcp` exposes runtime tools for agent operations.

## Core Rules

- Treat `credentials.json` and Cognito token artifacts as sensitive.
- Use CloudFormation for provisioning workflows.
- Keep endpoint/token preflight strict.
- Keep runtime (`enabler-creds`/`enabler-mcp`) and admin (`enabler-admin`) surfaces separated.

## Current CLI Surfaces

### Runtime
- `./enabler-creds`: `summary`, `status`, `paths`, `refresh`, `credential-process`
- `./enabler-mcp`: MCP stdio server for taskboard/messages/files/shortlinks
- `./enabler`: retired shim

### Admin
- `./enabler-admin`: `stack-output`, `ssm`, `cognito`, `agent`

## Runtime Data Model

### `.enabler/credentials.json`
Contains issued STS credentials and runtime references, including:
- `principal`
- `credentials`
- `cognitoTokens`
- `grants`
- `constraints`
- `references` (messages, s3, ssmKeys, provisioning, taskboard, shortlinks, files)

### Additional credential artifacts
- `.enabler/sts.env`
- `.enabler/sts-<set>.env`
- `.enabler/cognito.env`

## Skills Layout

Skills are sourced directly from root `skills/` folders:
- `skills/get-started/SKILL.md`
- `skills/messages-basic-ops/SKILL.md`
- `skills/files-basic-ops/SKILL.md`
- `skills/shortlinks/SKILL.md`
- `skills/taskboard-basics/SKILL.md`
- `skills/ssm-key-access/SKILL.md`
- `skills/provisioning-cfn-mode/SKILL.md`

## Operator Shortcuts

```bash
./enabler-admin --help
./enabler-creds --help
./enabler-mcp
just test
```

## Wish I Knew Earlier

- MCP stdio framing here must be newline-delimited JSON-RPC. `Content-Length` framing causes Codex MCP startup timeout symptoms even when the server process is fast.
