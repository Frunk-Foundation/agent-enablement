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
- `./enabler-mcp`: MCP stdio server for taskboard/messages/share/shortlinks
- `./enabler-mcp-cli`: thin local MCP client (`list`, `inspect`, `call`, `result`, `raw`)
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
- `skills/enabler-mcp-cli/SKILL.md`
- `skills/provisioning-cfn-mode/SKILL.md`

## Operator Shortcuts

```bash
./enabler-admin --help
./enabler-creds --help
./enabler-mcp
./enabler-mcp-cli list
just test
```

## Wish I Knew Earlier

- MCP stdio framing here must be newline-delimited JSON-RPC. `Content-Length` framing causes Codex MCP startup timeout symptoms even when the server process is fast.
- Delegation uses short-code request/approve/redeem. Any named profile can approve a pending code; redeem is one-time and writes the target session cache/artifacts.
- Agent-id session mode must derive credential paths from resolved `GlobalOpts.agent_id` (not only env). Otherwise helper flows that construct `GlobalOpts` directly will silently read/write the wrong session.
- Codex MCP can start unbound (no `--agent-id`). In unbound mode, bootstrap via `credentials.exec` delegation request/approve/redeem, then runtime tools become available.
- MCP runtime switching (`credentials.exec` + `action=set_agentid`) changes only the default context for future calls; async jobs must pin enqueue-time `agentId` to avoid identity drift.
- MCP has a built-in discovery path now: call top-level `help` or any `*.exec` with `action=help`; in unbound mode, help still works so bootstrap guidance is always available.
- After credentials schema changes deploy, run `credentials.exec` with `action=ensure` and `args.forceRefresh=true` to pull new fields immediately instead of waiting for expiry-driven refresh.
- Runtime SSM access is available via `ssm.exec` (`paths|list|get`); returned values are plaintext secret material and must not be echoed into logs or transcripts.
