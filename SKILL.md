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
- `./enabler-mcp`: MCP stdio server for taskboard/eventbus/jmap-mail/jmap-contacts/fileshare/shortlinks
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
- `references` (eventbus, jmapMail, jmapContacts, directory, s3, ssmKeys, provisioning, taskboard, shortlinks, files)

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
- Delegation uses short-code request/approve/redeem. Redeem is now retry-safe: the request moves through a `redeeming` state and only finalizes after ephemeral Cognito auth and profile upsert succeed.
- Agent-id session mode must derive credential paths from resolved `GlobalOpts.agent_id` (not only env). Otherwise helper flows that construct `GlobalOpts` directly will silently read/write the wrong session.
- Managed session storage is keyed by stable `principal.sub`, not by mutable `agentId`. Session listing and `set_agentid` still use `agentId` as the human-facing alias.
- Codex MCP can start unbound (no `--agent-id`). In unbound mode, bootstrap via `credentials.exec` delegation request/approve/redeem, then runtime tools become available.
- MCP runtime switching (`credentials.exec` + `action=set_agentid`) changes only the default context for future calls; async jobs must pin enqueue-time `agentId` to avoid identity drift.
- MCP has a built-in discovery path now: call top-level `help` or any `*.exec` with `action=help`; in unbound mode, help still works so bootstrap guidance is always available.
- After credentials schema changes deploy, run `credentials.exec` with `action=ensure` and `args.forceRefresh=true` to pull new fields immediately instead of waiting for expiry-driven refresh.
- Runtime credential renewal is refresh-token-only. Username/password are for bootstrap issuance only; admin-issued seeded bundles and delegation redeem should converge on the same session artifact.
- Cognito refresh lifetime now follows `profileType` via separate app clients in one pool: named uses the long-lived client, ephemeral uses the 7-day client. If refresh behavior looks wrong, inspect the cached `auth.cognitoClientId` first.
- `trunk check` is not usable until the repo has been initialized with `trunk init`; otherwise it exits immediately with that setup error instead of linting changed files.
- Runtime SSM access is available via `ssm.exec` (`paths|list|get`); returned values are plaintext secret material and must not be echoed into logs or transcripts.
- Agent mail now goes through `jmap-mail.exec`; the old EventBridge/SQS inbox flow is rebranded as `eventbus.exec` and is not the mail interface.
- JMAP mail attachments are fileshare-backed in v1: `emailsubmission_set` can reference pre-uploaded attachment objects or upload `attachmentFilePaths` directly and persist the resulting attachment metadata on the mail item.
- MCP runtime context falls back to `ENABLER_COGNITO_USERNAME` when `ENABLER_AGENT_ID` is unset, so tests or unbound startup checks must clear both env vars if they intend to exercise true unbound behavior.
