# Agent Enablement

This repo provides an agent-first runtime flow with split credential and MCP surfaces:

- `./enabler-creds`: credential lifecycle (`summary`, `status`, `paths`, `refresh`, `credential-process`)
- `./enabler-mcp`: agent MCP server (taskboard/messages/files/shortlinks + credential visibility)
- `./enabler-admin`: admin/control-plane workflow (`stack-output`, `ssm`, `cognito`, `agent`)
- `./enabler`: retired; prints migration guidance and exits non-zero

## API Surface

- `POST /v1/credentials`: returns short-lived STS credentials and runtime references
- `POST /v1/delegation/requests`: create short-code delegation request (API key)
- `POST /v1/delegation/approvals`: approve pending delegation request (Cognito bearer)
- `POST /v1/delegation/redeem`: redeem approved request code for ephemeral credentials (API key)
- `POST /v1/delegation/status`: fetch request status by code (API key)
- `POST /v1/links`: creates shortlinks (Cognito bearer)
- `GET /l/{code}`: resolves shortlinks
- `/v1/taskboard/*`: taskboard operations (Cognito bearer)

## Agent Quickstart

1. Install local runtime dependencies:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

2. Provide bootstrap env vars:

```bash
export ENABLER_COGNITO_USERNAME='<username>'
export ENABLER_COGNITO_PASSWORD='<password>'
export ENABLER_API_KEY='<shared-api-key>'
export ENABLER_CREDENTIALS_ENDPOINT='<credentials-endpoint-url>'
# optional when starting MCP already bound:
export ENABLER_AGENT_ID='<agent-id>'
```

3. Fetch/refresh runtime credentials and write artifacts:

```bash
./enabler-creds summary
```

4. For AWS CLI/SDK, use `credential_process`:

```bash
./enabler-creds credential-process --set agentEnablement
```

Ephemeral delegation flow (request -> approve -> redeem):

```bash
# requester (can be an ephemeral bootstrap client)
./enabler-creds delegation request --scopes taskboard,messages --ttl-seconds 600 --purpose "session bootstrap"
# approver (named profile only)
./enabler-creds delegation approve --request-code '<requestCode>'
# requester redeems and writes local session artifacts
./enabler-creds delegation redeem --request-code '<requestCode>'
```

5. For agents, launch MCP:

```bash
./enabler-mcp
```

`./enabler-mcp` uses newline-delimited JSON-RPC over stdio (MCP transport). It does not use `Content-Length` framing.

Runtime identity switching is supported without restart via MCP tool `credentials.exec`:
- Startup `--agent-id` is optional; MCP may start unbound.
- `credentials.exec` with `action=set_agentid` changes default context for subsequent calls.
- Async operations are pinned to the `agentId` active at enqueue time.

Credential lifecycle actions are exposed via MCP tool `credentials.exec`:
- `action=ensure`: ensure credentials are present/fresh and return readiness metadata.
  - pass `args.forceRefresh=true` to force broker refresh immediately and rewrite local artifacts (`session.json`, `sts*.env`, `cognito.env`).
- `action=list_sessions`: enumerate managed local agent sessions.
- `action=set_agentid`: switch default runtime identity to another existing local session.
- `action=delegation_request`: create short-code delegation request.
- `action=delegation_approve`: approve request code (named profile only).
- `action=delegation_redeem`: redeem approved request code and write target session artifacts.
- `action=delegation_status`: fetch delegation request status by code.

When MCP starts unbound (no `--agent-id` and no `ENABLER_AGENT_ID`), non-bootstrap tools fail with `UNBOUND_IDENTITY` until a delegation code is redeemed.

## Credentials Output Modes

- Default: human-readable artifact locations + freshness status.
- Every refresh/summary writes shell-compatible STS env file(s):
  - `.enabler/sts.env` for the active runtime set.
  - One file per credential set when present
    (for example `.enabler/sts-agentenablement.env` and `.enabler/sts-agentawsworkshopprovisioning.env`).
- Writes Cognito token env file: `.enabler/cognito.env`.

Examples:

```bash
# Default location output
./enabler-creds summary

# Files are written on every run:
# - .enabler/sts.env
# - .enabler/sts-<credential-set>.env (if credential sets exist)
# - .enabler/cognito.env
```

## AWS credential_process (Ongoing STS Refresh)

Use `credential_process` profiles so AWS CLI/SDKs fetch fresh STS creds on demand.

```bash
# Print strict credential_process JSON for one set
./enabler-creds credential-process --set agentEnablement
```

Example `~/.aws/config` profiles:

```ini
[profile enabler-enablement]
region = us-east-2
credential_process = /bin/bash -lc 'cd /Users/jay/Projects/agent_enablement && ./enabler-creds credential-process --set agentEnablement'

[profile enabler-workshop-provisioning]
region = us-east-2
credential_process = /bin/bash -lc 'cd /Users/jay/Projects/agent_enablement && ./enabler-creds credential-process --set agentAWSWorkshopProvisioning'

[profile enabler-workshop-runtime]
region = us-east-2
credential_process = /bin/bash -lc 'cd /Users/jay/Projects/agent_enablement && ./enabler-creds credential-process --set agentAWSWorkshopRuntime'
```

Then run tools with the appropriate profile, for example:

```bash
AWS_PROFILE=enabler-enablement aws sts get-caller-identity
```

Migration guide for existing agents/scripts that still source `sts.env`:
- `docs/agent-credential-process-migration.md`

## Shortlinks Output Modes

- Exposed through `enabler-mcp` tools:
  - `help` (`tool?`, `action?`)
  - `credentials.exec` (`action=help|ensure|list_sessions|set_agentid|delegation_request|delegation_approve|delegation_redeem|delegation_status`)
  - `shortlinks.exec` (`action=help|create|resolve_url`)
  - `ops.result` (for async polling when `async=true`)

`shortlinks.exec` `action=create` returns `shortUrl` based on `references.shortlinks.redirectBaseUrl`, which is expected to be the CloudFront `/l/` base URL.

Help examples:

```json
{"method":"tools/call","params":{"name":"help","arguments":{}}}
{"method":"tools/call","params":{"name":"help","arguments":{"tool":"messages.exec"}}}
{"method":"tools/call","params":{"name":"messages.exec","arguments":{"action":"help","args":{"action":"recv"}}}}
```

## MCP Startup Troubleshooting

- If Codex reports MCP startup timeout, first verify transport framing and process launch command.
- Quick local handshake check:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | ./enabler-mcp
```

- Codex MCP config may be unbound (no args), or explicitly bound:

```toml
[mcp_servers.agent-enablement]
command = "/Users/jay/Projects/agent_enablement/enabler-mcp"
# optional:
# args = ["--agent-id", "jay"]
```

- Launcher is cwd-independent. Unbound startup requires `ENABLER_API_KEY` and `ENABLER_CREDENTIALS_ENDPOINT` for delegation bootstrap actions.

## Managed Session Model

- Runtime tools are keyed by active bound `agentId` once a session is bound.
- Credentials are persisted in managed session storage (default):
  - Linux: `~/.local/state/enabler/sessions/<agent-id>/session.json`
  - macOS: `~/Library/Application Support/enabler/sessions/<agent-id>/session.json`
- Artifacts are adjacent to session state:
  - `sts.env`, `sts-<set>.env`, `cognito.env`

## Taskboard Output Modes

- Exposed through `enabler-mcp` tools:
  - `help` (`tool?`, `action?`)
  - `credentials.exec` (`action=help|ensure|list_sessions|set_agentid|delegation_request|delegation_approve|delegation_redeem|delegation_status`)
  - `taskboard.exec` (`action=help|create|add|list|claim|unclaim|done|fail|status|audit|my_activity`)
  - `messages.exec` (`action=help|send|recv|ack`)
  - `files.exec` (`action=help|share`)
  - `ops.result` (for async polling when `async=true`)

`files.exec` `action=share` returns a CloudFront HTTPS `publicUrl` derived from `references.files.publicBaseUrl`. Uploads set S3 object metadata (`ContentType`, plus `ContentEncoding` when detectable) so CloudFront serves the correct file type. If that reference is missing, upload occurs but the command fails with a configuration error.

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
./enabler-admin agent onboard <username> <password> --profile-type named
./enabler-admin agent seed-profile --username <u> --password <p> --profile-type ephemeral
./enabler-admin agent decommission <username>
./enabler-admin agent handoff create --username <u> --password <p> --out handoff.json
./enabler-admin agent handoff print-env --file handoff.json
```

Ephemeral profiles (`profileType=ephemeral`) are hard-blocked from `agentAWSWorkshop*` credential sets.

## Skills Layout

Agent skills are now sourced directly from project root:

- `skills/get-started/SKILL.md`
- `skills/messages-basic-ops/SKILL.md`
- `skills/files-basic-ops/SKILL.md`
- `skills/shortlinks/SKILL.md`
- `skills/taskboard-basics/SKILL.md`
- `skills/ssm-key-access/SKILL.md`
- `skills/provisioning-cfn-mode/SKILL.md`

## Tests

```bash
just test
```

System tests (requires deployed stack + AWS access):

```bash
just test-system
```

## Repo Hygiene

Keep generated/local-only artifacts untracked. In particular, do not commit:
- `.DS_Store`
- `__pycache__/` and `*.pyc`
- `cdk.out/`
- local `Library/` cache content

Run the lightweight hygiene guard:

```bash
just hygiene
```
