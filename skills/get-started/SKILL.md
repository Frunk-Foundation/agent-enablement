# Get Started

## Purpose
Bootstrap credential artifacts and run agent operations through MCP tools.

## When To Use
Use immediately after receiving bootstrap values (username, password, API key, credentials endpoint).

## Inputs
- `enabler-creds` binary.
- `enabler-mcp` binary.
- Bootstrap values:
  - `ENABLER_COGNITO_USERNAME`
  - `ENABLER_COGNITO_PASSWORD`
  - `ENABLER_API_KEY`
  - `ENABLER_CREDENTIALS_ENDPOINT`

## Workflow
1. Install local runtime dependencies:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

2. Prime credentials/artifacts:

```bash
./enabler-creds summary
```

3. Check freshness and available sets:

```bash
./enabler-creds status
```

4. Launch MCP server (stdio):

```bash
./enabler-mcp
```

5. Continue with task-focused skills:
- `skills/enabler-mcp-cli/SKILL.md`
- `skills/files-basic-ops/SKILL.md`
- `skills/messages-basic-ops/SKILL.md`
- `skills/shortlinks/SKILL.md`
- `skills/taskboard-basics/SKILL.md`
- `skills/ssm-key-access/SKILL.md`
- `skills/provisioning-cfn-mode/SKILL.md`

## Outputs
- `.enabler/credentials.json`
- `.enabler/sts.env`
- `.enabler/sts-<set>.env`
- `.enabler/cognito.env`

## Guardrails
- Treat `.enabler/credentials.json` and `.enabler/cognito.env` as sensitive.
- Refresh is on-demand; call `./enabler-creds refresh` if you need an explicit refresh cycle.
- For AWS CLI/SDK usage, rely on `credential_process` profiles instead of sourcing env files.

## References
- `../../README.md`
