# SSM Key Access

## Purpose
Read shared and per-agent secret values from SSM Parameter Store using issued STS credentials.

## When To Use
Use this when you need API keys or configuration values that are distributed through Parameter Store.

## Inputs
- Running `enabler-mcp` with a bound identity, or `enabler-mcp-cli` with `--agent-id`.

## Workflow
1. Discover allowed paths through MCP:

```bash
./enabler-mcp-cli --agent-id <agent-id> call ssm.exec --action paths
```

2. List parameter names in your agent scope:

```bash
./enabler-mcp-cli --agent-id <agent-id> call ssm.exec --action list --args-json '{"args":{"scope":"agent","recursive":true}}'
```

3. Read one parameter by full name:

```bash
./enabler-mcp-cli --agent-id <agent-id> call ssm.exec --action get --args-json '{"args":{"name":"/agent-enablement/prod/agent/<principal.sub>/example-key"}}'
```

4. Shared scope listing example:

```bash
./enabler-mcp-cli --agent-id <agent-id> call ssm.exec --action list --args-json '{"args":{"scope":"shared","recursive":true}}'
```

5. Optional direct AWS CLI fallback (same issued STS credentials):

```bash
aws ssm get-parameters-by-path \
  --path "/agent-enablement/prod/agent/<principal.sub>/" \
  --recursive \
  --query 'Parameters[].Name' \
  --output text
```

## Outputs
- Parameter names and plaintext SecureString values via MCP.

## Guardrails
- Treat parameter values as secrets; do not log or share them.
- `ssm.exec get` returns plaintext value in tool output.
- Issued credentials can read only shared path and your own agent path.
- If you try to read another agent’s path, expect `AccessDenied`.
- To share a key with more than one agent (but not all agents), duplicate the value into each agent’s per-agent path.

## References
- `../../README.md`
