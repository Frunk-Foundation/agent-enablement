# Enabler MCP CLI

## Purpose
Run enabler MCP tools from shell using `./enabler-mcp-cli` (without an external MCP client).

## When To Use
Use when an agent needs direct, scriptable access to the MCP tool surface from terminal commands.

## Inputs
- `./enabler-mcp-cli` binary.
- Optional bound identity: `--agent-id <id>`.
- Valid local session cache for the active/bound agent id.

## Workflow
1. Discover available tools:

```bash
./enabler-mcp-cli --agent-id <id> list
```

2. Inspect help for a tool/action:

```bash
./enabler-mcp-cli --agent-id <id> inspect credentials.exec
./enabler-mcp-cli --agent-id <id> inspect credentials.exec --action ensure
```

3. Call a tool action:

```bash
./enabler-mcp-cli --agent-id <id> call credentials.exec --action ensure --args-json '{"set":"agentEnablement"}'
./enabler-mcp-cli --agent-id <id> call taskboard.exec --action list --args-json '{"boardId":"<board-id>","limit":20}'
```

4. Use async and poll results:

```bash
./enabler-mcp-cli --agent-id <id> call messages.exec --action recv --args-json '{"maxNumber":10,"waitTimeSeconds":20}' --async
./enabler-mcp-cli --agent-id <id> result <operation-id>
```

5. Send raw JSON-RPC when needed:

```bash
./enabler-mcp-cli --agent-id <id> raw --request-json '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## Outputs
- JSON-only responses suitable for piping to `jq` and automation scripts.
- Direct tool payloads from `help`, `credentials.*`, `taskboard.exec`, `messages.exec`, `fileshare.exec`, `shortlinks.exec`, and `ops.result`.

## Guardrails
- Keep `--args-json` as a JSON object; invalid JSON returns CLI usage errors.
- Place `--agent-id` before the subcommand (Typer global option behavior).
- `result` only works for operation ids known to the current process context.

## References
- `../../README.md`
