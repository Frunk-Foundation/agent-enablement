# Plan: Thin `enabler-mcp-cli` Wrapper

## Behavior First

Add a local CLI wrapper that executes the same MCP tools exposed by `enabler-mcp`, without requiring a third-party MCP client. Keep it thin and deterministic.

Target command surface:

- `enabler-mcp-cli list`
- `enabler-mcp-cli inspect [tool] [--action <action>]`
- `enabler-mcp-cli call <tool> [--action <action>] [--args-json <json>] [--async]`
- `enabler-mcp-cli result <operation-id>`
- `enabler-mcp-cli raw --request-json <json> | --request-file <path>`

## Implementation

1. Add Typer entrypoint module that:
   - boots dotenv/runtime env exactly like existing CLIs,
   - binds optional `--agent-id`,
   - sends JSON-RPC requests to in-process `EnablerMcp`,
   - prints JSON-only output.
2. Add root launcher script `./enabler-mcp-cli` (venv-first, repo-local Python fallback).
3. Add focused automated tests for key command paths and argument handling.
4. Update `README.md` and `SKILL.md` with usage and operator guidance.
5. Run targeted tests and smoke-check commands.

## Constraints

- No new protocol; wrapper must call the existing MCP tool handlers.
- Keep output machine-consumable JSON for agent automation.
- Keep command names aligned to `mcporter`-style expectations.
