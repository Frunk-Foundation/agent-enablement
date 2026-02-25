# Implementation Plan: Split `enabler` into `enabler-creds` and `enabler-mcp`

## Behavior First
- `./enabler` is no longer a runtime CLI. It exits non-zero with migration guidance.
- `./enabler-creds` is the credential lifecycle CLI.
- `./enabler-mcp` is the stdio MCP server for agent runtime tools.
- Runtime tools resolve endpoints from cached credentials references, not `connection.json`.

## Deliverables
1. New launcher scripts: `enabler-creds`, `enabler-mcp`.
2. New Python modules: `enabler_cli/creds_main.py`, `enabler_cli/mcp_main.py`, `enabler_cli/mcp_server.py`.
3. Credential service module extracted from existing logic.
4. Runtime service module using credentials references for taskboard/messages/files/shortlinks.
5. Cutover `enabler` script to migration error.
6. Tests for:
   - `enabler` cutover behavior
   - `enabler-creds` command surface
   - MCP `tools/list` and a representative tool call

## Sequence
1. Add shared service modules with minimal behavior changes.
2. Implement `enabler-creds` Typer app with `summary`, `status`, `paths`, `refresh`, `credential-process`.
3. Implement MCP server with tools mapped to internal service calls.
4. Update wrappers (`enabler`, add `enabler-creds`, `enabler-mcp`).
5. Add docs updates and focused tests.
6. Run targeted tests and smoke checks.
7. Commit with Conventional Commit message.
