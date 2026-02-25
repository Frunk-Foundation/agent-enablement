# Implementation Plan: Consolidated Async MCP 7-Tool Surface

## Behavior First
- Replace granular MCP runtime tools with consolidated executors.
- Keep both credential tools: `credentials.status`, `credentials.ensure`.
- Add async mode for domain executors and polling via `ops.result`.

## Final Tool Set
1. credentials.status
2. credentials.ensure
3. taskboard.exec
4. messages.exec
5. shortlinks.exec
6. files.exec
7. ops.result

## Deliverables
1. Refactor `enabler_cli/mcp_server.py` tool registry and dispatch.
2. Add in-process operation queue/store for async execution.
3. Add action-level auth requirements (set/token) by domain action.
4. Update MCP tests for new tool names, dispatch, and async lifecycle.
5. Update docs (`README.md`) to list consolidated MCP tools.

## Sequence
1. Implement operation model and queue worker in MCP server.
2. Implement consolidated `*.exec` dispatchers and auth preflight mapping.
3. Add `ops.result` tool.
4. Replace legacy tool registrations.
5. Update tests and docs.
6. Run focused test suite and smoke MCP flow.
