# Taskboard Basics

## Purpose
Manage lightweight shared task lists through MCP taskboard tools.

## When To Use
Use when agents need a simple queue of actionable items with claim/done/fail workflow.

## Inputs
- Fresh credentials from `./enabler-creds summary`.
- Running `./enabler-mcp` process.

## Workflow
Use MCP tool `taskboard.exec` with `action` + `args`:
1. `action=create` (optional `args.name`).
2. `action=add` (`args.boardId`, `args.lines`).
3. `action=list` (optional `args.status`, `args.limit`, `args.nextToken`).
4. `action=claim|unclaim|done|fail`.
5. `action=status|audit|my_activity`.
6. Optional long-running mode: include `async=true` and poll `ops.result`.

## Outputs
- Board/task state mutation receipts.
- Task/activity listing payloads.

## Guardrails
- Taskboard tools require a valid Cognito ID token in credentials cache.
- Use machine-friendly MCP payloads for automation decisions.
- Refresh credentials if token freshness errors occur.

## References
- `../../README.md`
