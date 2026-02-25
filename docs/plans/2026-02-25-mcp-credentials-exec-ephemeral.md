# Implementation Plan: MCP credentials.exec Ephemeral Bootstrap

## Goal
Enable named agents to mint and exchange ephemeral credentials directly through MCP via a consolidated credentials tool.

## Scope
- Add `credentials.exec` tool with `bootstrap_ephemeral` and `list_sessions` actions.
- Reuse strict endpoint/token preflight and managed session artifact writes.
- Keep startup/default identity model and `context.set_agentid` unchanged.
- Keep async operation pinning semantics.

## Defaults
- bootstrap scopes default to `taskboard,messages`.
- TTL default to `600` seconds.
- `switchToEphemeral` default `false`.
