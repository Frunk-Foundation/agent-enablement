# Implementation Plan: MCP `ensure` force-refresh option

## Summary
Add `args.forceRefresh` to MCP `credentials.exec` `action=ensure` so agents can force a credentials refresh immediately and rewrite local artifacts.

## Behavior
- `credentials.exec` `action=ensure` accepts optional `args.forceRefresh` (default false).
- When false: existing ensure behavior unchanged.
- When true:
  - fetch fresh credentials from broker even if cache is still fresh,
  - write refreshed session cache,
  - rewrite `sts.env` / `sts-<set>.env` and `cognito.env`,
  - return manifest details in ensure response.

## Files
- `enabler_cli/mcp_server.py`
- `tests/test_enabler_mcp.py`
- `README.md`
- `SKILL.md`

## Tests
- ensure with forceRefresh performs network refresh and returns `refreshed=true`.
- ensure default path remains `refreshed=false`.
- forceRefresh response includes artifact manifest and cache path.
