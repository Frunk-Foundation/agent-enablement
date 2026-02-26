# Implementation Plan: Unbound-by-Default MCP Bootstrap

## Summary
Allow `enabler-mcp` to start without `--agent-id` and bootstrap identity via delegation request/approve/redeem.

## Behavior
- MCP startup succeeds with no agent id.
- Tools list remains visible.
- Identity-dependent actions fail with `UNBOUND_IDENTITY` until identity is bound.
- `credentials.exec` delegation request/status/redeem are allowed while unbound.
- `delegation_redeem` binds MCP to server-issued `ephemeralAgentId` and writes session artifacts.

## Changes
- `enabler_cli/mcp_server.py`
  - Remove startup hard requirement for agent id.
  - Add unbound gating helper and unbound status payload.
  - Allow unbound delegation bootstrap actions.
  - Resolve credentials endpoint from env when unbound.
  - Bind default identity on redeem from response principal/ephemeral id.
- `lambda/credentials_handler.py`
  - Ensure delegation redeem response includes `ephemeralAgentId` and `ephemeralUsername`.
- Docs update in README/SKILL.

## Testing
- Add/adjust MCP tests for unbound startup, tool visibility, blocked identity-required actions, delegation request/status/redeem in unbound mode, and post-redeem binding.
- Add/adjust handler test for redeem response shape.
- Run regression suite used by project handoffs.
