# Credential Architecture Hardening

## Summary
- Re-key local credential sessions by stable principal identity instead of mutable `agentId`.
- Make delegation redeem idempotent and safe across partial failures.
- Remove automatic basic-auth fallback from runtime credential renewal.

## Key Changes
- Store session artifacts under a principal-scoped directory keyed by `principal.sub`, with `agentId` retained as display metadata and lookup alias.
- Add explicit session metadata to broker responses so local tooling can show principal identity, issuance mode, and renewal mode.
- Change delegation state handling from one-shot redeem to a resumable lifecycle that only finalizes after Cognito auth and profile upsert succeed.
- Treat username/password as bootstrap-only; runtime refresh uses refresh token or fails with explicit rebootstrap guidance.

## Test Plan
- Session cache paths are isolated by principal even when `agentId` changes or collides.
- MCP session listing and `set_agentid` continue to work with principal-scoped storage.
- Runtime auto-refresh does not fall back to basic auth when refresh renewal fails.
- Delegation redeem can be retried after partial Cognito/profile failures without burning the request code.

## Assumptions
- No migration/backfill or compatibility shim for the old `sessions/<agentId>/session.json` layout.
- Existing public tool names remain stable.
