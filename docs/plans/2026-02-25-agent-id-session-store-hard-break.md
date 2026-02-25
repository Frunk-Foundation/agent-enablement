# Implementation Plan: Agent-ID Session Store Hard Break

## Goal
Replace cache-file-oriented runtime credential UX with agent-id-oriented managed sessions for `enabler-creds` and `enabler-mcp`.

## Scope
- Add agent-id and session-store defaults to runtime credential path resolution.
- Make `enabler-mcp` require a fixed `agent_id` for process lifetime.
- Make `enabler-creds` use `--agent-id` / `ENABLER_AGENT_ID` instead of `--creds-cache`.
- Add `enabler-creds session` commands for list/status/revoke/bootstrap.
- Keep delegation/exchange write targets bound to explicit agent identities.
- Update tests and docs for the breaking surface.

## Constraints
- Ephemeral exchange remains hard-blocked from workshop credential sets.
- No daemon/service added.
- Persist credentials on disk in managed session store.
