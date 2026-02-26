# Implementation Plan: Delegation Request-Approve-Redeem (Hard Break)

## Summary
Replace delegate JWT handoff with a short-code, server-tracked delegation lifecycle:

1. `request` creates a pending delegation request with a 22-character base58 code.
2. `approve` is performed by any named agent.
3. `redeem` is one-time and returns ephemeral credentials/session artifacts.

This removes long JWT copy/paste and keeps one-time, auditable delegation.

## Behavior Contract
- Request creation succeeds without Cognito auth but with API key protection.
- Request returns short `requestCode` and `requestId` (22-char base58), status `pending`, and expiry.
- Any named agent can approve a pending request before expiry.
- Redeem succeeds only for `approved` and unexpired requests and consumes the request atomically.
- Redeem is one-time; replay fails.
- Ephemeral credentials from redeem remain hard-blocked from workshop credential sets.
- Legacy delegate JWT endpoints and commands are removed.

## Public Interface Changes
- API: add
  - `POST /v1/delegation/requests`
  - `POST /v1/delegation/approvals`
  - `POST /v1/delegation/redeem`
- API: remove
  - `POST /v1/delegate-token`
  - `POST /v1/credentials/exchange`
- MCP `credentials.exec`:
  - add actions `delegation_request|delegation_approve|delegation_redeem|delegation_status`
  - remove `bootstrap_ephemeral`
- CLI `enabler-creds`:
  - add `delegation request|approve|redeem|status`
  - remove `delegate-token create`, `exchange`, `bootstrap-ephemeral`, `session bootstrap-ephemeral`

## Data Model
- Add DynamoDB table `DelegationRequests` with PK `requestCode` and TTL attr `expiresAtEpoch`.
- Request records include status, timestamps, scopes, TTL, purpose, approver metadata, and ephemeral identity fields.

## Validation / Tests
- Lambda handler tests for request/approve/redeem success and failure modes.
- Stack guardrail tests for route auth/api-key settings and env wiring.
- MCP tests for new credentials actions and removed action.
- CLI tests for new delegation commands and removed legacy commands.
- Smoke flow with two sessions: request -> approve -> redeem -> runtime operation.
