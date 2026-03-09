# Passwordless Agent Bootstrap with 365-Day Refresh Tokens

## Summary
Move agent bootstrap to a single seeded-session model and remove username/password from normal agent operation. Set Cognito refresh token validity to `365 days`, make both bootstrap paths converge on the same broker-style session bundle, and replace the current admin username/password handoff with admin-issued seeded credentials.

There will be exactly two bootstrap paths:
- `enabler-admin` issues a seeded session bundle and can optionally place it into the target session store ahead of time.
- An agent redeems a delegation code and receives the same seeded session bundle shape.

After bootstrap, all runtime renewal remains refresh-token-only, using the cached bundle and never falling back to username/password.

## Key Changes
- Change the Cognito user pool client refresh token validity from `1 day` to `365 days`.
- Standardize one runtime bootstrap artifact: the existing broker-style credentials/session JSON bundle.
- Replace the current admin username/password handoff flow with seeded-session issuance and placement.
- Add explicit admin bootstrap issuance and placement commands.
- Add bundle import support to `enabler-creds`.
- Keep `enabler-mcp` and `enabler-mcp-cli` on the existing shared session store/runtime contract.

## Implementation Changes
- Update the user pool client in the stack to `Duration.days(365)` and update guardrail coverage.
- Replace `agent handoff` with an admin bootstrap namespace that supports:
  - emitting a seeded bundle to stdout or a file
  - placing the seeded bundle into a specified session root or explicit credentials cache path
- Reuse the existing artifact-writing helpers so admin placement, bundle import, and delegation redeem all write the same managed files.
- Add `enabler-creds session import` for broker-style credentials/session JSON from stdin or file.
- Remove obsolete username/password handoff docs and references.

## Test Plan
- Assert the synthesized Cognito app client uses a 365-day refresh token lifetime.
- Cover admin bootstrap issue/place with a broker-style credentials bundle and managed artifact placement.
- Cover `enabler-creds session import` from file and stdin.
- Verify imported or admin-placed bundles work with `status`/`summary` and do not require username/password env vars.
- Remove or replace tests that reference the old handoff JSON/export flow.

## Assumptions
- `365 days` is the single default refresh-token validity for the existing Cognito app client.
- Username/password remain admin-side bootstrap inputs only and are no longer part of the agent-facing handoff contract.
- The canonical bootstrap artifact is the existing broker-style credentials/session JSON, not a new schema.
