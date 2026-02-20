# Implementation Plan - 2026-02-19

## Goals
1. Add user-removal support:
   - `enabler-admin cognito remove-user` (Cognito-only)
   - `enabler-admin agent decommission` (Cognito + profile + group-membership + inbox queue)
2. Make `./enabler credentials` print summary by default.
3. Add `./enabler credentials --sts-env-vars` to write sibling `sts.env` next to credentials cache.

## Behavior
- `credentials` default output is summary unless `--json` is passed.
- `--include-headers` output remains unchanged and has precedence.
- `--sts-env-vars` writes:
  - `AWS_ACCESS_KEY_ID`
  - `AWS_SECRET_ACCESS_KEY`
  - `AWS_SESSION_TOKEN`
  - `AWS_REGION`
- `cognito remove-user` deletes user only.
- `agent decommission`:
  - resolves Cognito sub from user
  - deletes Cognito user
  - deletes profile by sub
  - deletes group member rows from profile groups + agentId
  - deletes inbox queue from profile inboxQueueUrl
  - supports `--dry-run` action preview

## Implementation Steps
1. Add admin handlers in `enabler_cli/admin_commands.py`.
2. Wire new CLI commands in `enabler_cli/cli.py`.
3. Extend `cmd_agent_credentials` + helper for env-file emission.
4. Update help text and README examples.
5. Update/add unit tests for default summary, `--json`, `--sts-env-vars`, and new admin commands.
6. Run targeted tests + CLI smoke checks.
