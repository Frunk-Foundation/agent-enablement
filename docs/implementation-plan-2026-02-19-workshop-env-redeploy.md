# Implementation Plan (2026-02-19): Restore workshop STS credential sets

## Behavior First
- Add local deploy env file for workshop wiring values.
- Ensure file is gitignored.
- Deploy only `AgentEnablementStack` in sandbox with workshop env vars set.
- Verify `enabler credentials` includes workshop credential sets and writes set-specific STS env files.

## Safety
- Run `cdk diff AgentEnablementStack` before deploy.
- Confirm no Cognito resource replacement/deletion is planned.

## Scope
- `.env.workshop.local` (local only, gitignored)
- `.gitignore` update
- Optional README note about loading deploy vars

## Validation
- `./enabler credentials --json | jq '.credentialSets | keys'`
- `./enabler credentials` location output includes workshop set STS env files.
