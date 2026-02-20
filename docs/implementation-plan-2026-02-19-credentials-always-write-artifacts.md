# Implementation Plan - 2026-02-19 - Always Write Credential Artifacts

## Goal
Ensure `enabler credentials` always emits all credential artifacts by default and clearly distinguishes STS sets (enablement vs workshop) in output.

## Behavior
- Every `enabler credentials` run writes:
  - credentials cache JSON
  - sts.env (active/default runtime set)
  - per-credential-set STS env files when credentialSets are present
  - cognito.env
- Default output always lists these artifact paths and freshness.
- Remove explicit `--sts-env-vars` and `--cognito-env-vars` options.

## Why files were missing previously
- Artifact writers were gated behind optional flags, so runs without flags produced partial artifacts.

## Steps
1. Make STS and Cognito env file writes unconditional in `cmd_agent_credentials`.
2. Remove STS/Cognito env output flags from CLI signature/help.
3. Keep output manifest focused on set-specific paths (exclude duplicated `default` in set list).
4. Update README and data-plane tests for always-on artifact generation.
5. Run targeted tests.
