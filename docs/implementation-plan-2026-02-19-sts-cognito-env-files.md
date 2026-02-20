# Implementation Plan - 2026-02-19 - STS + Cognito Env Files

## Goal
Improve credentials discoverability/consumption by writing environment files for both STS credential sets and Cognito tokens.

## Behavior
- `enabler credentials --sts-env-vars` writes:
  - `.enabler/sts.env` for active runtime credential set
  - one file per credential set when `credentialSets` exists
- `enabler credentials --cognito-env-vars` writes:
  - `.enabler/cognito.env` with common token env names

## Details
- STS env values: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_REGION
- Cognito env values: ID_TOKEN, ACCESS_TOKEN, REFRESH_TOKEN, TOKEN_TYPE, EXPIRES_IN plus COGNITO_* aliases
- Summary output includes `stsEnvPath`, `stsEnvPaths`, and `cognitoEnvPath`

## Validation
- Update CLI data-plane tests for:
  - default STS env path and permissions
  - per-credential-set STS env files
  - cognito.env output content and permissions
