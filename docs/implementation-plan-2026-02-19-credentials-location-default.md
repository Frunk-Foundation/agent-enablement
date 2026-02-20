# Implementation Plan - 2026-02-19 - Credentials Location-First Default

## Goal
Simplify `enabler` consumption by making `enabler credentials` default output a location-first manifest (human-readable), while preserving full broker payload behind `--json`.

## Behavior
- Default (`enabler credentials`): print artifact locations + short descriptions + freshness.
- `--json`: print full credentials broker payload JSON.
- `--include-headers`: unchanged, still returns debug wrapper JSON.
- `--summary`: retained as compatibility alias and treated as default behavior.

## Location Manifest Contents
- credentials.json path
- connection.json path (present/missing)
- sts.env default path + per-credential-set STS env file paths
- cognito.env path
- expiresAt and freshness state

## Steps
1. Add manifest builder/render helpers in `enabler_cli/cli.py`.
2. Update `cmd_agent_credentials` output routing and help text.
3. Update tests for new default behavior and keep `--json` contract stable.
4. Update README to document location-first default and JSON mode.
5. Run targeted tests and CLI smoke checks.
