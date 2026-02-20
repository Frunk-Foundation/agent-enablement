# Implementation Plan (2026-02-19): `enabler credential-process`

## Behavior First
- Add a dedicated agent CLI command `enabler credential-process` for AWS `credential_process` usage.
- Require explicit `--set` selection.
- Emit strict credential_process JSON only on stdout:
  - `Version`, `AccessKeyId`, `SecretAccessKey`, `SessionToken`, optional `Expiration`.
- Fail non-zero for missing set or missing credential fields.

## Scope
- Add command wiring + handler logic in `enabler_cli/cli.py`.
- Add helper(s) for set selection and JSON transformation.
- Add tests in `tests/test_enabler_cli_data_plane.py`.
- Update `README.md` with `credential_process` examples.

## Red → Green
1. Add tests for success/missing-set/validation behavior first.
2. Implement command and helpers minimally to pass tests.
3. Refactor for shared helper reuse and clarity while keeping tests green.

## Validation
- Run targeted tests:
  - `tests/test_enabler_cli_data_plane.py`
  - `tests/test_enabler_cli_utils.py`
- Smoke check:
  - `./enabler credential-process --help`
