# Implementation Plan: CloudFront-only `files.share` via credentials contract (bundle-obsolete)

## Summary
Remove presigned URL fallback and make CloudFront link generation deterministic from credentials-only references.

## Behavior
- Credentials endpoint must include `references.files.publicBaseUrl`.
- If that value is missing at issuance time, credentials handler returns MISCONFIGURED (500).
- `cmd_files_share` uploads object, then:
  - returns CloudFront URL if `publicBaseUrl` exists,
  - otherwise fails with explicit error (upload-then-fail).
- No use of bundle connection metadata for this flow.

## Files
- `lambda/credentials_handler.py`
- `stacks/agent_enablement_stack.py`
- `enabler_cli/apps/agent_admin_cli.py`
- tests:
  - `tests/test_credentials_handler.py`
  - `tests/test_stack_iam_guardrails.py`
  - `tests/test_enabler_cli_data_plane.py`

## Tests
- Ensure credentials response includes `references.files.publicBaseUrl`.
- Ensure credentials handler is misconfigured when `FILES_PUBLIC_BASE_URL` missing.
- Ensure stack sets `FILES_PUBLIC_BASE_URL` on CredentialsHandler env.
- Ensure files share no longer presigns and upload-then-fail occurs when base URL missing.
