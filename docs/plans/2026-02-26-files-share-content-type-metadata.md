# Files Share Content-Type Metadata

## Summary
Set explicit S3 object metadata on `files share` uploads so CloudFront serves correct MIME types.

## Decisions
- Use `mimetypes.guess_type(..., strict=False)`.
- Always send `ExtraArgs` on upload.
- If MIME is unknown, set `ContentType=application/octet-stream`.
- If encoding is known (e.g. gzip), also set `ContentEncoding`.

## Implementation
1. Add a helper in `enabler_cli/apps/agent_admin_cli.py` to compute S3 `ExtraArgs` from file path.
2. Use the helper in `cmd_files_share` by passing `ExtraArgs` to `s3.upload_file`.
3. Mirror the same behavior in `enabler_cli/cli.py` to keep legacy/compat path consistent.
4. Update README file-share docs to state metadata behavior.

## Tests (Red -> Green)
1. Update existing file-share tests to assert `ExtraArgs` includes expected `ContentType` for `.txt`.
2. Add test: unknown extension falls back to `application/octet-stream`.
3. Add test: guessed encoding populates `ContentEncoding`.
4. Keep existing missing-`publicBaseUrl` failure tests green with new upload signature.

## Acceptance
- `pytest -q tests/test_enabler_cli_data_plane.py -k files_share` passes.
- CLI/MCP upload path still returns the same URLs and payload shape.
