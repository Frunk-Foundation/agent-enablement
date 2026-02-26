# Share Basic Ops

## Purpose
Upload a local file or folder via MCP and return shareable metadata.

## When To Use
Use when you need to share one file or a recursive folder (for multi-page static sites) without hand-writing S3 commands.

## Inputs
- Fresh credentials from `./enabler-creds summary`.
- Running `./enabler-mcp` process.
- Local file path or folder path.

## Workflow
Use MCP tool `share.exec`:
1. For one file, call `action=file` with `args.filePath` and optional `args.name`.
2. For recursive folder upload, call `action=folder` with `args.folderPath` and optional `args.rootDocument`.
3. Consume returned metadata (`publicUrl` for file uploads, or `siteBaseUrl`/`rootUrl`/`files[]` manifest for folder uploads).
4. Optional long-running mode: include `async=true` and poll `ops.result`.

## Outputs
- File upload payload includes:
  - `s3Uri`
  - `publicUrl`
  - `bucket`, `key`
- Folder upload payload includes:
  - `prefix`, `siteBaseUrl`, `rootUrl`, `fileCount`
  - `files[]` entries with `relativePath`, `s3Uri`, `publicUrl`, `key`

## Guardrails
- Do not hardcode generated key paths.
- Folder upload preserves relative paths under one generated prefix (supports static-site assets/pages).
- Treat shared URLs as sensitive depending on content.

## References
- `../../README.md`
