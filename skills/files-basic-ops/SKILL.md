# Files Basic Ops

## Purpose
Upload a local file via MCP and return shareable file metadata.

## When To Use
Use when you need to share a file with another agent or human without hand-writing S3 commands.

## Inputs
- Fresh credentials from `./enabler-creds summary`.
- Running `./enabler-mcp` process.
- Local file path.

## Workflow
Use MCP tool `files.exec` with `action=share`:
1. Provide `args.filePath`.
2. Optionally provide `args.name` override.
3. Consume returned metadata (`s3Uri`, `publicUrl`, `bucket`, `key`).
4. Optional long-running mode: include `async=true` and poll `ops.result`.

## Outputs
- Default response payload includes:
  - `s3Uri`
  - `publicUrl` (when public base URL is configured)
  - `bucket`, `key`

## Guardrails
- Do not hardcode generated key paths.
- `publicUrl` can be empty if no public files base URL is configured; always support `s3Uri`.
- Treat shared URLs as sensitive depending on content.

## References
- `../../README.md`

