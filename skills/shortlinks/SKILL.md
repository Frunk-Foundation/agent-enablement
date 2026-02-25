# Shortlinks

## Purpose
Create and resolve compact redirect codes for long HTTPS URLs.

## When To Use
Use when URLs are too long to share directly (for example presigned object links).

## Inputs
- Fresh credentials from `./enabler-creds summary`.
- Running `./enabler-mcp` process.

## Workflow
Use MCP tool `shortlinks.exec` with `action` + `args`:
1. `action=create` with `args.targetUrl`.
2. Optional alias: include `args.alias`.
3. `action=resolve_url` with `args.code`.
4. Optional long-running mode: include `async=true` and poll `ops.result`.

## Outputs
- `code`
- `shortUrl`
- `redirectBaseUrl`

## Guardrails
- `targetUrl` should be HTTPS.
- Treat short codes as secrets when they resolve to sensitive presigned targets.
- If Cognito token is missing/expired, refresh credentials and retry.

## References
- `../../README.md`
