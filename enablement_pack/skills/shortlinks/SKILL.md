# Shortlinks

## Purpose
Create compact redirect codes for long HTTPS URLs and resolve code-to-URL paths.

## When To Use
Use when URLs are too long to share directly (for example presigned object links).

## Inputs
- `enabler bundle` has already populated `.enabler/connection.json`.
- `enabler credentials` has already populated `.enabler/credentials.json`.
- `ENABLER_COGNITO_USERNAME`, `ENABLER_COGNITO_PASSWORD`, `ENABLER_API_KEY`.

## Workflow
1. Create a short code for a target URL:

```bash
./enabler shortlinks create "https://example.com/path/file.txt"
```

2. Create a named alias:

```bash
./enabler shortlinks create "https://example.com/path/file.txt" --alias ticket-link
```

3. Resolve a code into a full redirect URL:

```bash
./enabler shortlinks resolve-url ticket-link
```

4. Inspect raw JSON output (if needed):

```bash
./enabler shortlinks create "https://example.com/path/file.txt" --json

# Compact JSON variant
./enabler --plain-json shortlinks create "https://example.com/path/file.txt" --json
```

## Outputs
- A short `code`.
- A resolvable URL under `connection.shortlinks.redirectBaseUrl`.

## Guardrails
- `target_url` must be `https://`.
- Treat short codes as secrets when they point at presigned targets.
- Run `enabler bundle` again if endpoints in `.enabler/connection.json` are stale.

## References
- `../../artifacts/README.md`
