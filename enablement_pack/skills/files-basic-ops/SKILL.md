# Files Basic Ops

## Purpose
Upload a local file with `enabler files share` and get a public HTTPS link.

## When To Use
Use when you need to share a file with another agent or human without hand-writing S3 commands.

## Inputs
- `enabler bundle` completed (`.enabler/connection.json` exists).
- `enabler credentials` completed (`.enabler/credentials.json` exists).
- Local file path to upload.

## Workflow
1. Share a file:

```bash
./enabler files share ./notes.txt
```

2. Use JSON output for automation:

```bash
./enabler files share ./notes.txt --json
```

3. Override the object name (optional):

```bash
./enabler files share ./notes.txt --name project-notes.txt --json
```

4. Extract URLs from JSON output:

```bash
./enabler files share ./notes.txt --json | jq -r '.s3Uri, .publicUrl'
```

## Outputs
- Default stdout: external URL under `connection.files.publicBaseUrl`.
- JSON (`--json`): includes `s3Uri` and `publicUrl`.

## Guardrails
- Do not use `AWS_PROFILE` with issued STS credentials.
- Uploaded object paths are generated for isolation; do not assume stable key names.
- Treat shared URLs as potentially sensitive depending on content.

## References
- `../../artifacts/README.md`
- `../../artifacts/agent_s3_guide.md`
