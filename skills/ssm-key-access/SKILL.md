# SSM Key Access

## Purpose
Read shared and per-agent secret values from SSM Parameter Store using issued STS credentials.

## When To Use
Use this when you need API keys or configuration values that are distributed through Parameter Store.

## Inputs
- `credentials.json` from `POST /v1/credentials`.
- `references.ssmKeys.*` from that JSON.

## Workflow
1. Export the issued STS credentials (do not use `AWS_PROFILE`):

```bash
export AWS_REGION="$(jq -r '.references.awsRegion' credentials.json)"
export AWS_ACCESS_KEY_ID="$(jq -r '.credentials.accessKeyId' credentials.json)"
export AWS_SECRET_ACCESS_KEY="$(jq -r '.credentials.secretAccessKey' credentials.json)"
export AWS_SESSION_TOKEN="$(jq -r '.credentials.sessionToken' credentials.json)"
```

2. Compute your shared + per-agent base paths:

```bash
STAGE="$(jq -r '.references.ssmKeys.stage' credentials.json)"
SUB="$(jq -r '.principal.sub' credentials.json)"
SHARED_BASE="/agent-enablement/${STAGE}/shared/"
AGENT_BASE="/agent-enablement/${STAGE}/agent/${SUB}/"
```

3. Read a shared key (SecureString):

```bash
aws ssm get-parameter \
  --name "${SHARED_BASE}example-shared-key" \
  --with-decryption \
  --query 'Parameter.Value' \
  --output text
```

4. Read your per-agent key (SecureString):

```bash
aws ssm get-parameter \
  --name "${AGENT_BASE}example-agent-key" \
  --with-decryption \
  --query 'Parameter.Value' \
  --output text
```

5. List keys under a path (names only):

```bash
aws ssm get-parameters-by-path \
  --path "${AGENT_BASE}" \
  --recursive \
  --query 'Parameters[].Name' \
  --output text
```

## Outputs
- Decrypted SecureString values returned by SSM.

## Guardrails
- Treat parameter values as secrets; do not log or share them.
- Issued credentials can read only:
  - `references.ssmKeys.sharedBasePath`
  - `references.ssmKeys.agentBasePathTemplate` with `<principal.sub>` replaced by your own `principal.sub`
- If you try to read another agent’s path, expect `AccessDenied`.
- To share a key with more than one agent (but not all agents), duplicate the value into each agent’s per-agent path.

## References
- `../../README.md`
