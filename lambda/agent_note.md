# Agent One-Command Access

All AWS access starts from the enablement API bundle-first flow.

What you do:
1. Call `POST /v1/bundle` using your assigned username/password + API key.
2. Download and unzip the bundle ZIP (content-only).
3. Run `POST /v1/credentials` when you need short-lived credentials.

What you get:
- `credentials`: STS credentials (`accessKeyId`, `secretAccessKey`, `sessionToken`)
- `grants`: explicit allowed actions/resources
- `constraints`: scope and runtime limits
- `references`: service references (including `messages`, `s3`, `ssmKeys`, `provisioning`)

Security rules:
- Treat `credentials.json` as secret material.
- Do not paste raw credentials or tokens into chat/issues/logs.
- Request fresh credentials when expired.

Provisioning rules:
- Use CloudFormation for provisioning scope operations.
- Pass required execution role and tags from `references.provisioning`.

Messaging rules:
- Use `./enabler messages send|recv|ack` with issued credentials.
- Keep secrets out of message payloads.
