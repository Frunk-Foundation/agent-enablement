# Agent Bootstrap API (Python CDK)

This project deploys a sandbox bootstrap API for agents:

- API Gateway REST API endpoint: `GET /v1/bootstrap`
- Access control: `Authorization: Bearer <JWT>` via Cognito user pool authorizer
- Lambda (Python 3.12) looks up per-agent profiles in DynamoDB (keyed by JWT `sub`)
- Lambda issues 15-minute STS credentials with an inline session policy restricted to:
  - S3 uploads to a server-generated UUID prefix
  - SQS SendMessage to a specific queue
  - EventBridge PutEvents to a specific bus

## Deploy

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
AWS_PROFILE=frunkfound-jay-admin-sandbox AWS_REGION=us-east-1 cdk bootstrap
AWS_PROFILE=frunkfound-jay-admin-sandbox AWS_REGION=us-east-1 cdk deploy --require-approval never
```

## Test

```bash
source .venv/bin/activate
pytest -q
```

## Invoke

Use outputs `BootstrapInvokeUrl` from CloudFormation and a Cognito access token:

```bash
curl -sS "<BootstrapInvokeUrl>" -H "Authorization: Bearer <AccessToken>" | jq
```

## Notes

- This stack intentionally does **not** use API keys/usage plans for auth.
- Permissions are spelled out in the bootstrap JSON response and enforced via STS session policies.
