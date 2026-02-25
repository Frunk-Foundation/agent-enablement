# Provisioning CFN Mode

## Purpose
Provision infrastructure only through CloudFormation when issued `provisioning` scope credentials.

## When To Use
Use when `constraints.credentialScope` is `provisioning` (including `credentialSets.agentAWSWorkshopProvisioning` and legacy `credentialSets.agentWorkshop` / `credentialSets.agentWorkshopProvisioning`, which are always provisioning).

## Inputs
- `credentials.json` from `POST /v1/credentials`.
- `references.provisioning.cfnExecutionRoleArn` (or `credentialSets.agentAWSWorkshopProvisioning.references.provisioning.cfnExecutionRoleArn`).
- `references.provisioning.requiredRoleBoundaryArn` (or `credentialSets.agentAWSWorkshopProvisioning.references.provisioning.requiredRoleBoundaryArn`).
- `references.provisioning.stackNamePattern` (or `credentialSets.agentAWSWorkshopProvisioning.references.provisioning.stackNamePattern`).
- `references.provisioning.requiredTags` (or `credentialSets.agentAWSWorkshopProvisioning.references.provisioning.requiredTags`).

## Workflow
### 0) Export STS Credentials (No AWS Profile)

When using issued STS credentials, do **not** set `AWS_PROFILE`. Export the `AWS_*` env vars instead.

Recommended: use the `POST /v1/credentials` output, then:

```bash
export SUB="$(jq -r '.principal.sub' credentials.json)"
export USERNAME="$(jq -r '.principal.username' credentials.json)"

export AWS_REGION="$(jq -r '.credentialSets.agentAWSWorkshopProvisioning.awsRegion // .credentialSets.agentWorkshop.awsRegion // .references.awsRegion' credentials.json)"
export AWS_ACCESS_KEY_ID="$(jq -r '.credentialSets.agentAWSWorkshopProvisioning.credentials.accessKeyId // .credentialSets.agentWorkshop.credentials.accessKeyId // .credentials.accessKeyId' credentials.json)"
export AWS_SECRET_ACCESS_KEY="$(jq -r '.credentialSets.agentAWSWorkshopProvisioning.credentials.secretAccessKey // .credentialSets.agentWorkshop.credentials.secretAccessKey // .credentials.secretAccessKey' credentials.json)"
export AWS_SESSION_TOKEN="$(jq -r '.credentialSets.agentAWSWorkshopProvisioning.credentials.sessionToken // .credentialSets.agentWorkshop.credentials.sessionToken // .credentials.sessionToken' credentials.json)"

export CFN_EXEC_ROLE_ARN="$(jq -r '.credentialSets.agentAWSWorkshopProvisioning.references.provisioning.cfnExecutionRoleArn // .credentialSets.agentWorkshop.references.provisioning.cfnExecutionRoleArn // .references.provisioning.cfnExecutionRoleArn' credentials.json)"
export REQUIRED_BOUNDARY_ARN="$(jq -r '.credentialSets.agentAWSWorkshopProvisioning.references.provisioning.requiredRoleBoundaryArn // .credentialSets.agentWorkshop.references.provisioning.requiredRoleBoundaryArn // .references.provisioning.requiredRoleBoundaryArn' credentials.json)"
```

### 0.5) Examples Folder

Bundle-first: example templates are included locally under `examples/` next to this `SKILL.md`.

Fallback (credentials-only mode, no bundle ZIP): if you are reading this skill from a URL (S3), fetch the examples:

```bash
SKILLS_ROOT="$(jq -r '.references.enablement.skillsRootUrl' credentials.json)"
curl -sS "${SKILLS_ROOT%/}/provisioning-cfn-mode/examples/01-minimal-sqs.yaml" -o 01-minimal-sqs.yaml
```

### 1) Example 01 (Minimal): SQS Only (No IAM Roles)

This is the fastest way to prove your provisioning credentials, required tags, and execution role are correct.

Template: `examples/01-minimal-sqs.yaml`

```bash
STACK_NAME="agent-${SUB}-minimal-$(date +%s)"

aws cloudformation deploy \
  --stack-name "$STACK_NAME" \
  --template-file examples/01-minimal-sqs.yaml \
  --role-arn "$CFN_EXEC_ROLE_ARN" \
  --tags agent_sub="$SUB" agent_username="$USERNAME"
```

### 2) Example 02 (More Involved): Lambda + IAM Role (RoleName + PermissionsBoundary)

If your template creates `AWS::IAM::Role`, you must set **both**:
- `RoleName` in an allowlisted prefix, and
- `PermissionsBoundary` at create time (must equal `requiredRoleBoundaryArn`).

Template: `examples/02-lambda-with-boundary.yaml`

Important: the required *stack name* pattern (`agent-<sub>-*`) is **not** the required *IAM role name* prefix.

Derive the IAM role name prefix from the CloudFormation execution role name:

```bash
CFN_EXEC_ROLE_NAME="${CFN_EXEC_ROLE_ARN##*/}"     # ex: agentawsworkshop-cfn-exec
ROLE_PREFIX="${CFN_EXEC_ROLE_NAME%-cfn-exec}-agent-"  # ex: agentawsworkshop-agent-
SHORT_SUB="$(echo "$SUB" | cut -c1-8)"

# Broken (does NOT match allowlist; commonly fails with iam:GetRole/iam:CreateRole denied):
# ROLE_NAME="agent-${SUB}-ps-deploy"

# Fixed (matches allowlist):
ROLE_NAME="${ROLE_PREFIX}ps-deploy-${SHORT_SUB}"

STACK_NAME="agent-${SUB}-lambda-$(date +%s)"
aws cloudformation deploy \
  --stack-name "$STACK_NAME" \
  --template-file examples/02-lambda-with-boundary.yaml \
  --role-arn "$CFN_EXEC_ROLE_ARN" \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides AgentRoleName="$ROLE_NAME" RequiredBoundaryArn="$REQUIRED_BOUNDARY_ARN" \
  --tags agent_sub="$SUB" agent_username="$USERNAME"
```

### 3) Example 03 (Real-World): Function URL + S3 Writer (Provision In CFN; Runtime Provisioning Denied)

This example is intentionally built around common misunderstandings:
- Workloads (Lambda) can write data (S3 objects) but should not be able to provision infrastructure (CreateBucket).
- Even if a workload role policy tries to allow `s3:CreateBucket`, the required permissions boundary blocks it.

Template: `examples/03-lambda-url-s3-writer.yaml`

```bash
CFN_EXEC_ROLE_NAME="${CFN_EXEC_ROLE_ARN##*/}"
ROLE_PREFIX="${CFN_EXEC_ROLE_NAME%-cfn-exec}-agent-"
SHORT_SUB="$(echo "$SUB" | cut -c1-8)"
ROLE_NAME="${ROLE_PREFIX}s3-writer-${SHORT_SUB}"

STACK_NAME="agent-${SUB}-writer-$(date +%s)"
aws cloudformation deploy \
  --stack-name "$STACK_NAME" \
  --template-file examples/03-lambda-url-s3-writer.yaml \
  --role-arn "$CFN_EXEC_ROLE_ARN" \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides AgentRoleName="$ROLE_NAME" RequiredBoundaryArn="$REQUIRED_BOUNDARY_ARN" \
  --tags agent_sub="$SUB" agent_username="$USERNAME"

FUNCTION_URL="$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --query \"Stacks[0].Outputs[?OutputKey=='FunctionUrl'].OutputValue\" \
  --output text)"

curl -sS "$FUNCTION_URL" | jq
```

Expected output includes:
- a successful `PutObject` into the stack-provisioned bucket
- a failed `CreateBucket` attempt (AccessDenied is expected)

### Post-Deploy (Direct Runtime Ops With Runtime Creds)

These `provisioning` scope credentials are intended for CloudFormation only. For direct read-only and data-plane operations in the AgentAWSWorkshop account, switch to `credentialSets.agentAWSWorkshopRuntime` (legacy: `credentialSets.agentWorkshopRuntime`):

```bash
export AWS_REGION="$(jq -r '.credentialSets.agentAWSWorkshopRuntime.awsRegion // .credentialSets.agentWorkshopRuntime.awsRegion' credentials.json)"
export AWS_ACCESS_KEY_ID="$(jq -r '.credentialSets.agentAWSWorkshopRuntime.credentials.accessKeyId // .credentialSets.agentWorkshopRuntime.credentials.accessKeyId' credentials.json)"
export AWS_SECRET_ACCESS_KEY="$(jq -r '.credentialSets.agentAWSWorkshopRuntime.credentials.secretAccessKey // .credentialSets.agentWorkshopRuntime.credentials.secretAccessKey' credentials.json)"
export AWS_SESSION_TOKEN="$(jq -r '.credentialSets.agentAWSWorkshopRuntime.credentials.sessionToken // .credentialSets.agentWorkshopRuntime.credentials.sessionToken' credentials.json)"
```

CloudFront invalidation (requires distribution tags `agent_sub` and `agent_username` to match your principal):

```bash
aws cloudfront create-invalidation --distribution-id "<dist-id>" --paths "/*"
```

DynamoDB item CRUD (requires table tags `agent_sub` and `agent_username` to match your principal; naming `agent-<sub>-*` is recommended):

```bash
aws dynamodb put-item --table-name "agent-${SUB}-table" --item '{"pk":{"S":"k1"},"v":{"S":"hello"}}'
aws dynamodb get-item --table-name "agent-${SUB}-table" --key '{"pk":{"S":"k1"}}'
```

Bedrock runtime (regional; run with a supported region like `us-east-1`):

```bash
AWS_REGION=us-east-1 aws bedrock-runtime converse --cli-input-json '{
  "modelId": "anthropic.claude-3-sonnet-20240229-v1:0",
  "messages": [
    {
      "role": "user",
      "content": [
        { "text": "hello" }
      ]
    }
  ]
}'
```

### Cleanup

```bash
aws cloudformation delete-stack --stack-name "$STACK_NAME" --role-arn "$CFN_EXEC_ROLE_ARN"
```

### IAM Role Naming (Critical)

CloudFormation will generate IAM role names automatically if you omit `RoleName`. In this sandbox/workshop
environment, that often fails because the CloudFormation execution role is only allowed to manage IAM roles
in a tight allowlist namespace.

The most common symptom is a preflight denial like:

- `... is not authorized to perform: iam:GetRole on resource: role agent-...`

Fix: use Example 02 to derive `ROLE_PREFIX` from the execution role name, then set `RoleName` to
`<derived-prefix>...` (and set `PermissionsBoundary` at create time).

### Lambda Function URLs (AuthType NONE)

If you need a public Function URL, use Example 03. It includes the required `AWS::Lambda::Permission`
resources so the URL does not return `403 Forbidden`.

## Outputs
- CloudFormation-managed resources created under enforced constraints.

## Guardrails
- Do not use direct service provisioning APIs.
- Do not omit required tags or role-arn.
- Do not omit `RoleName` for `AWS::IAM::Role` resources.
- Keep IAM role names within the allowlisted prefix derived above.
- Always set `PermissionsBoundary` on IAM roles at creation time.

## References
- `../../README.md`

