# Agent Migration: STS Env Files -> AWS credential_process

## Audience
Agents and workflows currently using the old method:
- run `./enabler-creds summary`
- `source .enabler/sts.env` (or set-specific `sts-*.env`)
- run AWS CLI/SDK commands with exported `AWS_*` session variables

This guide moves AWS auth to `credential_process` so STS credentials refresh automatically.

## Why migrate
Old method problems:
- Credentials expire and break long-running workflows.
- Multiple credential sets (enablement vs workshop) are easy to mix up.
- Shell/session state leaks across commands and tools.

New method benefits:
- AWS CLI/SDK fetches creds on demand.
- Set-specific profile selection is explicit.
- No manual `source` refresh loop required for AWS calls.

## New command
Use:

```bash
./enabler-creds credential-process --set <credential-set>
```

Supported set names:
- `agentEnablement`
- `agentAWSWorkshopProvisioning`
- `agentAWSWorkshopRuntime`

The command prints strict AWS `credential_process` JSON only.

## One-time setup (`~/.aws/config`)
Add profiles:

```ini
[profile enabler-enablement]
region = us-east-2
credential_process = /bin/bash -lc 'cd /Users/jay/Projects/agent_enablement && ./enabler-creds credential-process --set agentEnablement'

[profile enabler-workshop-provisioning]
region = us-east-2
credential_process = /bin/bash -lc 'cd /Users/jay/Projects/agent_enablement && ./enabler-creds credential-process --set agentAWSWorkshopProvisioning'

[profile enabler-workshop-runtime]
region = us-east-2
credential_process = /bin/bash -lc 'cd /Users/jay/Projects/agent_enablement && ./enabler-creds credential-process --set agentAWSWorkshopRuntime'
```

## Cutover steps
1. Stop sourcing STS env files:

```bash
# old (remove from scripts)
source .enabler/sts.env
source .enabler/sts-agentenablement.env
source .enabler/sts-agentawsworkshopprovisioning.env
```

2. Clear exported STS vars in your current shell:

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_REGION AWS_DEFAULT_REGION
```

3. Use profiles per task:

```bash
AWS_PROFILE=enabler-enablement aws sts get-caller-identity
AWS_PROFILE=enabler-workshop-provisioning aws cloudformation list-stacks
AWS_PROFILE=enabler-workshop-runtime aws s3 ls
```

4. In SDK-based tools, set profile instead of raw keys:
- Python/boto3: `AWS_PROFILE=enabler-enablement`
- Node SDK v3: `AWS_PROFILE=enabler-enablement`
- Go SDK v2: `AWS_PROFILE=enabler-enablement`

## Behavior expectations
- `credential_process` is run by AWS clients as needed.
- No background daemon is required for AWS STS freshness.
- If a set is missing (for example workshop not configured), command fails hard.

## Troubleshooting
### `missing credential set: agentAWSWorkshopProvisioning`
Your broker response does not include that set in current deployment. Use `agentEnablement` or fix workshop stack/env wiring.

### AWS still uses old credentials
You likely still have exported `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` in shell. `unset` them and retry.

### Verify output shape

```bash
./enabler-creds credential-process --set agentEnablement | jq -c 'keys'
# expected keys: AccessKeyId, SecretAccessKey, SessionToken, Version (+ Expiration when present)
```

## Cognito note
This migration covers AWS STS only.
Cognito tokens are still written to `.enabler/cognito.env` by `./enabler-creds summary` when needed by non-AWS tooling.
