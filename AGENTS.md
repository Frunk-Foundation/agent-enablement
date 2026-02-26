# Agent Instructions (aws-toolkit-4-agents)

## Non-Negotiables

- **Commit proactively using detailed Conventional Commits.**
  - Include a clear type/scope and a body explaining what changed and why.
  - Use a `BREAKING CHANGE:` footer when you intentionally change public interfaces (routes, output keys, env vars, etc.).
- **Cognito-authenticated CLI commands must use strict client-side preflight.**
  - Validate endpoint source/shape and token shape before any network call.
  - Agent CLI (`enabler`) resolves Cognito endpoints from explicit flags/env or credentials references only.
  - Admin CLI (`enabler-admin`) may use stack outputs for admin workflows; do not derive Cognito endpoints from unrelated outputs.

## Quick Context

- AWS defaults for this repo:
  - Profile: `frunkfound-jay-admin`
  - Region: `us-east-2`

- CLI split:
  - `enabler`: agent/client surface (`agent bundle|credentials`, `taskboard`, `comms`, `s3`)
  - `enabler-admin`: admin/control-plane surface (`stack`, `ssm`, `cognito`, admin-side `agent`, `pack`)
  - Internal module layout:
    - `enabler_cli/cli.py`: Typer wiring + compatibility re-exports
    - `enabler_cli/admin_commands.py`: admin command implementations
    - `enabler_cli/agent_commands.py`: runtime helper implementations
    - `enabler_cli/cli_shared.py`: shared constants/types/error primitives
  - Preserve compatibility exports from `enabler_cli.cli` unless a breaking change is explicitly intended.

- CDK stack name (default): `AgentEnablementStack` (override via `CDK_STACK_NAME`; legacy stack name: `AgentsAccessStack`)
- API routes:
  - Bundle-first: `POST /v1/bundle` (CloudFormation output: `BundleInvokeUrl`)
  - Credentials-only (optional): `POST /v1/credentials` (CloudFormation output: `CredentialsInvokeUrl`)
