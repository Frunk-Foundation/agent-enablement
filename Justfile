set shell := ["bash", "-cu"]

# Set AWS_PROFILE in your shell for real usage; placeholder default keeps examples neutral.
profile := env_var_or_default("AWS_PROFILE", "CHANGE_ME_ADMIN_PROFILE")
region := env_var_or_default("AWS_REGION", "us-east-2")
stack := env_var_or_default("STACK", "AgentEnablementStack")

username := env_var_or_default("ENABLER_ADMIN_COGNITO_USERNAME", "agent-test")
password := env_var_or_default("ENABLER_ADMIN_COGNITO_PASSWORD", "")
credential_scope := env_var_or_default("CREDENTIAL_SCOPE", "runtime")

# Show available recipes when running `just` with no args.
default:
	@just --list

# Bootstrap local developer dependencies without global Python changes.
bootstrap-local:
	@./scripts/bootstrap-local.sh

# Check local prerequisites and dependency health.
doctor:
	@./scripts/doctor.sh

# Install local git hooks from .githooks/
install-git-hooks:
	@./scripts/install-git-hooks.sh

# Scan staged changes for secrets (used by pre-commit)
gitleaks-staged:
	@gitleaks protect --staged --redact --config .gitleaks.toml

# Scan current working tree for secrets
gitleaks:
	@gitleaks detect --source . --no-git --redact --config .gitleaks.toml

# Print key stack outputs used for testing
stack-outputs:
	AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} stack output | jq .

# Create a Cognito user with a permanent password.
# Requires: ENABLER_ADMIN_COGNITO_PASSWORD
cognito-create-user:
	@AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} cognito create-user \
		--username '{{username}}' \
		--password '{{password}}' \
		>/dev/null

# Rotate an agent's Cognito password (admin).
# Usage: just rotate-agent-password <username> <newpassword>
rotate-agent-password agent_username new_password:
	@AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} cognito rotate-password \
		'{{agent_username}}' '{{new_password}}' \
		>/dev/null

# Onboard an agent (admin control-plane): create Cognito user + seed DynamoDB profile
# Usage: just onboard-agent <username> <password>
onboard-agent agent_username agent_password:
	@AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} agent onboard \
		'{{agent_username}}' '{{agent_password}}' \
		--credential-scope {{credential_scope}} \
		>/dev/null

# Fetch a Cognito ID token (prints token)
# Requires: ENABLER_ADMIN_COGNITO_PASSWORD
cognito-token:
	@AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} cognito id-token \
		--username '{{username}}' \
		--password '{{password}}'

# Upsert only the agent profile (admin control-plane; keyed by JWT sub)
# Requires: ENABLER_ADMIN_COGNITO_PASSWORD
ddb-put-profile:
	@AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} agent seed-profile \
		--username '{{username}}' \
		--password '{{password}}' \
		--credential-scope {{credential_scope}} \
		>/dev/null

# Generate a bootstrap handoff JSON for an agent.
# Usage: just handoff-create <username> <password> [out]
handoff-create agent_username agent_password out="agent-handoff.json":
	@AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} agent handoff create \
		--username '{{agent_username}}' \
		--password '{{agent_password}}' \
		--out '{{out}}'

# Print ENABLER_COGNITO_* and ENABLER_* exports from a handoff JSON.
# Usage: just handoff-print-env [file]
handoff-print-env file="agent-handoff.json":
	@./enabler-admin agent handoff print-env --file '{{file}}'

# Fetch shared API key metadata/value JSON from SSM.
# This uses stack output ApiKeyParameterName unless API_KEY_PARAMETER_NAME is provided.
api-key:
	@AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} ssm api-key \
		--name "${API_KEY_PARAMETER_NAME:-}"

# Print JSON base paths used for key distribution in SSM.
ssm-key-base-paths:
	AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} ssm base-paths | jq .

# Put a shared key from a file (SecureString). Overwrites if it already exists.
# Usage: just ssm-put-shared-file openai-api-key ./value.txt
ssm-put-shared-file key value_file:
	@AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} ssm put-shared \
		"{{key}}" --value-file "{{value_file}}" --overwrite | jq .

# Put an agent-scoped key from a file (SecureString). Overwrites if it already exists.
# Usage: just ssm-put-agent-file <sub> openai-api-key ./value.txt
ssm-put-agent-file sub key value_file:
	@AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} ssm put-agent \
		"{{sub}}" "{{key}}" --value-file "{{value_file}}" --overwrite | jq .

# Get a shared key value (decrypted).
ssm-get-shared key:
	@AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} ssm get-shared "{{key}}"

# Get an agent-scoped key value (decrypted).
ssm-get-agent sub key:
	@AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} ssm get-agent "{{sub}}" "{{key}}"

# Call bundle endpoint (Basic Auth + API key), download ZIP, and pretty-print the minimal JSON
# Requires: ENABLER_ADMIN_COGNITO_PASSWORD and a seeded profile (just ddb-put-profile)
curl-bundle:
	@ENDPOINT="${ENABLER_BUNDLE_ENDPOINT:-$(AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} stack output BundleInvokeUrl)}"; \
	API_KEY="${ENABLER_API_KEY:-$(just api-key | jq -r '.value')}"; \
	AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler bundle \
		--username '{{username}}' \
		--password '{{password}}' \
		--endpoint "$ENDPOINT" \
		--api-key "$API_KEY" \
		--out enablement-bundle.zip \
		| jq .

# Call credentials endpoint (Basic Auth + API key) and pretty-print (credentials-only; no ZIP)
# Requires: ENABLER_ADMIN_COGNITO_PASSWORD and a seeded profile (just ddb-put-profile)
curl-credentials:
	@ENDPOINT="${ENABLER_CREDENTIALS_ENDPOINT:-$(AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} stack output CredentialsInvokeUrl)}"; \
	API_KEY="${ENABLER_API_KEY:-$(just api-key | jq -r '.value')}"; \
	AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler credentials \
		--username '{{username}}' \
		--password '{{password}}' \
		--endpoint "$ENDPOINT" \
		--api-key "$API_KEY" \
		| jq .

# Show status + headers for debugging
curl-credentials-verbose:
	@ENDPOINT=$(AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin --stack {{stack}} stack output CredentialsInvokeUrl); \
	API_KEY="$(just api-key | jq -r '.value')"; \
	curl -i -sS -u '{{username}}:{{password}}' -H "x-api-key: $API_KEY" -X POST "$ENDPOINT"

# Build the link-first enablement pack under enablement_pack/dist/<version>
# Usage: just build-enablement-pack [base_url]
build-enablement-pack base_url="https://example.invalid/agent-enablement/latest":
	./enabler-admin pack-build --base-url "{{base_url}}"

# Publish an enablement pack version to S3 and update latest pointers.
# Usage: just publish-enablement-pack <bucket> <version> [prefix]
publish-enablement-pack bucket version prefix="agent-enablement":
	AWS_PROFILE={{profile}} AWS_REGION={{region}} ./enabler-admin pack-publish \
		--bucket "{{bucket}}" \
		--version "{{version}}" \
		--prefix "{{prefix}}"

# Unit tests (CDK/jsii imports require a writable HOME; system tests are skipped by default)
test:
	@mkdir -p /tmp/codex-home
	@HOME=/tmp/codex-home .venv/bin/python -m pytest -q

# System tests (runs against a deployed stack; requires real AWS access)
test-system:
	@RUN_SYSTEM=1 AWS_PROFILE={{profile}} AWS_REGION={{region}} STACK={{stack}} .venv/bin/python -m pytest -q tests/system
