set shell := ["bash", "-cu"]

profile := env_var_or_default("AWS_PROFILE", "frunkfound-jay-admin-sandbox")
region := env_var_or_default("AWS_REGION", "us-east-1")
stack := env_var_or_default("STACK", "AgentBootstrapStack")

# Derived from stack outputs if not provided
endpoint := env_var_or_default("BOOTSTRAP_ENDPOINT", "")
user_pool_id := env_var_or_default("USER_POOL_ID", "")
client_id := env_var_or_default("USER_POOL_CLIENT_ID", "")
profiles_table := env_var_or_default("AGENT_PROFILES_TABLE", "")

username := env_var_or_default("COGNITO_USERNAME", "agent-test")
password := env_var_or_default("COGNITO_PASSWORD", "")

# Print key stack outputs used for testing
stack-outputs:
	AWS_PROFILE={{profile}} AWS_REGION={{region}} aws cloudformation describe-stacks \
		--stack-name {{stack}} \
		--query 'Stacks[0].Outputs' --output json | jq .

# Create a Cognito user with a permanent password.
# Requires: COGNITO_PASSWORD
cognito-create-user:
	USER_POOL_ID=$(AWS_PROFILE={{profile}} AWS_REGION={{region}} aws cloudformation describe-stacks --stack-name {{stack}} --query 'Stacks[0].Outputs[?OutputKey==`UserPoolId`].OutputValue' --output text); \
	AWS_PROFILE={{profile}} AWS_REGION={{region}} aws cognito-idp admin-create-user \
		--user-pool-id $USER_POOL_ID \
		--username "{{username}}" \
		--message-action SUPPRESS >/dev/null 2>&1 || true; \
	AWS_PROFILE={{profile}} AWS_REGION={{region}} aws cognito-idp admin-set-user-password \
		--user-pool-id $USER_POOL_ID \
		--username "{{username}}" \
		--password "{{password}}" \
		--permanent

# Fetch a Cognito ID token (prints token)
# Requires: COGNITO_PASSWORD
cognito-token:
	CLIENT_ID=$(AWS_PROFILE={{profile}} AWS_REGION={{region}} aws cloudformation describe-stacks --stack-name {{stack}} --query 'Stacks[0].Outputs[?OutputKey==`UserPoolClientId`].OutputValue' --output text); \
	AWS_PROFILE={{profile}} AWS_REGION={{region}} aws cognito-idp initiate-auth \
		--client-id $CLIENT_ID \
		--auth-flow USER_PASSWORD_AUTH \
		--auth-parameters USERNAME="{{username}}",PASSWORD="{{password}}" \
		--query 'AuthenticationResult.IdToken' --output text

# Upsert an agent profile for the current user (keyed by JWT sub)
# Requires: COGNITO_PASSWORD
ddb-put-profile:
	TOKEN=$(just cognito-token); \
	SUB=$(TOKEN="$TOKEN" python3 -c 'import os,base64,json; tok=os.environ["TOKEN"]; payload=tok.split(".")[1]; payload += "=" * (-len(payload)%4); print(json.loads(base64.urlsafe_b64decode(payload.encode()).decode()).get("sub",""))'); \
	TABLE=$(AWS_PROFILE={{profile}} AWS_REGION={{region}} aws cloudformation describe-stacks --stack-name {{stack}} --query 'Stacks[0].Outputs[?OutputKey==`AgentProfilesTableName`].OutputValue' --output text); \
	ROLE_ARN=$(AWS_PROFILE={{profile}} AWS_REGION={{region}} aws cloudformation describe-stacks --stack-name {{stack}} --query 'Stacks[0].Outputs[?OutputKey==`BrokerTargetRoleArn`].OutputValue' --output text); \
	BUCKET=$(AWS_PROFILE={{profile}} AWS_REGION={{region}} aws cloudformation describe-stacks --stack-name {{stack}} --query 'Stacks[0].Outputs[?OutputKey==`UploadBucketName`].OutputValue' --output text); \
	QUEUE_ARN=$(AWS_PROFILE={{profile}} AWS_REGION={{region}} aws cloudformation describe-stacks --stack-name {{stack}} --query 'Stacks[0].Outputs[?OutputKey==`QueueArn`].OutputValue' --output text); \
	BUS_ARN=$(AWS_PROFILE={{profile}} AWS_REGION={{region}} aws cloudformation describe-stacks --stack-name {{stack}} --query 'Stacks[0].Outputs[?OutputKey==`EventBusArn`].OutputValue' --output text); \
	ITEM=$(jq -n --arg sub "$SUB" --arg role "$ROLE_ARN" --arg bucket "$BUCKET" --arg queue "$QUEUE_ARN" --arg bus "$BUS_ARN" '{sub:{S:$sub},enabled:{BOOL:true},assumeRoleArn:{S:$role},s3Bucket:{S:$bucket},s3BasePrefix:{S:"uploads/"},sqsQueueArn:{S:$queue},eventBusArn:{S:$bus},instructionText:{S:"Upload to your UUID prefix, then send an SQS message and emit an EventBridge event."}}'); \
	AWS_PROFILE={{profile}} AWS_REGION={{region}} aws dynamodb put-item \
		--table-name "$TABLE" \
		--item "$ITEM"

# Call bootstrap with JWT token and pretty-print
# Requires: COGNITO_PASSWORD and a seeded profile (just ddb-put-profile)
curl-bootstrap:
	ENDPOINT=$(AWS_PROFILE={{profile}} AWS_REGION={{region}} aws cloudformation describe-stacks --stack-name {{stack}} --query 'Stacks[0].Outputs[?OutputKey==`BootstrapInvokeUrl`].OutputValue' --output text); \
	TOKEN=$(just cognito-token); \
	curl -sS "$ENDPOINT" -H "Authorization: Bearer $TOKEN" | jq .

# Show status + headers for debugging
curl-bootstrap-verbose:
	ENDPOINT=$(AWS_PROFILE={{profile}} AWS_REGION={{region}} aws cloudformation describe-stacks --stack-name {{stack}} --query 'Stacks[0].Outputs[?OutputKey==`BootstrapInvokeUrl`].OutputValue' --output text); \
	TOKEN=$(just cognito-token); \
	curl -i -sS "$ENDPOINT" -H "Authorization: Bearer $TOKEN"
