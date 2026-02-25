import json
import sys
from pathlib import Path

from aws_cdk import App
from aws_cdk import assertions

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from stacks.agent_enablement_stack import AgentEnablementStack


def _synth_template(monkeypatch) -> dict:
    monkeypatch.setenv("STAGE", "test")
    app = App()
    stack = AgentEnablementStack(app, "IamGuardrailsTestStack")
    return assertions.Template.from_stack(
        stack, skip_cyclical_dependencies_check=True
    ).to_json()


def _find_resource(template: dict, resource_type: str, logical_id_contains: str) -> dict:
    for logical_id, resource in template["Resources"].items():
        if (
            resource.get("Type") == resource_type
            and logical_id_contains in logical_id
        ):
            return resource
    raise AssertionError(f"{resource_type} containing {logical_id_contains} not found")


def _find_resource_with_id(template: dict, resource_type: str, logical_id_contains: str) -> tuple[str, dict]:
    for logical_id, resource in template["Resources"].items():
        if (
            resource.get("Type") == resource_type
            and logical_id_contains in logical_id
        ):
            return logical_id, resource
    raise AssertionError(f"{resource_type} containing {logical_id_contains} not found")


def _statement_actions(stmt: dict) -> list[str]:
    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        return [actions]
    return actions


def _find_inline_policy_statements_for_role(template: dict, role_logical_id_contains: str) -> list[dict]:
    role = _find_resource(template, "AWS::IAM::Role", role_logical_id_contains)
    policies = (role.get("Properties") or {}).get("Policies") or []
    all_statements: list[dict] = []
    for p in policies:
        doc = (p or {}).get("PolicyDocument") or {}
        stmts = doc.get("Statement") or []
        if isinstance(stmts, list):
            all_statements.extend(stmts)
    return all_statements


def test_outputs_include_split_role_and_boundary_arns(monkeypatch):
    template = _synth_template(monkeypatch)
    outputs = template["Outputs"]

    assert "BrokerTargetRoleArn" in outputs
    assert "BrokerRuntimeRoleArn" in outputs
    assert "BrokerProvisioningRoleArn" in outputs
    assert "CredentialsLambdaExecutionRoleArn" in outputs
    assert "CfnExecutionRoleArn" in outputs
    assert "AgentWorkloadBoundaryArn" in outputs
    assert "AgentGroupMembersTableName" in outputs
    assert "TaskboardInvokeUrl" in outputs
    assert "TaskboardTasksTableName" in outputs
    assert "TaskboardAuditTableName" in outputs
    assert "FilesPublicBaseUrl" in outputs


def test_credentials_handler_uses_explicit_scope_role_env_vars(monkeypatch):
    template = _synth_template(monkeypatch)
    fn = _find_resource(template, "AWS::Lambda::Function", "CredentialsHandler")
    env_vars = fn["Properties"]["Environment"]["Variables"]

    assert "ASSUME_ROLE_RUNTIME_ARN" in env_vars
    assert "ASSUME_ROLE_PROVISIONING_ARN" in env_vars
    assert "CFN_EXECUTION_ROLE_ARN" in env_vars
    assert "AGENT_WORKLOAD_BOUNDARY_ARN" in env_vars
    assert "SSM_KEYS_STAGE" in env_vars
    assert "ENABLEMENT_INDEX_URL" in env_vars
    assert "ENABLEMENT_ARTIFACTS_ROOT_URL" in env_vars
    assert "ENABLEMENT_SKILLS_ROOT_URL" in env_vars
    assert "ENABLEMENT_VERSION" in env_vars
    assert "CREDENTIALS_REFRESH_PATH" in env_vars
    assert "CREDENTIALS_EXCHANGE_PATH" in env_vars
    assert "DELEGATE_TOKEN_PATH" in env_vars
    assert "DELEGATE_TOKEN_SIGNING_SECRET" in env_vars
    assert "USER_POOL_ID" in env_vars
    assert "ASSUME_ROLE_ARN" not in env_vars


def test_user_pool_client_refresh_token_validity_is_one_day(monkeypatch):
    template = _synth_template(monkeypatch)
    client = _find_resource(template, "AWS::Cognito::UserPoolClient", "AgentUserPoolClient")
    props = client.get("Properties") or {}
    assert props.get("RefreshTokenValidity") == 1440
    units = props.get("TokenValidityUnits") or {}
    assert units.get("RefreshToken") == "minutes"


def test_credentials_refresh_route_is_api_key_protected(monkeypatch):
    template = _synth_template(monkeypatch)
    resources = template["Resources"]
    refresh_resource_id = next(
        logical_id
        for logical_id, resource in resources.items()
        if resource.get("Type") == "AWS::ApiGateway::Resource"
        and (resource.get("Properties") or {}).get("PathPart") == "refresh"
    )
    refresh_method = next(
        resource
        for resource in resources.values()
        if resource.get("Type") == "AWS::ApiGateway::Method"
        and ((resource.get("Properties") or {}).get("HttpMethod") == "POST")
        and (((resource.get("Properties") or {}).get("ResourceId") or {}).get("Ref") == refresh_resource_id)
    )
    props = refresh_method.get("Properties") or {}
    assert props.get("AuthorizationType") == "NONE"
    assert props.get("ApiKeyRequired") is True


def test_bundle_handler_sets_cloudfront_urls_from_distributions(monkeypatch):
    template = _synth_template(monkeypatch)
    fn = _find_resource(template, "AWS::Lambda::Function", "BundleHandler")
    env_vars = fn["Properties"]["Environment"]["Variables"]

    assert "SHORTLINK_REDIRECT_BASE_URL" in env_vars
    assert "FILES_PUBLIC_BASE_URL" in env_vars
    rendered = json.dumps(env_vars["SHORTLINK_REDIRECT_BASE_URL"], sort_keys=True)
    assert "DomainName" in rendered
    assert "/l/" in rendered
    rendered_files = json.dumps(env_vars["FILES_PUBLIC_BASE_URL"], sort_keys=True)
    assert "DomainName" in rendered_files


def test_upload_distribution_uses_oac_and_bucket_policy_allows_distribution(monkeypatch):
    template = _synth_template(monkeypatch)

    oac = _find_resource(template, "AWS::CloudFront::OriginAccessControl", "AgentUploadDistributionOrigin")
    oac_cfg = (oac.get("Properties") or {}).get("OriginAccessControlConfig") or {}
    assert oac_cfg.get("OriginAccessControlOriginType") == "s3"

    dist = _find_resource(template, "AWS::CloudFront::Distribution", "AgentUploadDistribution")
    origins = (((dist.get("Properties") or {}).get("DistributionConfig") or {}).get("Origins") or [])
    assert isinstance(origins, list) and len(origins) >= 1
    first_origin = origins[0] or {}
    assert "OriginAccessControlId" in first_origin

    policy = _find_resource(template, "AWS::S3::BucketPolicy", "AgentUploadBucketPolicy")
    statements = (((policy.get("Properties") or {}).get("PolicyDocument") or {}).get("Statement") or [])
    cloudfront_stmt = next(
        (
            s
            for s in statements
            if ((s.get("Principal") or {}).get("Service") == "cloudfront.amazonaws.com")
        ),
        None,
    )
    assert isinstance(cloudfront_stmt, dict)
    assert "s3:GetObject" in _statement_actions(cloudfront_stmt)

    source_arn = (((cloudfront_stmt.get("Condition") or {}).get("StringEquals") or {}).get("AWS:SourceArn"))
    rendered = json.dumps(source_arn, sort_keys=True)
    assert "cloudfront::" in rendered
    assert "distribution/" in rendered
    assert "AgentUploadDistribution" in rendered


def test_runtime_boundary_excludes_cloudformation_and_iam(monkeypatch):
    template = _synth_template(monkeypatch)
    policy = _find_resource(template, "AWS::IAM::ManagedPolicy", "IssuedCredsBoundary")
    statements = policy["Properties"]["PolicyDocument"]["Statement"]

    all_actions: list[str] = []
    for stmt in statements:
        all_actions.extend(_statement_actions(stmt))

    assert not any(a.startswith("cloudformation:") for a in all_actions)
    assert not any(a.startswith("iam:") for a in all_actions)


def test_runtime_boundary_and_role_allow_scoped_ssm_key_reads(monkeypatch):
    template = _synth_template(monkeypatch)

    boundary = _find_resource(template, "AWS::IAM::ManagedPolicy", "IssuedCredsBoundary")
    b_statements = boundary["Properties"]["PolicyDocument"]["Statement"]
    b_ssm_stmt = next(
        (s for s in b_statements if "ssm:GetParameter" in _statement_actions(s)),
        None,
    )
    assert isinstance(b_ssm_stmt, dict)
    assert set(_statement_actions(b_ssm_stmt)) >= {
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
    }
    b_res = json.dumps(b_ssm_stmt.get("Resource"), sort_keys=True)
    assert "parameter/agent-enablement/test/shared/" in b_res
    assert "parameter/agent-enablement/test/agent/${aws:PrincipalTag/sub}/" in b_res

    r_statements = _find_inline_policy_statements_for_role(template, "AgentBrokerTargetRole")
    r_ssm_stmt = next(
        (s for s in r_statements if "ssm:GetParameter" in _statement_actions(s)),
        None,
    )
    assert isinstance(r_ssm_stmt, dict)
    assert set(_statement_actions(r_ssm_stmt)) >= {
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
    }
    r_res = json.dumps(r_ssm_stmt.get("Resource"), sort_keys=True)
    assert "parameter/agent-enablement/test/shared/" in r_res
    assert "parameter/agent-enablement/test/agent/${aws:PrincipalTag/sub}/" in r_res


def test_runtime_boundary_and_role_allow_execute_api_invoke_in_us_east_2(monkeypatch):
    template = _synth_template(monkeypatch)

    boundary = _find_resource(template, "AWS::IAM::ManagedPolicy", "IssuedCredsBoundary")
    b_statements = boundary["Properties"]["PolicyDocument"]["Statement"]
    b_stmt = next((s for s in b_statements if "execute-api:Invoke" in _statement_actions(s)), None)
    assert isinstance(b_stmt, dict)
    b_res = json.dumps(b_stmt.get("Resource"), sort_keys=True)
    assert ":execute-api:us-east-2:" in b_res
    assert ":*\"" in b_res or ":*]" in b_res or ":*" in b_res

    r_statements = _find_inline_policy_statements_for_role(template, "AgentBrokerTargetRole")
    r_stmt = next((s for s in r_statements if "execute-api:Invoke" in _statement_actions(s)), None)
    assert isinstance(r_stmt, dict)
    r_res = json.dumps(r_stmt.get("Resource"), sort_keys=True)
    assert ":execute-api:us-east-2:" in r_res
    assert ":*\"" in r_res or ":*]" in r_res or ":*" in r_res


def test_runtime_role_can_read_agent_enablement_objects_under_both_prefixes(monkeypatch):
    template = _synth_template(monkeypatch)
    statements = _find_inline_policy_statements_for_role(template, "AgentBrokerTargetRole")
    get_obj_statements = [s for s in statements if "s3:GetObject" in _statement_actions(s)]

    enablement_stmt = next(
        (s for s in get_obj_statements if "enablement/" in json.dumps(s.get("Resource"), sort_keys=True)),
        None,
    )
    assert isinstance(enablement_stmt, dict)
    resources_json = json.dumps(enablement_stmt.get("Resource"), sort_keys=True)
    assert "agent-enablement/" in resources_json
    assert "enablement/" in resources_json


def test_runtime_role_scopes_uploads_by_sub_b58_tag(monkeypatch):
    template = _synth_template(monkeypatch)
    statements = _find_inline_policy_statements_for_role(template, "AgentBrokerTargetRole")
    upload_stmt = next(
        (
            s
            for s in statements
            if "s3:PutObject" in _statement_actions(s)
            and "PrincipalTag/sub_b58" in json.dumps(s.get("Resource"), sort_keys=True)
        ),
        None,
    )
    assert isinstance(upload_stmt, dict)
    rendered = json.dumps(upload_stmt.get("Resource"), sort_keys=True)
    assert "f/${aws:PrincipalTag/sub_b58}/" in rendered
    assert "upload_prefix_uuid" not in rendered


def test_cfn_execution_boundary_requires_role_permissions_boundary(monkeypatch):
    template = _synth_template(monkeypatch)
    boundary_id, _ = _find_resource_with_id(
        template, "AWS::IAM::ManagedPolicy", "AgentManagedWorkloadBoundary"
    )
    policy = _find_resource(template, "AWS::IAM::ManagedPolicy", "AgentCfnExecutionBoundary")
    statements = policy["Properties"]["PolicyDocument"]["Statement"]

    create_role_stmt = next(
        s for s in statements if "iam:CreateRole" in _statement_actions(s)
    )
    assert create_role_stmt["Condition"]["StringEquals"]["iam:PermissionsBoundary"] == {"Ref": boundary_id}

    attach_stmt = next(
        s for s in statements if "iam:AttachRolePolicy" in _statement_actions(s)
    )
    allowed = attach_stmt["Condition"]["StringLike"]["iam:PolicyARN"]
    rendered_allowed = [str(p) for p in allowed]
    assert any("AWSLambdaBasicExecutionRole" in p for p in rendered_allowed)
    assert any("AWSLambdaVPCAccessExecutionRole" in p for p in rendered_allowed)
    assert any("AWSXRayDaemonWriteAccess" in p for p in rendered_allowed)

    deny_stmt = next(
        s
        for s in statements
        if "iam:DeleteRolePermissionsBoundary" in _statement_actions(s)
    )
    assert deny_stmt["Effect"] == "Deny"


def test_provisioning_boundary_passrole_is_cfn_only(monkeypatch):
    template = _synth_template(monkeypatch)
    policy = _find_resource(template, "AWS::IAM::ManagedPolicy", "IssuedProvisioningBoundary")
    statements = policy["Properties"]["PolicyDocument"]["Statement"]

    pass_stmt = next(s for s in statements if "iam:PassRole" in _statement_actions(s))
    assert pass_stmt["Condition"]["StringEquals"]["iam:PassedToService"] == "cloudformation.amazonaws.com"
    assert isinstance(pass_stmt["Resource"], dict)
    assert pass_stmt["Resource"]["Fn::GetAtt"][0].startswith("AgentCfnExecutionRole")
    assert pass_stmt["Resource"]["Fn::GetAtt"][1] == "Arn"


def test_messages_router_sqs_send_is_scoped_to_agent_inbox_prefix(monkeypatch):
    template = _synth_template(monkeypatch)
    fn = _find_resource(template, "AWS::Lambda::Function", "MessagesRouterHandler")
    env_vars = fn["Properties"]["Environment"]["Variables"]
    assert "GROUP_MEMBERS_TABLE_NAME" not in env_vars
    assert env_vars["PROFILE_AGENT_ID_INDEX"] == "agentId-index"
    policy = _find_resource(template, "AWS::IAM::Policy", "MessagesRouterHandlerServiceRoleDefaultPolicy")
    statements = policy["Properties"]["PolicyDocument"]["Statement"]

    send_stmt = next(s for s in statements if "sqs:SendMessage" in _statement_actions(s))
    resource = send_stmt["Resource"]
    assert isinstance(resource, dict)
    rendered = "".join(str(part) for part in resource["Fn::Join"][1])
    assert rendered.endswith(":agent-inbox-*")


def test_api_gateway_access_logging_omits_headers(monkeypatch):
    template = _synth_template(monkeypatch)
    stage = _find_resource(template, "AWS::ApiGateway::Stage", "AgentsAccessApiDeploymentStage")
    fmt = stage["Properties"]["AccessLogSetting"]["Format"]

    assert "authorization" not in fmt.lower()
    assert "$context.requestId" in fmt
    assert "$context.httpMethod" in fmt
    assert "$context.resourcePath" in fmt
    assert "$context.status" in fmt


def test_taskboard_routes_use_cognito_user_pools_authorizer(monkeypatch):
    template = _synth_template(monkeypatch)
    methods = [
        r
        for r in template["Resources"].values()
        if r.get("Type") == "AWS::ApiGateway::Method"
        and (r.get("Properties") or {}).get("AuthorizationType") == "COGNITO_USER_POOLS"
    ]

    # Cognito-authorized routes:
    # taskboard (11 routes) + links create (1 route) + delegate-token (1 route)
    assert len(methods) == 13
    for m in methods:
        props = m.get("Properties") or {}
        assert props.get("ApiKeyRequired") is not True


def test_credentials_exchange_route_is_api_key_protected(monkeypatch):
    template = _synth_template(monkeypatch)
    resources = template["Resources"]
    exchange_resource_id = next(
        logical_id
        for logical_id, resource in resources.items()
        if resource.get("Type") == "AWS::ApiGateway::Resource"
        and (resource.get("Properties") or {}).get("PathPart") == "exchange"
    )
    exchange_method = next(
        resource
        for resource in resources.values()
        if resource.get("Type") == "AWS::ApiGateway::Method"
        and ((resource.get("Properties") or {}).get("HttpMethod") == "POST")
        and (((resource.get("Properties") or {}).get("ResourceId") or {}).get("Ref") == exchange_resource_id)
    )
    props = exchange_method.get("Properties") or {}
    assert props.get("AuthorizationType") == "NONE"
    assert props.get("ApiKeyRequired") is True


def test_shortlink_resolve_route_uses_apigw_direct_dynamodb_getitem(monkeypatch):
    template = _synth_template(monkeypatch)

    methods = [
        r
        for r in template["Resources"].values()
        if r.get("Type") == "AWS::ApiGateway::Method"
    ]
    resolve_method = next(
        (
            m
            for m in methods
            if (m.get("Properties") or {}).get("HttpMethod") == "GET"
            and (m.get("Properties") or {}).get("AuthorizationType") == "NONE"
            and ((m.get("Properties") or {}).get("Integration") or {}).get("Type") == "AWS"
            and "dynamodb:action/GetItem"
            in str(((m.get("Properties") or {}).get("Integration") or {}).get("Uri") or "")
        ),
        None,
    )
    assert isinstance(resolve_method, dict)
    props = resolve_method["Properties"]
    integration = props["Integration"]

    assert props["RequestParameters"]["method.request.path.code"] is True
    assert integration["IntegrationHttpMethod"] == "POST"
    assert integration["PassthroughBehavior"] == "NEVER"
    req_templates = integration.get("RequestTemplates") or {}
    assert "application/json" in req_templates
    request_template_rendered = json.dumps(req_templates["application/json"], sort_keys=True)
    assert "$util.escapeJavaScript(" in request_template_rendered
    assert "input.params" in request_template_rendered
    assert "code" in request_template_rendered
    assert "ConsistentRead" in request_template_rendered
    assert "TableName" in request_template_rendered

    method_response_codes = {(mr or {}).get("StatusCode") for mr in (props.get("MethodResponses") or [])}
    assert {"307", "404", "500"}.issubset(method_response_codes)


def test_shortlink_resolve_apigw_role_scopes_dynamodb_getitem(monkeypatch):
    template = _synth_template(monkeypatch)

    role_id, role = _find_resource_with_id(template, "AWS::IAM::Role", "ShortlinkResolveApiGatewayRole")
    principal = (
        (role.get("Properties") or {})
        .get("AssumeRolePolicyDocument", {})
        .get("Statement", [{}])[0]
        .get("Principal", {})
        .get("Service")
    )
    assert principal == "apigateway.amazonaws.com"

    policy = next(
        (
            r
            for r in template["Resources"].values()
            if r.get("Type") == "AWS::IAM::Policy"
            and any((ref or {}).get("Ref") == role_id for ref in ((r.get("Properties") or {}).get("Roles") or []))
        ),
        None,
    )
    assert isinstance(policy, dict)
    statements = ((policy.get("Properties") or {}).get("PolicyDocument") or {}).get("Statement") or []

    stmt = next((s for s in statements if "dynamodb:GetItem" in _statement_actions(s)), None)
    assert isinstance(stmt, dict)
    resource = stmt.get("Resource")
    assert isinstance(resource, dict)
    assert resource.get("Fn::GetAtt", [""])[0].startswith("ShortLinks")
