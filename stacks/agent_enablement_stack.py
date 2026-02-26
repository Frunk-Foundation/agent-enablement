import json
import os

from aws_cdk import (
    Aws,
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_apigateway as apigw,
    aws_cognito as cognito,
    aws_dynamodb as ddb,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_s3 as s3,
    aws_sqs as sqs,
    aws_cloudwatch as cloudwatch,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_secretsmanager as secretsmanager,
    aws_ssm as ssm,
)
from constructs import Construct


class AgentEnablementStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Used for API stage name and to help avoid naming collisions within an account+region.
        stage_name = os.getenv("STAGE", "prod")
        data_retention_mode = os.getenv("DATA_RETENTION_MODE", "destroy").strip().lower()
        if data_retention_mode not in {"destroy", "retain"}:
            raise ValueError(
                "DATA_RETENTION_MODE must be 'destroy' or 'retain' (case-insensitive)"
            )
        # Dev-first default: delete stateful resources on teardown for fast iteration.
        # For production deployments, set DATA_RETENTION_MODE=retain.
        stateful_removal_policy = (
            RemovalPolicy.DESTROY
            if data_retention_mode == "destroy"
            else RemovalPolicy.RETAIN
        )
        bucket_auto_delete_objects = data_retention_mode == "destroy"
        session_duration_seconds = 3600
        schema_version = "2026-02-14"

        # Keep names collision-proof across multiple stacks in the same account+region.
        name_prefix = f"{construct_id}-{stage_name}"

        agent_workshop_provisioning_role_arn = (
            os.getenv("ASSUME_ROLE_AGENT_WORKSHOP_PROVISIONING_ARN") or ""
        ).strip()
        agent_workshop_runtime_role_arn = (
            os.getenv("ASSUME_ROLE_AGENT_WORKSHOP_RUNTIME_ARN") or ""
        ).strip()
        agent_workshop_cfn_execution_role_arn = (
            os.getenv("AGENT_WORKSHOP_CFN_EXECUTION_ROLE_ARN") or ""
        ).strip()
        agent_workshop_workload_boundary_arn = (
            os.getenv("AGENT_WORKSHOP_WORKLOAD_BOUNDARY_ARN") or ""
        ).strip()
        agent_workshop_account_id = (os.getenv("AGENT_WORKSHOP_ACCOUNT_ID") or "").strip()
        agent_workshop_region = (os.getenv("AGENT_WORKSHOP_REGION") or "").strip()

        # These env vars are also used to deploy the separate AgentAWSWorkshop target stack.
        # Don't treat account/region alone as "enabled" to avoid
        # blocking target-stack deploys that run through the same CDK app.
        any_agent_workshop_cfg = any(
            [
                agent_workshop_provisioning_role_arn,
                agent_workshop_runtime_role_arn,
                agent_workshop_cfn_execution_role_arn,
                agent_workshop_workload_boundary_arn,
            ]
        )
        if any_agent_workshop_cfg and not (
            agent_workshop_provisioning_role_arn
            and agent_workshop_runtime_role_arn
            and agent_workshop_cfn_execution_role_arn
            and agent_workshop_workload_boundary_arn
        ):
            raise ValueError(
                "To enable AgentAWSWorkshop credential sets (credentialSets.agentAWSWorkshopProvisioning/Runtime), set "
                "ASSUME_ROLE_AGENT_WORKSHOP_PROVISIONING_ARN, "
                "ASSUME_ROLE_AGENT_WORKSHOP_RUNTIME_ARN, "
                "AGENT_WORKSHOP_CFN_EXECUTION_ROLE_ARN, and "
                "AGENT_WORKSHOP_WORKLOAD_BOUNDARY_ARN."
            )

        upload_bucket = s3.Bucket(
            self,
            "AgentUploadBucket",
            removal_policy=stateful_removal_policy,
            auto_delete_objects=bucket_auto_delete_objects,
            enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            lifecycle_rules=[
                s3.LifecycleRule(
                    enabled=True,
                    expiration=Duration.days(30),
                )
            ],
            cors=[
                s3.CorsRule(
                    allowed_methods=[
                        s3.HttpMethods.GET,
                        s3.HttpMethods.HEAD,
                        s3.HttpMethods.PUT,
                        s3.HttpMethods.POST,
                    ],
                    allowed_origins=["*"],
                    allowed_headers=["*"],
                    exposed_headers=["ETag"],
                    max_age=3000,
                )
            ],
        )

        comms_files_bucket = s3.Bucket(
            self,
            "AgentCommsFilesBucket",
            removal_policy=stateful_removal_policy,
            auto_delete_objects=bucket_auto_delete_objects,
            enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            lifecycle_rules=[
                # Bundles contain credential material; expire quickly.
                s3.LifecycleRule(
                    enabled=True,
                    prefix="bundles/",
                    expiration=Duration.days(1),
                ),
                s3.LifecycleRule(
                    enabled=True,
                    expiration=Duration.days(30),
                )
            ],
        )

        agent_queue = sqs.Queue(
            self,
            "AgentQueue",
            retention_period=Duration.days(4),
            removal_policy=stateful_removal_policy,
        )

        agent_bus = events.EventBus(
            self,
            "AgentEventBus",
            event_bus_name=f"{name_prefix}-bus",
        )

        profile_table = ddb.Table(
            self,
            "AgentProfiles",
            partition_key=ddb.Attribute(name="sub", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            removal_policy=stateful_removal_policy,
        )
        profile_table.add_global_secondary_index(
            index_name="agentId-index",
            partition_key=ddb.Attribute(name="agentId", type=ddb.AttributeType.STRING),
            projection_type=ddb.ProjectionType.ALL,
        )

        group_members_table = ddb.Table(
            self,
            "AgentGroupMembers",
            partition_key=ddb.Attribute(name="groupId", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="agentId", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            removal_policy=stateful_removal_policy,
        )

        links_table = ddb.Table(
            self,
            "ShortLinks",
            partition_key=ddb.Attribute(name="code", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            removal_policy=stateful_removal_policy,
        )

        taskboard_tasks_table = ddb.Table(
            self,
            "TaskboardTasks",
            partition_key=ddb.Attribute(name="boardId", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="taskId", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            removal_policy=stateful_removal_policy,
        )

        taskboard_audit_table = ddb.Table(
            self,
            "TaskboardAudit",
            partition_key=ddb.Attribute(name="boardId", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="tsActionTask", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            removal_policy=stateful_removal_policy,
        )
        taskboard_audit_table.add_global_secondary_index(
            index_name="ActorTimeIndex",
            partition_key=ddb.Attribute(name="actorSub", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="actorTsBoardTask", type=ddb.AttributeType.STRING),
            projection_type=ddb.ProjectionType.ALL,
        )
        delegation_requests_table = ddb.Table(
            self,
            "DelegationRequests",
            partition_key=ddb.Attribute(name="requestCode", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="expiresAtEpoch",
            point_in_time_recovery=True,
            removal_policy=stateful_removal_policy,
        )

        user_pool = cognito.UserPool(
            self,
            "AgentUserPool",
            user_pool_name=f"{name_prefix}-users",
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(username=True, email=True),
            password_policy=cognito.PasswordPolicy(
                min_length=12,
                require_digits=True,
                require_lowercase=True,
                require_uppercase=True,
                require_symbols=True,
            ),
            removal_policy=stateful_removal_policy,
        )

        user_pool_client = user_pool.add_client(
            "AgentUserPoolClient",
            auth_flows=cognito.AuthFlow(user_password=True, user_srp=True),
            generate_secret=False,
            refresh_token_validity=Duration.days(1),
        )
        # Canonical prefix: agent-enablement/latest/...
        enablement_base_url = (
            f"https://{comms_files_bucket.bucket_regional_domain_name}/agent-enablement/latest"
        )
        enablement_index_url = f"{enablement_base_url}/CONTENTS.md"
        enablement_bundle_url = f"{enablement_base_url}/agent-enablement-bundle.zip"
        enablement_artifacts_root_url = f"{enablement_base_url}/artifacts/"
        enablement_skills_root_url = f"{enablement_base_url}/skills/"

        lambda_execution_role = iam.Role(
            self,
            "CredentialsLambdaExecutionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ],
        )

        # Runtime role: only direct runtime service access (S3/SQS/EventBridge).
        # Note: keep this logical id stable to avoid replacing existing deployed stacks.
        sandbox_api_invoke_arn = (
            f"arn:{Aws.PARTITION}:execute-api:us-east-2:{Aws.ACCOUNT_ID}:*"
        )
        issued_runtime_boundary = iam.ManagedPolicy(
            self,
            "IssuedCredsBoundary",
            statements=[
                iam.PolicyStatement(
                    actions=["sts:GetCallerIdentity"],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    actions=[
                        "ssm:GetParameter",
                        "ssm:GetParameters",
                        "ssm:GetParametersByPath",
                    ],
                    resources=[
                        f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:parameter/agent-enablement/{stage_name}/shared/*",
                        f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:parameter/agent-enablement/{stage_name}/agent/${{aws:PrincipalTag/sub}}/*",
                    ],
                ),
                iam.PolicyStatement(
                    actions=[
                        "s3:PutObject",
                        "s3:GetObject",
                        "s3:AbortMultipartUpload",
                        "s3:CreateMultipartUpload",
                        "s3:UploadPart",
                        "s3:CompleteMultipartUpload",
                        "s3:ListMultipartUploadParts",
                    ],
                    resources=[upload_bucket.arn_for_objects("*")],
                ),
                iam.PolicyStatement(
                    actions=["s3:ListBucketMultipartUploads", "s3:ListBucket"],
                    resources=[upload_bucket.bucket_arn],
                ),
                iam.PolicyStatement(
                    actions=[
                        "s3:PutObject",
                        "s3:GetObject",
                        "s3:AbortMultipartUpload",
                        "s3:CreateMultipartUpload",
                        "s3:UploadPart",
                        "s3:CompleteMultipartUpload",
                        "s3:ListMultipartUploadParts",
                    ],
                    resources=[comms_files_bucket.arn_for_objects("*")],
                ),
                iam.PolicyStatement(
                    actions=["s3:ListBucket"],
                    resources=[comms_files_bucket.bucket_arn],
                ),
                iam.PolicyStatement(
                    actions=["sqs:SendMessage"],
                    resources=[agent_queue.queue_arn],
                ),
                iam.PolicyStatement(
                    actions=[
                        "sqs:ReceiveMessage",
                        "sqs:DeleteMessage",
                        "sqs:ChangeMessageVisibility",
                        "sqs:GetQueueAttributes",
                    ],
                    resources=[f"arn:aws:sqs:{Aws.REGION}:{Aws.ACCOUNT_ID}:*"],
                ),
                iam.PolicyStatement(
                    actions=["events:PutEvents"],
                    resources=[agent_bus.event_bus_arn],
                ),
                iam.PolicyStatement(
                    actions=["execute-api:Invoke"],
                    resources=[sandbox_api_invoke_arn],
                ),
            ],
        )

        broker_target_role = iam.Role(
            self,
            "AgentBrokerTargetRole",
            assumed_by=iam.ArnPrincipal(lambda_execution_role.role_arn),
            permissions_boundary=issued_runtime_boundary,
            inline_policies={
                "AgentBrokerRuntime": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["sts:GetCallerIdentity"],
                            resources=["*"],
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "s3:PutObject",
                                "s3:GetObject",
                                "s3:AbortMultipartUpload",
                                "s3:CreateMultipartUpload",
                                "s3:UploadPart",
                                "s3:CompleteMultipartUpload",
                                "s3:ListMultipartUploadParts",
                            ],
                            # Scope uploads to each principal's deterministic base58 prefix.
                            resources=[
                                upload_bucket.arn_for_objects(
                                    "f/${aws:PrincipalTag/sub_b58}/*"
                                )
                            ],
                        ),
                        iam.PolicyStatement(
                            actions=["s3:ListBucketMultipartUploads"],
                            resources=[upload_bucket.bucket_arn],
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "s3:PutObject",
                                "s3:AbortMultipartUpload",
                                "s3:CreateMultipartUpload",
                                "s3:UploadPart",
                                "s3:CompleteMultipartUpload",
                                "s3:ListMultipartUploadParts",
                            ],
                            # Allow writing comms files only under the agent's own prefixes.
                            resources=[
                                comms_files_bucket.arn_for_objects(
                                    "direct/${aws:PrincipalTag/agent_id}/*"
                                ),
                                comms_files_bucket.arn_for_objects(
                                    "broadcast/${aws:PrincipalTag/agent_id}/*"
                                ),
                            ],
                        ),
                        iam.PolicyStatement(
                            actions=["s3:GetObject"],
                            resources=[
                                comms_files_bucket.arn_for_objects(
                                    "direct/*/${aws:PrincipalTag/agent_id}/*"
                                ),
                                comms_files_bucket.arn_for_objects("broadcast/*"),
                            ],
                        ),
                        # Enablement pack (skills/artifacts) is shared, read-only content.
                        iam.PolicyStatement(
                            actions=["s3:GetObject"],
                            resources=[
                                comms_files_bucket.arn_for_objects("agent-enablement/*"),
                                comms_files_bucket.arn_for_objects("enablement/*"),
                            ],
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "ssm:GetParameter",
                                "ssm:GetParameters",
                                "ssm:GetParametersByPath",
                            ],
                            resources=[
                                f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:parameter/agent-enablement/{stage_name}/shared/*",
                                f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:parameter/agent-enablement/{stage_name}/agent/${{aws:PrincipalTag/sub}}/*",
                            ],
                        ),
                        iam.PolicyStatement(
                            actions=["sqs:SendMessage"],
                            resources=[agent_queue.queue_arn],
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "sqs:ReceiveMessage",
                                "sqs:DeleteMessage",
                                "sqs:ChangeMessageVisibility",
                                "sqs:GetQueueAttributes",
                            ],
                            resources=[
                                f"arn:aws:sqs:{Aws.REGION}:{Aws.ACCOUNT_ID}:agent-inbox-*"
                            ],
                            conditions={
                                "StringEquals": {
                                    "aws:ResourceTag/agent_sub": "${aws:PrincipalTag/sub}"
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            actions=["events:PutEvents"],
                            resources=[agent_bus.event_bus_arn],
                            conditions={
                                "ForAllValues:StringEquals": {
                                    "events:source": "agents.messages.sub.${aws:PrincipalTag/sub}",
                                    "events:detail-type": "agent.message.v2",
                                },
                                "BoolIfExists": {"events:eventBusInvocation": "false"},
                            },
                        ),
                        iam.PolicyStatement(
                            actions=["execute-api:Invoke"],
                            resources=[sandbox_api_invoke_arn],
                        ),
                    ]
                )
            },
            description="Runtime role assumed by the credentials broker; scoped by required session tags (sub_b58, agent_id, sub).",
        )

        agent_managed_role_prefix = f"{name_prefix}-agent-"
        managed_role_arn_pattern = (
            f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:role/{agent_managed_role_prefix}*"
        )
        managed_policy_arn_pattern = (
            f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:policy/{agent_managed_role_prefix}*"
        )
        allowed_attach_policy_arns = [
            managed_policy_arn_pattern,
            f"arn:{Aws.PARTITION}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            f"arn:{Aws.PARTITION}:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
            f"arn:{Aws.PARTITION}:iam::aws:policy/AWSXRayDaemonWriteAccess",
        ]

        agent_workload_boundary = iam.ManagedPolicy(
            self,
            "AgentManagedWorkloadBoundary",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "xray:PutTraceSegments",
                        "xray:PutTelemetryRecords",
                    ],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    actions=[
                        "s3:*",
                        "dynamodb:*",
                        "sqs:*",
                        "events:*",
                        "states:*",
                        "execute-api:Invoke",
                        "ssm:GetParameter",
                        "ssm:GetParameters",
                        "ssm:GetParametersByPath",
                        "secretsmanager:GetSecretValue",
                        "kms:Decrypt",
                    ],
                    resources=["*"],
                ),
            ],
        )

        cfn_execution_boundary = iam.ManagedPolicy(
            self,
            "AgentCfnExecutionBoundary",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "cloudfront:*",
                        "s3:*",
                        "lambda:*",
                        "apigateway:*",
                        "states:*",
                        "logs:*",
                    ],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    actions=[
                        "iam:CreateRole",
                    ],
                    resources=[managed_role_arn_pattern],
                    conditions={
                        "StringEquals": {
                            "iam:PermissionsBoundary": agent_workload_boundary.managed_policy_arn,
                        }
                    },
                ),
                iam.PolicyStatement(
                    actions=[
                        "iam:DeleteRole",
                        "iam:GetRole",
                        "iam:UpdateRole",
                        "iam:TagRole",
                        "iam:UntagRole",
                        "iam:PutRolePolicy",
                        "iam:DeleteRolePolicy",
                        "iam:PutRolePermissionsBoundary",
                    ],
                    resources=[managed_role_arn_pattern],
                ),
                iam.PolicyStatement(
                    actions=[
                        "iam:AttachRolePolicy",
                        "iam:DetachRolePolicy",
                    ],
                    resources=[managed_role_arn_pattern],
                    conditions={"StringLike": {"iam:PolicyARN": allowed_attach_policy_arns}},
                ),
                iam.PolicyStatement(
                    actions=[
                        "iam:CreatePolicy",
                        "iam:DeletePolicy",
                        "iam:GetPolicy",
                        "iam:GetPolicyVersion",
                        "iam:CreatePolicyVersion",
                        "iam:DeletePolicyVersion",
                        "iam:SetDefaultPolicyVersion",
                    ],
                    resources=[managed_policy_arn_pattern],
                ),
                iam.PolicyStatement(
                    actions=["iam:PassRole"],
                    resources=[managed_role_arn_pattern],
                    conditions={
                        "StringEquals": {
                            "iam:PassedToService": [
                                "lambda.amazonaws.com",
                                "apigateway.amazonaws.com",
                                "states.amazonaws.com",
                                "cloudformation.amazonaws.com",
                            ]
                        }
                    },
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=["iam:DeleteRolePermissionsBoundary"],
                    resources=[managed_role_arn_pattern],
                ),
                # Never allow mutation of broker and control roles through the execution role.
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=["iam:*"],
                    resources=[
                        lambda_execution_role.role_arn,
                        broker_target_role.role_arn,
                    ],
                ),
            ],
        )

        cfn_execution_role = iam.Role(
            self,
            "AgentCfnExecutionRole",
            role_name=f"{name_prefix}-cfn-exec",
            assumed_by=iam.ServicePrincipal("cloudformation.amazonaws.com"),
            permissions_boundary=cfn_execution_boundary,
            inline_policies={
                "AgentCfnExecution": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "cloudfront:*",
                                "s3:*",
                                "lambda:*",
                                "apigateway:*",
                                "states:*",
                                "logs:*",
                            ],
                            resources=["*"],
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "iam:CreateRole",
                            ],
                            resources=[managed_role_arn_pattern],
                            conditions={
                                "StringEquals": {
                                    "iam:PermissionsBoundary": agent_workload_boundary.managed_policy_arn,
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "iam:DeleteRole",
                                "iam:GetRole",
                                "iam:UpdateRole",
                                "iam:TagRole",
                                "iam:UntagRole",
                                "iam:PutRolePolicy",
                                "iam:DeleteRolePolicy",
                                "iam:PutRolePermissionsBoundary",
                            ],
                            resources=[managed_role_arn_pattern],
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "iam:AttachRolePolicy",
                                "iam:DetachRolePolicy",
                            ],
                            resources=[managed_role_arn_pattern],
                            conditions={"StringLike": {"iam:PolicyARN": allowed_attach_policy_arns}},
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "iam:CreatePolicy",
                                "iam:DeletePolicy",
                                "iam:GetPolicy",
                                "iam:GetPolicyVersion",
                                "iam:CreatePolicyVersion",
                                "iam:DeletePolicyVersion",
                                "iam:SetDefaultPolicyVersion",
                            ],
                            resources=[managed_policy_arn_pattern],
                        ),
                        iam.PolicyStatement(
                            actions=["iam:PassRole"],
                            resources=[managed_role_arn_pattern],
                            conditions={
                                "StringEquals": {
                                    "iam:PassedToService": [
                                        "lambda.amazonaws.com",
                                        "apigateway.amazonaws.com",
                                        "states.amazonaws.com",
                                        "cloudformation.amazonaws.com",
                                    ]
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.DENY,
                            actions=["iam:DeleteRolePermissionsBoundary"],
                            resources=[managed_role_arn_pattern],
                        ),
                    ]
                )
            },
            description="Execution role for CloudFormation-managed resources created by agents.",
        )

        issued_provisioning_boundary = iam.ManagedPolicy(
            self,
            "IssuedProvisioningBoundary",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "cloudformation:CreateStack",
                        "cloudformation:UpdateStack",
                        "cloudformation:DeleteStack",
                        "cloudformation:CreateChangeSet",
                        "cloudformation:ExecuteChangeSet",
                        "cloudformation:DeleteChangeSet",
                        "cloudformation:DescribeStacks",
                        "cloudformation:DescribeStackEvents",
                        "cloudformation:DescribeStackResources",
                        "cloudformation:DescribeChangeSet",
                        "cloudformation:GetTemplate",
                        "cloudformation:GetTemplateSummary",
                        "cloudformation:ListStackResources",
                        "cloudformation:ListStacks",
                        "cloudformation:ValidateTemplate",
                    ],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    actions=["iam:PassRole"],
                    resources=[cfn_execution_role.role_arn],
                    conditions={
                        "StringEquals": {
                            "iam:PassedToService": "cloudformation.amazonaws.com",
                        }
                    },
                ),
            ],
        )

        broker_provisioning_role = iam.Role(
            self,
            "AgentBrokerProvisioningRole",
            assumed_by=iam.ArnPrincipal(lambda_execution_role.role_arn),
            permissions_boundary=issued_provisioning_boundary,
            inline_policies={
                "AgentBrokerProvisioning": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "cloudformation:Describe*",
                                "cloudformation:Get*",
                                "cloudformation:List*",
                                "cloudformation:ValidateTemplate",
                            ],
                            resources=["*"],
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "cloudformation:CreateStack",
                                "cloudformation:UpdateStack",
                                "cloudformation:CreateChangeSet",
                            ],
                            resources=["*"],
                            conditions={
                                "StringEquals": {
                                    "cloudformation:RoleArn": cfn_execution_role.role_arn,
                                    "aws:RequestTag/agent_sub": "${aws:PrincipalTag/sub}",
                                    "aws:RequestTag/agent_username": "${aws:PrincipalTag/username}",
                                },
                                "StringLike": {
                                    "cloudformation:StackName": "agent-${aws:PrincipalTag/sub}-*",
                                },
                            },
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "cloudformation:ExecuteChangeSet",
                                "cloudformation:DeleteChangeSet",
                                "cloudformation:DeleteStack",
                            ],
                            resources=["*"],
                            conditions={
                                "StringEquals": {
                                    "cloudformation:RoleArn": cfn_execution_role.role_arn,
                                    "aws:ResourceTag/agent_sub": "${aws:PrincipalTag/sub}",
                                    "aws:ResourceTag/agent_username": "${aws:PrincipalTag/username}",
                                },
                                "StringLike": {
                                    "cloudformation:StackName": "agent-${aws:PrincipalTag/sub}-*",
                                },
                            },
                        ),
                        iam.PolicyStatement(
                            actions=["iam:PassRole"],
                            resources=[cfn_execution_role.role_arn],
                            conditions={
                                "StringEquals": {
                                    "iam:PassedToService": "cloudformation.amazonaws.com",
                                }
                            },
                        ),
                    ]
                )
            },
            description="Provisioning-control role assumed by broker; only CloudFormation control-plane + pass execution role.",
        )

        # Allow the Credentials Lambda to set session tags + source identity when assuming
        # the broker-controlled target roles.
        for role in (broker_target_role, broker_provisioning_role):
            if role.assume_role_policy:
                role.assume_role_policy.add_statements(
                    iam.PolicyStatement(
                        actions=["sts:TagSession", "sts:SetSourceIdentity"],
                        principals=[iam.ArnPrincipal(lambda_execution_role.role_arn)],
                    )
                )

        assume_role_resources = [
            broker_target_role.role_arn,
            broker_provisioning_role.role_arn,
            *(
                [agent_workshop_provisioning_role_arn]
                if agent_workshop_provisioning_role_arn
                else []
            ),
            *(
                [agent_workshop_runtime_role_arn]
                if agent_workshop_runtime_role_arn
                else []
            ),
        ]

        lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=["sts:AssumeRole"],
                resources=assume_role_resources,
            )
        )
        # `sts:TagSession` and `sts:SetSourceIdentity` are evaluated separately from
        # `sts:AssumeRole` (when those request params are used) and may not support
        # resource-level permissions on the target role ARN. Grant them broadly; the
        # role is still constrained by the `sts:AssumeRole` allowlist above.
        lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=["sts:TagSession", "sts:SetSourceIdentity"],
                resources=["*"],
            )
        )

        lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "cognito-idp:AdminCreateUser",
                    "cognito-idp:AdminSetUserPassword",
                ],
                resources=[user_pool.user_pool_arn],
            )
        )

        profile_table.grant_read_write_data(lambda_execution_role)
        delegation_requests_table.grant_read_write_data(lambda_execution_role)

        # Bundle handler needs read access to the enablement pack prefix and write access
        # under bundles/. Keep these narrow; presigned URLs are scoped to bundle keys.
        lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=["s3:ListBucket"],
                resources=[comms_files_bucket.bucket_arn],
                conditions={
                    "StringLike": {
                        "s3:prefix": [
                            "agent-enablement/*",
                            "enablement/*",
                        ]
                    }
                },
            )
        )
        lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[
                    comms_files_bucket.arn_for_objects("agent-enablement/*"),
                    comms_files_bucket.arn_for_objects("enablement/*"),
                ],
            )
        )

        credentials_env = {
            "PROFILE_TABLE_NAME": profile_table.table_name,
            "DELEGATION_REQUESTS_TABLE_NAME": delegation_requests_table.table_name,
            "ASSUME_ROLE_RUNTIME_ARN": broker_target_role.role_arn,
            "ASSUME_ROLE_PROVISIONING_ARN": broker_provisioning_role.role_arn,
            "CFN_EXECUTION_ROLE_ARN": cfn_execution_role.role_arn,
            "AGENT_WORKLOAD_BOUNDARY_ARN": agent_workload_boundary.managed_policy_arn,
            **(
                {
                    "ASSUME_ROLE_AGENT_WORKSHOP_PROVISIONING_ARN": agent_workshop_provisioning_role_arn,
                    "ASSUME_ROLE_AGENT_WORKSHOP_RUNTIME_ARN": agent_workshop_runtime_role_arn,
                    "AGENT_WORKSHOP_CFN_EXECUTION_ROLE_ARN": agent_workshop_cfn_execution_role_arn,
                    "AGENT_WORKSHOP_WORKLOAD_BOUNDARY_ARN": agent_workshop_workload_boundary_arn,
                    "AGENT_WORKSHOP_ACCOUNT_ID": agent_workshop_account_id,
                    "AGENT_WORKSHOP_REGION": agent_workshop_region,
                }
                if agent_workshop_provisioning_role_arn
                else {}
            ),
            "DEFAULT_TTL_SECONDS": str(session_duration_seconds),
            "MAX_TTL_SECONDS": str(session_duration_seconds),
            "SCHEMA_VERSION": schema_version,
            "USER_POOL_CLIENT_ID": user_pool_client.user_pool_client_id,
            "USER_POOL_ID": user_pool.user_pool_id,
            "UPLOAD_BUCKET": upload_bucket.bucket_name,
            "SQS_QUEUE_ARN": agent_queue.queue_arn,
            "EVENT_BUS_ARN": agent_bus.event_bus_arn,
            "COMMS_FILES_BUCKET": comms_files_bucket.bucket_name,
            "CREDENTIALS_PATH": "/v1/credentials",
            "CREDENTIALS_REFRESH_PATH": "/v1/credentials/refresh",
            "DELEGATION_REQUEST_PATH": "/v1/delegation/requests",
            "DELEGATION_APPROVAL_PATH": "/v1/delegation/approvals",
            "DELEGATION_REDEEM_PATH": "/v1/delegation/redeem",
            "DELEGATION_STATUS_PATH": "/v1/delegation/status",
            "DELEGATION_DEFAULT_TTL_SECONDS": "600",
            "DELEGATION_MAX_TTL_SECONDS": "600",
            "BUNDLE_PATH": "/v1/bundle",
            "TASKBOARD_PATH": "/v1/taskboard",
            "SHORTLINK_CREATE_PATH": "/v1/links",
            "SHORTLINK_REDIRECT_PREFIX": "/l/",
            "ENABLEMENT_INDEX_URL": enablement_index_url,
            "ENABLEMENT_BUNDLE_URL": enablement_bundle_url,
            "ENABLEMENT_ARTIFACTS_ROOT_URL": enablement_artifacts_root_url,
            "ENABLEMENT_SKILLS_ROOT_URL": enablement_skills_root_url,
            "ENABLEMENT_VERSION": "latest",
        }

        credentials_fn = _lambda.Function(
            self,
            "CredentialsHandler",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="credentials_handler.handler",
            code=_lambda.Code.from_asset("lambda"),
            timeout=Duration.seconds(10),
            role=lambda_execution_role,
            environment=credentials_env,
        )

        bundle_fn = _lambda.Function(
            self,
            "BundleHandler",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="bundle_handler.handler",
            code=_lambda.Code.from_asset("lambda"),
            timeout=Duration.seconds(30),
            role=lambda_execution_role,
            environment=credentials_env,
        )

        shortlink_create_fn = _lambda.Function(
            self,
            "ShortlinkCreateHandler",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="shortlink_create.handler",
            code=_lambda.Code.from_asset("lambda"),
            timeout=Duration.seconds(10),
            environment={
                "PROFILE_TABLE_NAME": profile_table.table_name,
                "LINKS_TABLE_NAME": links_table.table_name,
                "SCHEMA_VERSION": schema_version,
            },
        )
        profile_table.grant_read_data(shortlink_create_fn)
        links_table.grant_read_write_data(shortlink_create_fn)

        shortlink_resolve_apigw_role = iam.Role(
            self,
            "ShortlinkResolveApiGatewayRole",
            assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"),
        )
        shortlink_resolve_apigw_role.add_to_policy(
            iam.PolicyStatement(
                actions=["dynamodb:GetItem"],
                resources=[links_table.table_arn],
            )
        )

        shortlink_resolve_integration = apigw.AwsIntegration(
            service="dynamodb",
            action="GetItem",
            integration_http_method="POST",
            options=apigw.IntegrationOptions(
                credentials_role=shortlink_resolve_apigw_role,
                passthrough_behavior=apigw.PassthroughBehavior.NEVER,
                request_templates={
                    "application/json": json.dumps(
                        {
                            "TableName": links_table.table_name,
                            "Key": {
                                "code": {
                                    "S": "$util.escapeJavaScript($input.params('code'))",
                                }
                            },
                            "ConsistentRead": True,
                        }
                    )
                },
                integration_responses=[
                    apigw.IntegrationResponse(
                        status_code="307",
                        response_templates={
                            "application/json": (
                                '#set($foundCode = "$input.path(\'$.Item.code.S\')")\n'
                                "#if($foundCode == \"\")\n"
                                "  #set($context.responseOverride.status = 404)\n"
                                '  {"errorCode":"NOT_FOUND","message":"short code not found","requestId":"$context.requestId"}\n'
                                "#else\n"
                                '  #set($disabled = "$input.path(\'$.Item.disabled.BOOL\')")\n'
                                "  #if($disabled == \"true\")\n"
                                "    #set($context.responseOverride.status = 404)\n"
                                '    {"errorCode":"NOT_FOUND","message":"short code not found","requestId":"$context.requestId"}\n'
                                "  #else\n"
                                '    #set($target = "$input.path(\'$.Item.targetUrl.S\')")\n'
                                "    #if($target == \"\")\n"
                                "      #set($context.responseOverride.status = 500)\n"
                                '      {"errorCode":"INVALID_LINK","message":"short code target missing","requestId":"$context.requestId"}\n'
                                "    #else\n"
                                "      #set($context.responseOverride.status = 307)\n"
                                "      #set($context.responseOverride.header.Location = \"$target\")\n"
                                "      {}\n"
                                "    #end\n"
                                "  #end\n"
                                "#end\n"
                            )
                        },
                        response_parameters={
                            "method.response.header.Cache-Control": "'no-store'",
                        },
                    ),
                    apigw.IntegrationResponse(
                        status_code="500",
                        selection_pattern="4\\d{2}|5\\d{2}",
                        response_templates={
                            "application/json": (
                                '{"errorCode":"INTERNAL_ERROR",'
                                '"message":"Failed to resolve short link",'
                                '"requestId":"$context.requestId"}'
                            )
                        },
                        response_parameters={
                            "method.response.header.Cache-Control": "'no-store'",
                        },
                    ),
                ],
            ),
        )

        messages_router_fn = _lambda.Function(
            self,
            "MessagesRouterHandler",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="messages_router.handler",
            code=_lambda.Code.from_asset("lambda"),
            timeout=Duration.seconds(10),
            environment={
                "PROFILE_TABLE_NAME": profile_table.table_name,
                "PROFILE_AGENT_ID_INDEX": "agentId-index",
                "SCHEMA_VERSION": schema_version,
            },
        )
        profile_table.grant_read_data(messages_router_fn)
        messages_router_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["sqs:SendMessage"],
                resources=[f"arn:aws:sqs:{Aws.REGION}:{Aws.ACCOUNT_ID}:agent-inbox-*"],
            )
        )

        taskboard_fn = _lambda.Function(
            self,
            "TaskboardHandler",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="taskboard_handler.handler",
            code=_lambda.Code.from_asset("lambda"),
            timeout=Duration.seconds(20),
            role=lambda_execution_role,
            environment={
                "TASKBOARD_TASKS_TABLE": taskboard_tasks_table.table_name,
                "TASKBOARD_AUDIT_TABLE": taskboard_audit_table.table_name,
                "TASKBOARD_SCHEMA_VERSION": schema_version,
            },
        )
        taskboard_tasks_table.grant_read_write_data(taskboard_fn)
        taskboard_audit_table.grant_read_write_data(taskboard_fn)

        events.Rule(
            self,
            "AgentsMessagesRouteRule",
            event_bus=agent_bus,
            event_pattern=events.EventPattern(
                detail_type=["agent.message.v2"],
            ),
            targets=[events_targets.LambdaFunction(messages_router_fn)],
        )

        # Create the Lambda log group explicitly so metric filters can be created during stack deploy.
        log_group = logs.LogGroup(
            self,
            "CredentialsLogGroup",
            log_group_name=f"/aws/lambda/{credentials_fn.function_name}",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=stateful_removal_policy,
        )

        access_log_group = logs.LogGroup(
            self,
            "ApiAccessLogGroup",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=stateful_removal_policy,
        )

        rest_api = apigw.RestApi(
            self,
            "AgentsAccessApi",
            rest_api_name=f"{name_prefix}-api",
            deploy_options=apigw.StageOptions(
                stage_name=stage_name,
                access_log_destination=apigw.LogGroupLogDestination(access_log_group),
                # Standard fields only; do not log headers (e.g., Authorization).
                access_log_format=apigw.AccessLogFormat.json_with_standard_fields(
                    caller=True,
                    http_method=True,
                    ip=True,
                    protocol=True,
                    request_time=True,
                    resource_path=True,
                    response_length=True,
                    status=True,
                    user=True,
                ),
            ),
            # Needed for API Gateway to push logs to CloudWatch Logs.
            cloud_watch_role=True,
        )
        shared_api_key_secret = secretsmanager.Secret(
            self,
            "SharedApiKeySecret",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                password_length=40,
                exclude_punctuation=True,
                include_space=False,
            ),
            removal_policy=stateful_removal_policy,
        )
        api_key_parameter_name = f"/agent-enablement/{construct_id}/{stage_name}/shared-api-key"
        api_key_parameter = ssm.CfnParameter(
            self,
            "SharedApiKeyParameter",
            name=api_key_parameter_name,
            description="Shared API key for internal agent access to protected API routes.",
            value=shared_api_key_secret.secret_value.unsafe_unwrap(),
            type="String",
        )
        api_key_parameter.apply_removal_policy(stateful_removal_policy)
        shared_api_key = rest_api.add_api_key(
            "AgentsSharedApiKey",
            api_key_name=f"{name_prefix}-shared-key",
            value=shared_api_key_secret.secret_value.unsafe_unwrap(),
        )
        usage_plan = rest_api.add_usage_plan(
            "AgentsSharedUsagePlan",
            name=f"{name_prefix}-shared-plan",
            throttle=apigw.ThrottleSettings(
                rate_limit=1,
                burst_limit=3,
            ),
        )
        usage_plan.add_api_key(shared_api_key)
        usage_plan.add_api_stage(stage=rest_api.deployment_stage)

        v1 = rest_api.root.add_resource("v1")
        credentials = v1.add_resource("credentials")
        credentials_refresh = credentials.add_resource("refresh")
        delegation = v1.add_resource("delegation")
        delegation_requests = delegation.add_resource("requests")
        delegation_approvals = delegation.add_resource("approvals")
        delegation_redeem = delegation.add_resource("redeem")
        delegation_status = delegation.add_resource("status")
        bundle = v1.add_resource("bundle")
        links = v1.add_resource("links")
        taskboard = v1.add_resource("taskboard")
        taskboard_boards = taskboard.add_resource("boards")
        taskboard_board = taskboard_boards.add_resource("{boardId}")
        taskboard_tasks = taskboard_board.add_resource("tasks")
        taskboard_tasks_claim = taskboard_tasks.add_resource("claim")
        taskboard_tasks_unclaim = taskboard_tasks.add_resource("unclaim")
        taskboard_tasks_done = taskboard_tasks.add_resource("done")
        taskboard_tasks_fail = taskboard_tasks.add_resource("fail")
        taskboard_status = taskboard_board.add_resource("status")
        taskboard_audit = taskboard_board.add_resource("audit")
        taskboard_my = taskboard.add_resource("my")
        taskboard_my_activity = taskboard_my.add_resource("activity")
        taskboard_my_activity_board = taskboard_my_activity.add_resource("{boardId}")
        short = rest_api.root.add_resource("l")
        short_code = short.add_resource("{code}")

        taskboard_authorizer = apigw.CognitoUserPoolsAuthorizer(
            self,
            "TaskboardCognitoAuthorizer",
            cognito_user_pools=[user_pool],
        )
        taskboard_integration = apigw.LambdaIntegration(taskboard_fn)

        # One-step agent flow: username/password via HTTP Basic Auth.
        # The Lambda authenticates against Cognito and returns a single JSON payload.
        credentials.add_method(
            "POST",
            apigw.LambdaIntegration(credentials_fn),
            authorization_type=apigw.AuthorizationType.NONE,
            api_key_required=True,
        )
        credentials_refresh.add_method(
            "POST",
            apigw.LambdaIntegration(credentials_fn),
            authorization_type=apigw.AuthorizationType.NONE,
            api_key_required=True,
        )
        delegation_requests.add_method(
            "POST",
            apigw.LambdaIntegration(credentials_fn),
            authorization_type=apigw.AuthorizationType.NONE,
            api_key_required=True,
        )
        delegation_approvals.add_method(
            "POST",
            apigw.LambdaIntegration(credentials_fn),
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=taskboard_authorizer,
        )
        delegation_redeem.add_method(
            "POST",
            apigw.LambdaIntegration(credentials_fn),
            authorization_type=apigw.AuthorizationType.NONE,
            api_key_required=True,
        )
        delegation_status.add_method(
            "POST",
            apigw.LambdaIntegration(credentials_fn),
            authorization_type=apigw.AuthorizationType.NONE,
            api_key_required=True,
        )
        bundle.add_method(
            "POST",
            apigw.LambdaIntegration(bundle_fn),
            authorization_type=apigw.AuthorizationType.NONE,
            api_key_required=True,
        )
        links.add_method(
            "POST",
            apigw.LambdaIntegration(shortlink_create_fn),
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=taskboard_authorizer,
        )
        taskboard_boards.add_method(
            "POST",
            taskboard_integration,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=taskboard_authorizer,
        )
        taskboard_tasks.add_method(
            "POST",
            taskboard_integration,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=taskboard_authorizer,
        )
        taskboard_tasks.add_method(
            "GET",
            taskboard_integration,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=taskboard_authorizer,
        )
        taskboard_tasks_claim.add_method(
            "PATCH",
            taskboard_integration,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=taskboard_authorizer,
        )
        taskboard_tasks_unclaim.add_method(
            "PATCH",
            taskboard_integration,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=taskboard_authorizer,
        )
        taskboard_tasks_done.add_method(
            "PATCH",
            taskboard_integration,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=taskboard_authorizer,
        )
        taskboard_tasks_fail.add_method(
            "PATCH",
            taskboard_integration,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=taskboard_authorizer,
        )
        taskboard_status.add_method(
            "GET",
            taskboard_integration,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=taskboard_authorizer,
        )
        taskboard_audit.add_method(
            "GET",
            taskboard_integration,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=taskboard_authorizer,
        )
        taskboard_my_activity.add_method(
            "GET",
            taskboard_integration,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=taskboard_authorizer,
        )
        taskboard_my_activity_board.add_method(
            "GET",
            taskboard_integration,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=taskboard_authorizer,
        )
        short_code.add_method(
            "GET",
            shortlink_resolve_integration,
            authorization_type=apigw.AuthorizationType.NONE,
            request_parameters={"method.request.path.code": True},
            method_responses=[
                apigw.MethodResponse(
                    status_code="307",
                    response_parameters={
                        "method.response.header.Location": True,
                        "method.response.header.Cache-Control": True,
                    },
                ),
                apigw.MethodResponse(
                    status_code="404",
                    response_parameters={
                        "method.response.header.Cache-Control": True,
                    },
                ),
                apigw.MethodResponse(
                    status_code="500",
                    response_parameters={
                        "method.response.header.Cache-Control": True,
                    },
                ),
            ],
        )

        distribution = cloudfront.Distribution(
            self,
            "AgentsAccessDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.HttpOrigin(
                    domain_name=f"{rest_api.rest_api_id}.execute-api.{Aws.REGION}.{Aws.URL_SUFFIX}",
                    origin_path=f"/{stage_name}",
                    protocol_policy=cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
            ),
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
        )
        upload_distribution = cloudfront.Distribution(
            self,
            "AgentUploadDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(upload_bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
            ),
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
        )
        credentials_fn.add_environment(
            "API_KEY_SSM_PARAMETER_NAME",
            api_key_parameter_name,
        )
        credentials_fn.add_environment(
            "SSM_KEYS_STAGE",
            stage_name,
        )
        bundle_fn.add_environment(
            "SSM_KEYS_STAGE",
            stage_name,
        )
        bundle_fn.add_environment(
            "SHORTLINK_REDIRECT_BASE_URL",
            f"https://{distribution.distribution_domain_name}/l/",
        )
        credentials_fn.add_environment(
            "SHORTLINK_REDIRECT_BASE_URL",
            f"https://{distribution.distribution_domain_name}/l/",
        )
        bundle_fn.add_environment(
            "FILES_PUBLIC_BASE_URL",
            f"https://{upload_distribution.distribution_domain_name}/",
        )
        credentials_fn.add_environment(
            "FILES_PUBLIC_BASE_URL",
            f"https://{upload_distribution.distribution_domain_name}/",
        )
        credentials_fn.add_environment(
            "API_REQUIRED_HEADERS",
            "x-api-key,authorization",
        )

        error_metric = cloudwatch.Metric(
            namespace="AgentsAccessAWS",
            metric_name="Errors",
            statistic="Sum",
            period=Duration.minutes(5),
        )

        logs.MetricFilter(
            self,
            "CredentialsErrorMetricFilter",
            log_group=log_group,
            metric_namespace="AgentsAccessAWS",
            metric_name="Errors",
            filter_pattern=logs.FilterPattern.string_value("$.outcome", "=", "error"),
            metric_value="1",
        )

        cloudwatch.Alarm(
            self,
            "CredentialsErrorsAlarm",
            metric=error_metric,
            threshold=1,
            evaluation_periods=1,
            datapoints_to_alarm=1,
        )

        CfnOutput(
            self,
            "CredentialsInvokeUrl",
            value=f"{rest_api.url}v1/credentials",
            description="Invoke URL for credentials endpoint.",
        )
        CfnOutput(
            self,
            "BundleInvokeUrl",
            value=f"{rest_api.url}v1/bundle",
            description="Invoke URL for enablement bundle endpoint.",
        )
        CfnOutput(
            self,
            "TaskboardInvokeUrl",
            value=f"{rest_api.url}v1/taskboard",
            description="Invoke URL base for taskboard endpoints.",
        )

        CfnOutput(
            self,
            "LinksCreateInvokeUrl",
            value=f"{rest_api.url}v1/links",
            description="Invoke URL for authenticated short-link creation.",
        )
        CfnOutput(
            self,
            "ApiKeyParameterName",
            value=api_key_parameter_name,
            description="SSM SecureString parameter name containing the shared API key.",
        )

        CfnOutput(
            self,
            "ShortLinksBaseUrl",
            value=f"https://{distribution.distribution_domain_name}/l/",
            description="Base URL for short-link redirects.",
        )
        CfnOutput(
            self,
            "FilesPublicBaseUrl",
            value=f"https://{upload_distribution.distribution_domain_name}/",
            description="Base URL for uploaded files served via CloudFront.",
        )

        CfnOutput(
            self,
            "AgentProfilesTableName",
            value=profile_table.table_name,
        )

        CfnOutput(
            self,
            "AgentGroupMembersTableName",
            value=group_members_table.table_name,
        )

        CfnOutput(
            self,
            "TaskboardTasksTableName",
            value=taskboard_tasks_table.table_name,
        )

        CfnOutput(
            self,
            "TaskboardAuditTableName",
            value=taskboard_audit_table.table_name,
        )

        CfnOutput(
            self,
            "UserPoolId",
            value=user_pool.user_pool_id,
        )

        CfnOutput(
            self,
            "UserPoolClientId",
            value=user_pool_client.user_pool_client_id,
        )

        CfnOutput(
            self,
            "UploadBucketName",
            value=upload_bucket.bucket_name,
        )

        CfnOutput(
            self,
            "CommsSharedBucketName",
            value=comms_files_bucket.bucket_name,
        )

        CfnOutput(
            self,
            "QueueArn",
            value=agent_queue.queue_arn,
        )

        CfnOutput(
            self,
            "EventBusArn",
            value=agent_bus.event_bus_arn,
        )

        CfnOutput(
            self,
            "BrokerTargetRoleArn",
            value=broker_target_role.role_arn,
        )

        CfnOutput(
            self,
            "BrokerRuntimeRoleArn",
            value=broker_target_role.role_arn,
        )

        CfnOutput(
            self,
            "BrokerProvisioningRoleArn",
            value=broker_provisioning_role.role_arn,
        )

        CfnOutput(
            self,
            "CredentialsLambdaExecutionRoleArn",
            value=lambda_execution_role.role_arn,
        )

        CfnOutput(
            self,
            "CfnExecutionRoleArn",
            value=cfn_execution_role.role_arn,
        )

        CfnOutput(
            self,
            "AgentWorkloadBoundaryArn",
            value=agent_workload_boundary.managed_policy_arn,
        )
