import os

from aws_cdk import (
    Aws,
    CfnOutput,
    Duration,
    Stack,
    aws_iam as iam,
)
from constructs import Construct


class AgentAWSWorkshopStack(Stack):
    """
    Deploy into the agent-workshop account (e.g. 000000000000).

    Creates:
    - A CloudFormation execution role for agent stacks
    - A permissions boundary required for agent-created roles
    - A broker-assumable provisioning role (trusted to the sandbox broker Lambda execution role)
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        name_prefix = (os.getenv("AGENT_WORKSHOP_NAME_PREFIX") or "agentawsworkshop").strip()
        if not name_prefix:
            name_prefix = "agentawsworkshop"

        broker_lambda_exec_role_arn = (
            os.getenv("BROKER_LAMBDA_EXEC_ROLE_ARN") or ""
        ).strip()
        if not broker_lambda_exec_role_arn:
            raise ValueError(
                "BROKER_LAMBDA_EXEC_ROLE_ARN must be set to the sandbox broker Lambda execution role ARN."
            )

        session_duration_seconds = int(
            (os.getenv("AGENT_WORKSHOP_SESSION_DURATION_SECONDS") or "3600").strip()
        )
        # Keep within STS max (1h) unless explicitly updated.
        session_duration_seconds = max(60, min(session_duration_seconds, 3600))

        agent_managed_role_prefix = f"{name_prefix}-agent-"
        managed_role_arn_pattern = (
            f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:role/{agent_managed_role_prefix}*"
        )
        managed_policy_arn_pattern = (
            f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:policy/{agent_managed_role_prefix}*"
        )
        managed_instance_profile_arn_pattern = (
            f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:instance-profile/{agent_managed_role_prefix}*"
        )

        # Boundary for all agent-created roles. This is intentionally a runtime/data-plane
        # allowlist so provisioned workloads (Lambda/ECS tasks/etc) cannot create or mutate
        # infrastructure directly, even if they attempt to do so via their own role policy.
        agent_workload_boundary = iam.ManagedPolicy(
            self,
            "AgentWorkloadBoundary",
            managed_policy_name=f"{name_prefix}-agent-workload-boundary",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "cloudwatch:PutMetricData",
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
                        # S3 data-plane (no bucket provisioning / config mutation).
                        "s3:GetBucketLocation",
                        "s3:ListBucket",
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject",
                        "s3:AbortMultipartUpload",
                        "s3:CreateMultipartUpload",
                        "s3:UploadPart",
                        "s3:CompleteMultipartUpload",
                        "s3:ListMultipartUploadParts",
                        "s3:ListBucketMultipartUploads",
                        # DynamoDB data-plane only.
                        "dynamodb:BatchGetItem",
                        "dynamodb:BatchWriteItem",
                        "dynamodb:DeleteItem",
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:Query",
                        "dynamodb:Scan",
                        "dynamodb:UpdateItem",
                        # SQS messaging only.
                        "sqs:ChangeMessageVisibility",
                        "sqs:DeleteMessage",
                        "sqs:DeleteMessageBatch",
                        "sqs:GetQueueAttributes",
                        "sqs:GetQueueUrl",
                        "sqs:ReceiveMessage",
                        "sqs:SendMessage",
                        "sqs:SendMessageBatch",
                        # EventBridge data-plane only.
                        "events:PutEvents",
                        # Step Functions execution only.
                        "states:DescribeExecution",
                        "states:GetExecutionHistory",
                        "states:StartExecution",
                        "states:StopExecution",
                        # Bedrock runtime only (no provisioning).
                        "bedrock:Converse",
                        "bedrock:ConverseStream",
                        "bedrock:InvokeModel",
                        "bedrock:InvokeModelWithResponseStream",
                        # Invoke-only for downstream APIs.
                        "execute-api:Invoke",
                        "lambda:InvokeFunction",
                        # Messaging/email (no resource provisioning).
                        "sns:Publish",
                        "ses:SendEmail",
                        "ses:SendRawEmail",
                        # Read-only config/secrets and decrypt.
                        "ssm:GetParameter",
                        "ssm:GetParameters",
                        "ssm:GetParametersByPath",
                        "secretsmanager:GetSecretValue",
                        "kms:Decrypt",
                        # Useful for runtime diagnostics without enabling privilege movement.
                        "sts:GetCallerIdentity",
                    ],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=[
                        "account:*",
                        "aws-portal:*",
                        "billing:*",
                        "budgets:*",
                        "iam:*",
                        "organizations:*",
                        "support:*",
                        "supportplans:*",
                    ],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=[
                        # Workloads should not be able to provision by calling CloudFormation APIs.
                        "cloudformation:*",
                    ],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=[
                        "sts:AssumeRole",
                        "sts:AssumeRoleWithSAML",
                        "sts:AssumeRoleWithWebIdentity",
                        "sts:TagSession",
                        "sts:SetSourceIdentity",
                    ],
                    resources=["*"],
                ),
            ],
        )

        allowed_attach_policy_arns = [
            managed_policy_arn_pattern,
            # Allow AWS service-role policies by default; deny high-risk policies separately.
            f"arn:{Aws.PARTITION}:iam::aws:policy/service-role/*",
            f"arn:{Aws.PARTITION}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
            f"arn:{Aws.PARTITION}:iam::aws:policy/AmazonSSMManagedInstanceCore",
            f"arn:{Aws.PARTITION}:iam::aws:policy/CloudWatchAgentServerPolicy",
            f"arn:{Aws.PARTITION}:iam::aws:policy/AmazonEKSClusterPolicy",
            f"arn:{Aws.PARTITION}:iam::aws:policy/AmazonEKSWorkerNodePolicy",
            f"arn:{Aws.PARTITION}:iam::aws:policy/AmazonEKS_CNI_Policy",
        ]

        cfn_execution_boundary = iam.ManagedPolicy(
            self,
            "CfnExecutionBoundary",
            managed_policy_name=f"{name_prefix}-cfn-exec-boundary",
            statements=[
                iam.PolicyStatement(actions=["*"], resources=["*"]),
                # Ensure the execution role can't rewrite the broker-control plane roles.
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=["iam:*"],
                    resources=[
                        f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:role/{name_prefix}-broker-provisioning",
                        f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:role/{name_prefix}-cfn-exec",
                    ],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=["iam:DeleteRolePermissionsBoundary"],
                    resources=[managed_role_arn_pattern],
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
                                "acm:*",
                                "apigateway:*",
                                "application-autoscaling:*",
                                "autoscaling:*",
                                "cloudfront:*",
                                "cloudwatch:*",
                                "cognito-identity:*",
                                "cognito-idp:*",
                                "dynamodb:*",
                                "ec2:*",
                                "ecr:*",
                                "ecs:*",
                                "eks:*",
                                "elasticloadbalancing:*",
                                "events:*",
                                "kms:*",
                                "lambda:*",
                                "logs:*",
                                "rds:*",
                                "route53:*",
                                "s3:*",
                                "secretsmanager:*",
                                "servicediscovery:*",
                                "sns:*",
                                "sqs:*",
                                "ssm:*",
                                "states:*",
                            ],
                            resources=["*"],
                        ),
                        # Allow creation of service-linked roles needed by common build services.
                        iam.PolicyStatement(
                            actions=["iam:CreateServiceLinkedRole"],
                            resources=["*"],
                            conditions={
                                "StringLike": {
                                    "iam:AWSServiceName": [
                                        "autoscaling.amazonaws.com",
                                        "ecs.amazonaws.com",
                                        "eks.amazonaws.com",
                                        "elasticloadbalancing.amazonaws.com",
                                        "rds.amazonaws.com",
                                        "spot.amazonaws.com",
                                    ]
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            actions=["iam:CreateRole"],
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
                                "iam:UpdateAssumeRolePolicy",
                            ],
                            resources=[managed_role_arn_pattern],
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
                                "iam:TagPolicy",
                                "iam:UntagPolicy",
                            ],
                            resources=[managed_policy_arn_pattern],
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "iam:AttachRolePolicy",
                                "iam:DetachRolePolicy",
                            ],
                            resources=[managed_role_arn_pattern],
                            conditions={
                                "StringLike": {"iam:PolicyARN": allowed_attach_policy_arns}
                            },
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "iam:CreateInstanceProfile",
                                "iam:DeleteInstanceProfile",
                                "iam:GetInstanceProfile",
                                "iam:AddRoleToInstanceProfile",
                                "iam:RemoveRoleFromInstanceProfile",
                                "iam:TagInstanceProfile",
                                "iam:UntagInstanceProfile",
                            ],
                            resources=[managed_instance_profile_arn_pattern],
                        ),
                        iam.PolicyStatement(
                            actions=["iam:PassRole"],
                            resources=[managed_role_arn_pattern],
                            conditions={
                                "StringEquals": {
                                    "iam:PassedToService": [
                                        "apigateway.amazonaws.com",
                                        "cloudformation.amazonaws.com",
                                        "ec2.amazonaws.com",
                                        "ecs-tasks.amazonaws.com",
                                        "ecs.amazonaws.com",
                                        "eks.amazonaws.com",
                                        "events.amazonaws.com",
                                        "lambda.amazonaws.com",
                                        "monitoring.rds.amazonaws.com",
                                        "rds.amazonaws.com",
                                        "states.amazonaws.com",
                                    ]
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.DENY,
                            actions=["iam:DeleteRolePermissionsBoundary"],
                            resources=[managed_role_arn_pattern],
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.DENY,
                            actions=[
                                "iam:CreateUser",
                                "iam:DeleteUser",
                                "iam:CreateAccessKey",
                                "iam:DeleteAccessKey",
                                "iam:UpdateAccessKey",
                                "iam:CreateLoginProfile",
                                "iam:DeleteLoginProfile",
                                "iam:UpdateLoginProfile",
                            ],
                            resources=["*"],
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.DENY,
                            actions=[
                                "iam:AttachGroupPolicy",
                                "iam:AttachRolePolicy",
                                "iam:AttachUserPolicy",
                            ],
                            resources=["*"],
                            conditions={
                                "ArnEquals": {
                                    "iam:PolicyARN": f"arn:{Aws.PARTITION}:iam::aws:policy/AdministratorAccess"
                                }
                            },
                        ),
                    ]
                )
            },
            max_session_duration=Duration.seconds(session_duration_seconds),
            description="Execution role for agent CloudFormation stacks in the agent-workshop account.",
        )

        issued_provisioning_boundary = iam.ManagedPolicy(
            self,
            "IssuedProvisioningBoundary",
            managed_policy_name=f"{name_prefix}-issued-provisioning-boundary",
            statements=[
                iam.PolicyStatement(
                    actions=["sts:GetCallerIdentity"],
                    resources=["*"],
                ),
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

        # CloudFormation does not reliably expose StackName/RoleARN request parameters as IAM condition keys
        # (at least not for the APIs agents commonly use, like CreateStack/CreateChangeSet/ExecuteChangeSet).
        # We scope stack operations by resource ARN patterns plus required (request/resource) tags instead.
        agent_stack_arn_pattern = (
            f"arn:{Aws.PARTITION}:cloudformation:{Aws.REGION}:{Aws.ACCOUNT_ID}:stack/"
            f"agent-${{aws:PrincipalTag/sub}}-*/*"
        )
        agent_changeset_arn_pattern = (
            f"arn:{Aws.PARTITION}:cloudformation:{Aws.REGION}:{Aws.ACCOUNT_ID}:changeSet/*"
        )

        broker_provisioning_role = iam.Role(
            self,
            "BrokerProvisioningRole",
            role_name=f"{name_prefix}-broker-provisioning",
            assumed_by=iam.ArnPrincipal(broker_lambda_exec_role_arn),
            permissions_boundary=issued_provisioning_boundary,
            inline_policies={
                "BrokerProvisioning": iam.PolicyDocument(
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
                                "cloudformation:CreateChangeSet",
                            ],
                            resources=[agent_stack_arn_pattern],
                            conditions={
                                "StringEquals": {
                                    "aws:RequestTag/agent_sub": "${aws:PrincipalTag/sub}",
                                    "aws:RequestTag/agent_username": "${aws:PrincipalTag/username}",
                                },
                            },
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "cloudformation:UpdateStack",
                                "cloudformation:CreateChangeSet",
                            ],
                            resources=[agent_stack_arn_pattern],
                            conditions={
                                "StringEquals": {
                                    "aws:ResourceTag/agent_sub": "${aws:PrincipalTag/sub}",
                                    "aws:ResourceTag/agent_username": "${aws:PrincipalTag/username}",
                                },
                            },
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "cloudformation:ExecuteChangeSet",
                            ],
                            resources=[agent_stack_arn_pattern],
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "cloudformation:DeleteStack",
                            ],
                            resources=[agent_stack_arn_pattern],
                            conditions={
                                "StringEquals": {
                                    "aws:ResourceTag/agent_sub": "${aws:PrincipalTag/sub}",
                                    "aws:ResourceTag/agent_username": "${aws:PrincipalTag/username}",
                                },
                            },
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "cloudformation:DeleteChangeSet",
                            ],
                            resources=[agent_stack_arn_pattern, agent_changeset_arn_pattern],
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
                        iam.PolicyStatement(
                            actions=["sts:GetCallerIdentity"],
                            resources=["*"],
                        ),
                    ]
                )
            },
            max_session_duration=Duration.seconds(session_duration_seconds),
            description="Provisioning-control role assumed by the sandbox broker; CloudFormation control-plane + pass execution role.",
        )

        if broker_provisioning_role.assume_role_policy:
            broker_provisioning_role.assume_role_policy.add_statements(
                iam.PolicyStatement(
                    actions=["sts:TagSession", "sts:SetSourceIdentity"],
                    principals=[iam.ArnPrincipal(broker_lambda_exec_role_arn)],
                )
            )

        issued_runtime_boundary = iam.ManagedPolicy(
            self,
            "IssuedRuntimeBoundary",
            managed_policy_name=f"{name_prefix}-issued-runtime-boundary",
            statements=[
                # Wide allow; we rely on identity policies + SCPs for the main restrictions.
                iam.PolicyStatement(actions=["*"], resources=["*"]),
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=[
                        "account:*",
                        "aws-portal:*",
                        "billing:*",
                        "budgets:*",
                        "organizations:*",
                        "support:*",
                        "supportplans:*",
                    ],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=[
                        "iam:*",
                    ],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=[
                        "sts:AssumeRole",
                        "sts:AssumeRoleWithSAML",
                        "sts:AssumeRoleWithWebIdentity",
                        "sts:TagSession",
                        "sts:SetSourceIdentity",
                    ],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=[
                        "cloudformation:Create*",
                        "cloudformation:Update*",
                        "cloudformation:Delete*",
                        "cloudformation:ExecuteChangeSet",
                    ],
                    resources=["*"],
                ),
            ],
        )

        broker_runtime_role = iam.Role(
            self,
            "BrokerRuntimeRole",
            role_name=f"{name_prefix}-broker-runtime",
            assumed_by=iam.ArnPrincipal(broker_lambda_exec_role_arn),
            permissions_boundary=issued_runtime_boundary,
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("ReadOnlyAccess")
            ],
            inline_policies={
                "BrokerRuntime": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "sqs:SendMessage",
                                "sqs:SendMessageBatch",
                                "sqs:DeleteMessage",
                                "sqs:DeleteMessageBatch",
                                "sqs:ChangeMessageVisibility",
                            ],
                            resources=[
                                f"arn:{Aws.PARTITION}:sqs:{Aws.REGION}:{Aws.ACCOUNT_ID}:*",
                            ],
                            conditions={
                                "StringEquals": {
                                    "aws:ResourceTag/agent_sub": "${aws:PrincipalTag/sub}",
                                    "aws:ResourceTag/agent_username": "${aws:PrincipalTag/username}",
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            actions=["sns:Publish"],
                            resources=[
                                f"arn:{Aws.PARTITION}:sns:{Aws.REGION}:{Aws.ACCOUNT_ID}:*",
                            ],
                            conditions={
                                "StringEquals": {
                                    "aws:ResourceTag/agent_sub": "${aws:PrincipalTag/sub}",
                                    "aws:ResourceTag/agent_username": "${aws:PrincipalTag/username}",
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            actions=["events:PutEvents"],
                            resources=[
                                f"arn:{Aws.PARTITION}:events:{Aws.REGION}:{Aws.ACCOUNT_ID}:event-bus/*",
                            ],
                            conditions={
                                "StringEquals": {
                                    "aws:ResourceTag/agent_sub": "${aws:PrincipalTag/sub}",
                                    "aws:ResourceTag/agent_username": "${aws:PrincipalTag/username}",
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            actions=["states:StartExecution"],
                            resources=[
                                f"arn:{Aws.PARTITION}:states:{Aws.REGION}:{Aws.ACCOUNT_ID}:stateMachine:*",
                            ],
                            conditions={
                                "StringEquals": {
                                    "aws:ResourceTag/agent_sub": "${aws:PrincipalTag/sub}",
                                    "aws:ResourceTag/agent_username": "${aws:PrincipalTag/username}",
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "states:DescribeExecution",
                                "states:GetExecutionHistory",
                                "states:StopExecution",
                            ],
                            resources=[
                                f"arn:{Aws.PARTITION}:states:{Aws.REGION}:{Aws.ACCOUNT_ID}:execution:*:*",
                            ],
                        ),
                        iam.PolicyStatement(
                            actions=["cloudfront:CreateInvalidation"],
                            resources=[
                                f"arn:{Aws.PARTITION}:cloudfront::{Aws.ACCOUNT_ID}:distribution/*",
                            ],
                            conditions={
                                "StringEquals": {
                                    "aws:ResourceTag/agent_sub": "${aws:PrincipalTag/sub}",
                                    "aws:ResourceTag/agent_username": "${aws:PrincipalTag/username}",
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "dynamodb:BatchWriteItem",
                                "dynamodb:DeleteItem",
                                "dynamodb:PutItem",
                                "dynamodb:UpdateItem",
                                "dynamodb:TransactWriteItems",
                            ],
                            resources=[
                                f"arn:{Aws.PARTITION}:dynamodb:{Aws.REGION}:{Aws.ACCOUNT_ID}:table/*",
                                f"arn:{Aws.PARTITION}:dynamodb:{Aws.REGION}:{Aws.ACCOUNT_ID}:table/*/index/*",
                            ],
                            conditions={
                                "StringEquals": {
                                    "aws:ResourceTag/agent_sub": "${aws:PrincipalTag/sub}",
                                    "aws:ResourceTag/agent_username": "${aws:PrincipalTag/username}",
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            actions=["secretsmanager:GetSecretValue"],
                            resources=[
                                f"arn:{Aws.PARTITION}:secretsmanager:{Aws.REGION}:{Aws.ACCOUNT_ID}:secret:*",
                            ],
                            conditions={
                                "StringEquals": {
                                    "aws:ResourceTag/agent_sub": "${aws:PrincipalTag/sub}",
                                    "aws:ResourceTag/agent_username": "${aws:PrincipalTag/username}",
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            actions=["kms:Decrypt"],
                            resources=[
                                f"arn:{Aws.PARTITION}:kms:{Aws.REGION}:{Aws.ACCOUNT_ID}:key/*",
                            ],
                            conditions={
                                "StringEquals": {
                                    "aws:ResourceTag/agent_sub": "${aws:PrincipalTag/sub}",
                                    "aws:ResourceTag/agent_username": "${aws:PrincipalTag/username}",
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "bedrock:Converse",
                                "bedrock:ConverseStream",
                                "bedrock:InvokeModel",
                                "bedrock:InvokeModelWithResponseStream",
                            ],
                            resources=["*"],
                            conditions={
                                "StringEquals": {
                                    "aws:RequestedRegion": ["us-east-1", "us-west-2"],
                                }
                            },
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "s3:PutObject",
                                "s3:DeleteObject",
                            ],
                            resources=[
                                f"arn:{Aws.PARTITION}:s3:::agent-${{aws:PrincipalTag/sub}}-*/*",
                            ],
                        ),
                    ]
                )
            },
            max_session_duration=Duration.seconds(session_duration_seconds),
            description="Runtime role assumed by the sandbox broker; broad read + safe data-plane ops (no provisioning).",
        )

        if broker_runtime_role.assume_role_policy:
            broker_runtime_role.assume_role_policy.add_statements(
                iam.PolicyStatement(
                    actions=["sts:TagSession", "sts:SetSourceIdentity"],
                    principals=[iam.ArnPrincipal(broker_lambda_exec_role_arn)],
                )
            )

        CfnOutput(
            self,
            "AgentSandboxBrokerProvisioningRoleArn",
            value=broker_provisioning_role.role_arn,
        )
        CfnOutput(
            self,
            "AgentAWSWorkshopBrokerProvisioningRoleArn",
            value=broker_provisioning_role.role_arn,
            description="Alias of AgentSandboxBrokerProvisioningRoleArn.",
        )
        CfnOutput(
            self,
            "AgentSandboxBrokerRuntimeRoleArn",
            value=broker_runtime_role.role_arn,
        )
        CfnOutput(
            self,
            "AgentAWSWorkshopBrokerRuntimeRoleArn",
            value=broker_runtime_role.role_arn,
            description="Alias of AgentSandboxBrokerRuntimeRoleArn.",
        )
        CfnOutput(
            self,
            "AgentSandboxCfnExecutionRoleArn",
            value=cfn_execution_role.role_arn,
        )
        CfnOutput(
            self,
            "AgentAWSWorkshopCfnExecutionRoleArn",
            value=cfn_execution_role.role_arn,
            description="Alias of AgentSandboxCfnExecutionRoleArn.",
        )
        CfnOutput(
            self,
            "AgentSandboxAgentWorkloadBoundaryArn",
            value=agent_workload_boundary.managed_policy_arn,
        )
        CfnOutput(
            self,
            "AgentAWSWorkshopAgentWorkloadBoundaryArn",
            value=agent_workload_boundary.managed_policy_arn,
            description="Alias of AgentSandboxAgentWorkloadBoundaryArn.",
        )
