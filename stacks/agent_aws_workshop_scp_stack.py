import json

from aws_cdk import Stack, aws_organizations as organizations
from constructs import Construct


class AgentAWSWorkshopScpStack(Stack):
    """
    Deploy into the AWS Organizations management account.

    Attaches deny-only SCPs to the AgentAWSWorkshop account to enforce:
    - Provisioning/mutation APIs must be called by CloudFormation (or exempt principals)
    - IAM/STS privilege-escalation actions are blocked outside CloudFormation
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        target_account_id: str,
        name_prefix: str = "agentawsworkshop",
        policy_name_prefix: str = "AgentAWSWorkshop",
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        target_account_id = (target_account_id or "").strip()
        if not target_account_id:
            raise ValueError("target_account_id is required (AgentAWSWorkshop account id).")

        name_prefix = (name_prefix or "agentawsworkshop").strip() or "agentawsworkshop"
        policy_name_prefix = (policy_name_prefix or "AgentAWSWorkshop").strip() or "AgentAWSWorkshop"

        # In SCP evaluation, aws:PrincipalArn is typically the STS assumed-role ARN:
        # arn:aws:sts::<acct>:assumed-role/<RoleName>/<SessionName>
        exempt_principal_arns = [
            f"arn:aws:sts::{target_account_id}:assumed-role/{name_prefix}-cfn-exec/*",
            # Do NOT exempt the broker-issued roles here. The point of the SCP backstop is that
            # even if a broker role policy is later misconfigured, it still can't provision.
            f"arn:aws:sts::{target_account_id}:assumed-role/AWSReservedSSO_AdministratorAccess_*/*",
        ]

        cfn_called_via_condition = {
            "ForAllValues:StringNotEqualsIfExists": {
                "aws:CalledVia": "cloudformation.amazonaws.com"
            }
        }

        not_exempt_principal_condition = {
            "ArnNotLike": {"aws:PrincipalArn": exempt_principal_arns}
        }

        deny_provisioning_actions = [
            # S3 provisioning/config (data-plane object CRUD is not included here).
            "s3:CreateBucket",
            "s3:DeleteBucket",
            "s3:PutBucket*",
            "s3:DeleteBucket*",
            # DynamoDB table provisioning (item CRUD is not included here).
            "dynamodb:CreateTable",
            "dynamodb:UpdateTable",
            "dynamodb:DeleteTable",
            "dynamodb:CreateGlobalTable",
            "dynamodb:UpdateGlobalTable",
            "dynamodb:DeleteGlobalTable",
            "dynamodb:TagResource",
            "dynamodb:UntagResource",
            # SQS provisioning/config (Send/Receive/DeleteMessage are not included here).
            "sqs:CreateQueue",
            "sqs:DeleteQueue",
            "sqs:SetQueueAttributes",
            "sqs:TagQueue",
            "sqs:UntagQueue",
            # SNS provisioning/config (Publish is not included here).
            "sns:CreateTopic",
            "sns:DeleteTopic",
            "sns:SetTopicAttributes",
            "sns:Subscribe",
            "sns:Unsubscribe",
            "sns:TagResource",
            "sns:UntagResource",
            # Lambda provisioning/config (Invoke is not included here).
            "lambda:CreateFunction",
            "lambda:DeleteFunction",
            "lambda:UpdateFunctionCode",
            "lambda:UpdateFunctionConfiguration",
            "lambda:CreateEventSourceMapping",
            "lambda:UpdateEventSourceMapping",
            "lambda:DeleteEventSourceMapping",
            "lambda:AddPermission",
            "lambda:RemovePermission",
            # EventBridge provisioning/config (events:PutEvents is not included here).
            "events:CreateEventBus",
            "events:DeleteEventBus",
            "events:PutRule",
            "events:DeleteRule",
            "events:PutTargets",
            "events:RemoveTargets",
            "events:PutPermission",
            "events:RemovePermission",
            "events:TagResource",
            "events:UntagResource",
            # Step Functions provisioning/config (states:StartExecution is not included here).
            "states:CreateStateMachine",
            "states:UpdateStateMachine",
            "states:DeleteStateMachine",
            "states:TagResource",
            "states:UntagResource",
            # CloudFront provisioning/config (CreateInvalidation is not included here).
            "cloudfront:CreateDistribution*",
            "cloudfront:UpdateDistribution*",
            "cloudfront:DeleteDistribution*",
            "cloudfront:TagResource",
            "cloudfront:UntagResource",
            # API Gateway uses verb-style IAM actions.
            "apigateway:POST",
            "apigateway:PUT",
            "apigateway:PATCH",
            "apigateway:DELETE",
        ]

        deny_provisioning_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyProvisioningNotViaCfn",
                    "Effect": "Deny",
                    "Action": deny_provisioning_actions,
                    "Resource": "*",
                    "Condition": {
                        **not_exempt_principal_condition,
                        **cfn_called_via_condition,
                    },
                }
            ],
        }

        deny_iam_escalation_actions = [
            # IAM role/policy mutation (priv-esc paths).
            "iam:CreateRole",
            "iam:DeleteRole",
            "iam:UpdateRole",
            "iam:PutRolePolicy",
            "iam:DeleteRolePolicy",
            "iam:AttachRolePolicy",
            "iam:DetachRolePolicy",
            "iam:CreatePolicy",
            "iam:DeletePolicy",
            "iam:CreatePolicyVersion",
            "iam:SetDefaultPolicyVersion",
            "iam:PutRolePermissionsBoundary",
            "iam:DeleteRolePermissionsBoundary",
            "iam:UpdateAssumeRolePolicy",
            # Optional hardening: avoid IAM user access keys entirely.
            "iam:CreateUser",
            "iam:DeleteUser",
            "iam:CreateAccessKey",
            "iam:DeleteAccessKey",
            "iam:UpdateAccessKey",
            "iam:CreateLoginProfile",
            "iam:DeleteLoginProfile",
            "iam:UpdateLoginProfile",
            # STS role chaining / session tampering.
            "sts:AssumeRole",
            "sts:AssumeRoleWithWebIdentity",
            "sts:AssumeRoleWithSAML",
            "sts:TagSession",
            "sts:SetSourceIdentity",
        ]

        deny_iam_escalation_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyIamEscalationNotViaCfn",
                    "Effect": "Deny",
                    "Action": deny_iam_escalation_actions,
                    "Resource": "*",
                    "Condition": {
                        **not_exempt_principal_condition,
                        **cfn_called_via_condition,
                    },
                }
            ],
        }

        organizations.CfnPolicy(
            self,
            "AgentAWSWorkshopDenyProvisioningNotViaCfn",
            name=f"{policy_name_prefix}-DenyProvisioningNotViaCfn",
            description="Deny common provisioning/mutation APIs unless called via CloudFormation or exempt principals.",
            type="SERVICE_CONTROL_POLICY",
            content=deny_provisioning_doc,
            target_ids=[target_account_id],
        )

        organizations.CfnPolicy(
            self,
            "AgentAWSWorkshopDenyIamEscalationNotViaCfn",
            name=f"{policy_name_prefix}-DenyIamEscalationNotViaCfn",
            description="Deny IAM/STS privilege-escalation actions unless called via CloudFormation or exempt principals.",
            type="SERVICE_CONTROL_POLICY",
            content=deny_iam_escalation_doc,
            target_ids=[target_account_id],
        )
