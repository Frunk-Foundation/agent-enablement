import json

from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_apigateway as apigw,
    aws_cognito as cognito,
    aws_dynamodb as ddb,
    aws_events as events,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_s3 as s3,
    aws_sqs as sqs,
    aws_cloudwatch as cloudwatch,
)
from constructs import Construct


class AgentBootstrapStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        stage_name = "prod"
        session_duration_seconds = 900
        schema_version = "2026-02-10"

        upload_bucket = s3.Bucket(
            self,
            "AgentUploadBucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        )

        agent_queue = sqs.Queue(
            self,
            "AgentQueue",
            retention_period=Duration.days(4),
            removal_policy=RemovalPolicy.DESTROY,
        )

        agent_bus = events.EventBus(
            self,
            "AgentEventBus",
            event_bus_name="agent-bus",
        )

        profile_table = ddb.Table(
            self,
            "AgentProfiles",
            partition_key=ddb.Attribute(name="sub", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        user_pool = cognito.UserPool(
            self,
            "AgentUserPool",
            user_pool_name="agent-bootstrap-users",
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(username=True, email=True),
            password_policy=cognito.PasswordPolicy(
                min_length=12,
                require_digits=True,
                require_lowercase=True,
                require_uppercase=True,
                require_symbols=True,
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )

        user_pool_client = user_pool.add_client(
            "AgentUserPoolClient",
            auth_flows=cognito.AuthFlow(user_password=True, user_srp=True),
            generate_secret=False,
        )

        lambda_execution_role = iam.Role(
            self,
            "BootstrapLambdaExecutionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ],
        )

        broker_target_role = iam.Role(
            self,
            "AgentBrokerTargetRole",
            assumed_by=iam.ArnPrincipal(lambda_execution_role.role_arn),
            inline_policies={
                "AgentBrokerTarget": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["sts:GetCallerIdentity"],
                            resources=["*"],
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "s3:PutObject",
                                "s3:AbortMultipartUpload",
                            ],
                            resources=[upload_bucket.arn_for_objects("*")],
                        ),
                        iam.PolicyStatement(
                            actions=["sqs:SendMessage"],
                            resources=[agent_queue.queue_arn],
                        ),
                        iam.PolicyStatement(
                            actions=["events:PutEvents"],
                            resources=[agent_bus.event_bus_arn],
                        ),
                    ]
                )
            },
            description="Role assumed by the bootstrap broker; per-request session policy restricts to agent profile resources.",
        )

        lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "sts:AssumeRole",
                    "sts:TagSession",
                    "sts:SetSourceIdentity",
                ],
                resources=[broker_target_role.role_arn],
            )
        )

        profile_table.grant_read_data(lambda_execution_role)

        bootstrap_fn = _lambda.Function(
            self,
            "BootstrapHandler",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="bootstrap_handler.handler",
            code=_lambda.Code.from_asset("lambda"),
            timeout=Duration.seconds(10),
            role=lambda_execution_role,
            environment={
                "PROFILE_TABLE_NAME": profile_table.table_name,
                "ASSUME_ROLE_ARN": broker_target_role.role_arn,
                "DEFAULT_TTL_SECONDS": str(session_duration_seconds),
                "MAX_TTL_SECONDS": str(session_duration_seconds),
                "SCHEMA_VERSION": schema_version,
                "UPLOAD_BUCKET": upload_bucket.bucket_name,
                "UPLOAD_BASE_PREFIX": "uploads/",
                "SQS_QUEUE_ARN": agent_queue.queue_arn,
                "EVENT_BUS_ARN": agent_bus.event_bus_arn,
            },
        )

        # Don't create the log group resource (it may already exist from prior invocations).
        # Reference by name so metric filters can attach without import conflicts.
        log_group = logs.LogGroup.from_log_group_name(
            self,
            "BootstrapLogGroup",
            f"/aws/lambda/{bootstrap_fn.function_name}",
        )

        rest_api = apigw.RestApi(
            self,
            "AgentBootstrapApi",
            rest_api_name="agent-bootstrap-api",
            deploy_options=apigw.StageOptions(stage_name=stage_name),
            cloud_watch_role=False,
        )

        authorizer = apigw.CognitoUserPoolsAuthorizer(
            self,
            "AgentCognitoAuthorizer",
            cognito_user_pools=[user_pool],
        )

        v1 = rest_api.root.add_resource("v1")
        bootstrap = v1.add_resource("bootstrap")
        bootstrap.add_method(
            "GET",
            apigw.LambdaIntegration(bootstrap_fn),
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=authorizer,
        )

        error_metric = cloudwatch.Metric(
            namespace="AgentBootstrap",
            metric_name="Errors",
            statistic="Sum",
            period=Duration.minutes(5),
        )

        logs.MetricFilter(
            self,
            "BootstrapErrorMetricFilter",
            log_group=log_group,
            metric_namespace="AgentBootstrap",
            metric_name="Errors",
            filter_pattern=logs.FilterPattern.string_value("$.outcome", "=", "error"),
            metric_value="1",
        )

        cloudwatch.Alarm(
            self,
            "BootstrapErrorsAlarm",
            metric=error_metric,
            threshold=1,
            evaluation_periods=1,
            datapoints_to_alarm=1,
        )

        CfnOutput(
            self,
            "BootstrapInvokeUrl",
            value=f"{rest_api.url}v1/bootstrap",
            description="Invoke URL for bootstrap endpoint.",
        )

        CfnOutput(
            self,
            "AgentProfilesTableName",
            value=profile_table.table_name,
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
            "SchemaVersion",
            value=schema_version,
        )
