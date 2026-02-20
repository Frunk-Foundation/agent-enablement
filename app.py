#!/usr/bin/env python3
import os

import aws_cdk as cdk

from stacks.agent_enablement_stack import AgentEnablementStack
from stacks.agent_aws_workshop_stack import AgentAWSWorkshopStack
from stacks.agent_aws_workshop_scp_stack import AgentAWSWorkshopScpStack

app = cdk.App()

stack_name = os.getenv("CDK_STACK_NAME", "AgentEnablementStack")

AgentEnablementStack(
    app,
    stack_name,
    env=cdk.Environment(
        account=os.getenv("CDK_DEFAULT_ACCOUNT"),
        region=os.getenv("CDK_DEFAULT_REGION", "us-east-2"),
    ),
)

agent_workshop_account_id = (os.getenv("AGENT_WORKSHOP_ACCOUNT_ID") or "").strip()
broker_lambda_exec_role_arn = (os.getenv("BROKER_LAMBDA_EXEC_ROLE_ARN") or "").strip()
if agent_workshop_account_id and broker_lambda_exec_role_arn:
    agent_workshop_stack_name = os.getenv(
        "AGENT_WORKSHOP_STACK_NAME", "AgentAWSWorkshopStack"
    )
    AgentAWSWorkshopStack(
        app,
        agent_workshop_stack_name,
        env=cdk.Environment(
            account=agent_workshop_account_id,
            region=os.getenv("AGENT_WORKSHOP_REGION", "us-east-2"),
        ),
    )

scp_enabled = (os.getenv("AGENT_WORKSHOP_SCP_ENABLED") or "").strip().lower() in {
    "1",
    "true",
    "yes",
}
if scp_enabled:
    scp_stack_name = os.getenv("AGENT_WORKSHOP_SCP_STACK_NAME", "AgentAWSWorkshopScpStack")
    # Placeholder only; set AGENT_WORKSHOP_SCP_TARGET_ACCOUNT_ID (or AGENT_WORKSHOP_ACCOUNT_ID) for real deploys.
    scp_target_account_id = (
        (os.getenv("AGENT_WORKSHOP_SCP_TARGET_ACCOUNT_ID") or agent_workshop_account_id)
        or "000000000000"
    ).strip()
    AgentAWSWorkshopScpStack(
        app,
        scp_stack_name,
        target_account_id=scp_target_account_id,
        name_prefix=os.getenv("AGENT_WORKSHOP_NAME_PREFIX", "agentawsworkshop"),
        env=cdk.Environment(
            account=os.getenv("CDK_DEFAULT_ACCOUNT"),
            region=os.getenv("CDK_DEFAULT_REGION", "us-east-1"),
        ),
    )

app.synth()
