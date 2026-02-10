#!/usr/bin/env python3
import os

import aws_cdk as cdk

from stacks.bootstrap_stack import AgentBootstrapStack

app = cdk.App()

AgentBootstrapStack(
    app,
    "AgentBootstrapStack",
    env=cdk.Environment(
        account=os.getenv("CDK_DEFAULT_ACCOUNT"),
        region=os.getenv("CDK_DEFAULT_REGION", "us-east-1"),
    ),
)

app.synth()
