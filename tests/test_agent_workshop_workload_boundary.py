import sys
from pathlib import Path

from aws_cdk import App
from aws_cdk import assertions

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from stacks.agent_aws_workshop_stack import AgentAWSWorkshopStack


def _synth_template(monkeypatch) -> dict:
    monkeypatch.setenv(
        "BROKER_LAMBDA_EXEC_ROLE_ARN",
        "arn:aws:iam::123456789012:role/DummyBrokerLambdaExecutionRole",
    )
    app = App()
    stack = AgentAWSWorkshopStack(app, "AgentWorkshopBoundaryTestStack")
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


def _statement_actions(stmt: dict) -> list[str]:
    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        return [actions]
    return actions


def _is_allow(stmt: dict) -> bool:
    return stmt.get("Effect", "Allow") == "Allow"


def test_agent_workload_boundary_is_explicit_allowlist(monkeypatch):
    template = _synth_template(monkeypatch)
    policy = _find_resource(template, "AWS::IAM::ManagedPolicy", "AgentWorkloadBoundary")
    statements = policy["Properties"]["PolicyDocument"]["Statement"]

    allow_actions: list[str] = []
    for stmt in statements:
        if _is_allow(stmt):
            allow_actions.extend(_statement_actions(stmt))

    # No blanket allow; allow statements should be an explicit allowlist.
    assert "*" not in allow_actions
    assert not any(a.endswith(":*") for a in allow_actions)


def test_agent_workload_boundary_denies_cloudformation(monkeypatch):
    template = _synth_template(monkeypatch)
    policy = _find_resource(template, "AWS::IAM::ManagedPolicy", "AgentWorkloadBoundary")
    statements = policy["Properties"]["PolicyDocument"]["Statement"]

    assert any(
        s.get("Effect") == "Deny" and "cloudformation:*" in _statement_actions(s)
        for s in statements
    )


def test_agent_workload_boundary_blocks_common_provisioning_actions(monkeypatch):
    template = _synth_template(monkeypatch)
    policy = _find_resource(template, "AWS::IAM::ManagedPolicy", "AgentWorkloadBoundary")
    statements = policy["Properties"]["PolicyDocument"]["Statement"]

    allow_actions: set[str] = set()
    for stmt in statements:
        if _is_allow(stmt):
            allow_actions.update(_statement_actions(stmt))

    for action in (
        "s3:CreateBucket",
        "dynamodb:CreateTable",
        "sqs:CreateQueue",
        "lambda:CreateFunction",
        "events:CreateEventBus",
    ):
        assert action not in allow_actions
