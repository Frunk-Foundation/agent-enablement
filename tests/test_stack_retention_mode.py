import pytest
from aws_cdk import App
from aws_cdk import assertions
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from stacks.agent_enablement_stack import AgentEnablementStack


def _synth_template(monkeypatch, mode: str | None) -> dict:
    monkeypatch.setenv("STAGE", "test")
    if mode is None:
        monkeypatch.delenv("DATA_RETENTION_MODE", raising=False)
    else:
        monkeypatch.setenv("DATA_RETENTION_MODE", mode)
    app = App()
    stack = AgentEnablementStack(app, "RetentionModeTestStack")
    return assertions.Template.from_stack(
        stack, skip_cyclical_dependencies_check=True
    ).to_json()


def _deletion_policies(template: dict, resource_type: str) -> list[str]:
    return [
        resource.get("DeletionPolicy", "")
        for resource in template["Resources"].values()
        if resource.get("Type") == resource_type
    ]


def _log_group_deletion_policies(template: dict) -> list[str]:
    policies: list[str] = []
    for resource in template["Resources"].values():
        if resource.get("Type") != "AWS::Logs::LogGroup":
            continue
        retention = (resource.get("Properties") or {}).get("RetentionInDays")
        if retention == 7:
            policies.append(resource.get("DeletionPolicy", ""))
    return policies


def test_default_data_retention_mode_is_destroy(monkeypatch):
    template = _synth_template(monkeypatch, mode=None)

    assert set(_deletion_policies(template, "AWS::S3::Bucket")) == {"Delete"}
    assert set(_deletion_policies(template, "AWS::DynamoDB::Table")) == {"Delete"}
    assert set(_deletion_policies(template, "AWS::SQS::Queue")) == {"Delete"}
    assert set(_deletion_policies(template, "AWS::Cognito::UserPool")) == {"Delete"}
    assert set(_log_group_deletion_policies(template)) == {"Delete"}

    auto_delete = [
        resource
        for resource in template["Resources"].values()
        if resource.get("Type") == "Custom::S3AutoDeleteObjects"
    ]
    assert len(auto_delete) == 2


def test_data_retention_mode_retain(monkeypatch):
    template = _synth_template(monkeypatch, mode="retain")

    assert set(_deletion_policies(template, "AWS::S3::Bucket")) == {"Retain"}
    assert set(_deletion_policies(template, "AWS::DynamoDB::Table")) == {"Retain"}
    assert set(_deletion_policies(template, "AWS::SQS::Queue")) == {"Retain"}
    assert set(_deletion_policies(template, "AWS::Cognito::UserPool")) == {"Retain"}
    assert set(_log_group_deletion_policies(template)) == {"Retain"}

    auto_delete = [
        resource
        for resource in template["Resources"].values()
        if resource.get("Type") == "Custom::S3AutoDeleteObjects"
    ]
    assert not auto_delete


def test_invalid_data_retention_mode_fails_fast(monkeypatch):
    monkeypatch.setenv("STAGE", "test")
    monkeypatch.setenv("DATA_RETENTION_MODE", "keep-forever")

    app = App()
    with pytest.raises(ValueError, match="DATA_RETENTION_MODE"):
        AgentEnablementStack(app, "RetentionModeInvalidStack")
