import json
import os
import time
from datetime import datetime, timezone
from typing import Any

import boto3

PROFILE_TABLE_NAME = os.environ.get("PROFILE_TABLE_NAME", "")
PROFILE_AGENT_ID_INDEX = os.environ.get("PROFILE_AGENT_ID_INDEX", "agentId-index")
SCHEMA_VERSION = os.environ.get("SCHEMA_VERSION", "2026-02-18")
SOURCE_PREFIX = "agents.messages.sub."

_ddb_client = None
_sqs_client = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ddb():
    global _ddb_client
    if _ddb_client is None:
        _ddb_client = boto3.client("dynamodb", region_name=os.environ.get("AWS_REGION"))
    return _ddb_client


def _sqs():
    global _sqs_client
    if _sqs_client is None:
        _sqs_client = boto3.client("sqs", region_name=os.environ.get("AWS_REGION"))
    return _sqs_client


def _unmarshal_profile(item: dict[str, Any]) -> dict[str, Any]:
    sub = str(item.get("sub", {}).get("S", "")).strip()
    enabled = bool(item.get("enabled", {}).get("BOOL", False))
    agent_id = str(item.get("agentId", {}).get("S", "")).strip()
    inbox_queue_url = str(item.get("inboxQueueUrl", {}).get("S", "")).strip()
    return {
        "sub": sub,
        "enabled": enabled,
        "agentId": agent_id,
        "inboxQueueUrl": inbox_queue_url,
    }


def _get_profile_by_sub(sub: str) -> dict[str, Any] | None:
    out = _ddb().get_item(
        TableName=PROFILE_TABLE_NAME,
        Key={"sub": {"S": sub}},
        ConsistentRead=True,
    )
    item = out.get("Item")
    if not item:
        return None
    profile = _unmarshal_profile(item)
    if not profile["enabled"] or not profile["sub"] or not profile["agentId"] or not profile["inboxQueueUrl"]:
        return None
    return profile


def _get_profile_by_username(username: str) -> dict[str, Any] | None:
    out = _ddb().query(
        TableName=PROFILE_TABLE_NAME,
        IndexName=PROFILE_AGENT_ID_INDEX,
        KeyConditionExpression="agentId = :agentId",
        ExpressionAttributeValues={":agentId": {"S": username}},
        Limit=10,
    )
    for item in out.get("Items", []):
        profile = _unmarshal_profile(item)
        if profile["enabled"] and profile["sub"] and profile["agentId"] and profile["inboxQueueUrl"]:
            return profile
    return None


def _parse_sender_sub(source: str) -> str:
    if not source.startswith(SOURCE_PREFIX):
        return ""
    sender_sub = source[len(SOURCE_PREFIX) :].strip()
    return sender_sub


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    start = time.time()
    log = {
        "event": "agent_enablement_route_messages",
        "schema_version": SCHEMA_VERSION,
        "ts": _now_iso(),
        "event_id": event.get("id", ""),
    }

    if not PROFILE_TABLE_NAME:
        log["outcome"] = "misconfigured"
        print(json.dumps(log, separators=(",", ":"), sort_keys=True))
        return {"ok": False, "error": "PROFILE_TABLE_NAME missing"}

    detail = event.get("detail") or {}
    source = str(event.get("source", "")).strip()
    sender_sub = _parse_sender_sub(source)
    to_username = str(detail.get("toUsername", "")).strip()

    if not sender_sub:
        log["outcome"] = "invalid_source"
        log["source"] = source
        log["to_username"] = to_username
        log["duration_ms"] = int((time.time() - start) * 1000)
        print(json.dumps(log, separators=(",", ":"), sort_keys=True))
        return {"ok": False, "error": "invalid_source", "sent": 0, "failed": 0}

    if not to_username or ":" in to_username:
        log["outcome"] = "invalid_to"
        log["source"] = source
        log["sender_sub"] = sender_sub
        log["to_username"] = to_username
        log["duration_ms"] = int((time.time() - start) * 1000)
        print(json.dumps(log, separators=(",", ":"), sort_keys=True))
        return {"ok": False, "error": "invalid_to", "sent": 0, "failed": 0}

    sender_profile = _get_profile_by_sub(sender_sub)
    if not sender_profile:
        log["outcome"] = "unauthorized_sender"
        log["source"] = source
        log["sender_sub"] = sender_sub
        log["to_username"] = to_username
        log["duration_ms"] = int((time.time() - start) * 1000)
        print(json.dumps(log, separators=(",", ":"), sort_keys=True))
        return {"ok": False, "error": "unauthorized_sender", "sent": 0, "failed": 0}

    recipient = _get_profile_by_username(to_username)
    if not recipient:
        log["outcome"] = "recipient_not_found"
        log["source"] = source
        log["sender_sub"] = sender_sub
        log["sender_username"] = sender_profile["agentId"]
        log["to_username"] = to_username
        log["duration_ms"] = int((time.time() - start) * 1000)
        print(json.dumps(log, separators=(",", ":"), sort_keys=True))
        return {"ok": False, "error": "recipient_not_found", "sent": 0, "failed": 0}

    payload = {
        "schemaVersion": SCHEMA_VERSION,
        "receivedAt": _now_iso(),
        "kind": str(detail.get("kind", "")).strip() or "json.v1",
        "toUsername": to_username,
        "senderUsername": sender_profile["agentId"],
        "senderSub": sender_sub,
        "message": detail.get("message"),
        "meta": detail.get("meta", {}),
        "event": {
            "id": event.get("id"),
            "source": event.get("source"),
            "detailType": event.get("detail-type"),
            "time": event.get("time"),
        },
    }
    body = json.dumps(payload, separators=(",", ":"))

    sent = 0
    failed = 0
    try:
        _sqs().send_message(QueueUrl=recipient["inboxQueueUrl"], MessageBody=body)
        sent += 1
    except Exception:
        failed += 1

    log["source"] = source
    log["sender_sub"] = sender_sub
    log["sender_username"] = sender_profile["agentId"]
    log["to_username"] = to_username
    log["sent"] = sent
    log["failed"] = failed
    log["outcome"] = "success" if failed == 0 else "partial_failure"
    log["duration_ms"] = int((time.time() - start) * 1000)
    print(json.dumps(log, separators=(",", ":"), sort_keys=True))
    return {"ok": failed == 0, "sent": sent, "failed": failed}
