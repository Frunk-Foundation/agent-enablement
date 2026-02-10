import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3

_sts_client = None
_ddb_client = None

PROFILE_TABLE_NAME = os.environ.get("PROFILE_TABLE_NAME", "")
ASSUME_ROLE_ARN = os.environ.get("ASSUME_ROLE_ARN", "")
DEFAULT_TTL_SECONDS = int(os.environ.get("DEFAULT_TTL_SECONDS", "900"))
MAX_TTL_SECONDS = int(os.environ.get("MAX_TTL_SECONDS", "900"))
SCHEMA_VERSION = os.environ.get("SCHEMA_VERSION", "2026-02-10")

UPLOAD_BUCKET = os.environ.get("UPLOAD_BUCKET", "")
UPLOAD_BASE_PREFIX = os.environ.get("UPLOAD_BASE_PREFIX", "uploads/")
SQS_QUEUE_ARN = os.environ.get("SQS_QUEUE_ARN", "")
EVENT_BUS_ARN = os.environ.get("EVENT_BUS_ARN", "")


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body),
    }


def _session_name(agent_id: str) -> str:
    sanitized = re.sub(r"[^a-zA-Z0-9+=,.@_-]", "", f"agent-{agent_id}")
    return (sanitized[:64] or "agent-session")


def _duration_seconds() -> int:
    return min(max(DEFAULT_TTL_SECONDS, 900), min(MAX_TTL_SECONDS, 3600))


def _get_claims(event: dict[str, Any]) -> dict[str, Any]:
    # REST API (proxy integration) authorizer claims are exposed here.
    return (
        event.get("requestContext", {})
        .get("authorizer", {})
        .get("claims", {})
        or {}
    )


def _get_request_id(event: dict[str, Any]) -> str:
    return (
        event.get("requestContext", {}).get("requestId")
        or event.get("requestContext", {}).get("requestId")
        or ""
    )


def _ddb_get_profile(sub: str) -> dict[str, Any] | None:
    out = _ddb().get_item(
        TableName=PROFILE_TABLE_NAME,
        Key={"sub": {"S": sub}},
        ConsistentRead=True,
    )
    return out.get("Item")


def _ddb_bool(item: dict[str, Any], key: str, default: bool = False) -> bool:
    val = item.get(key)
    if not val or "BOOL" not in val:
        return default
    return bool(val["BOOL"])


def _ddb_str(item: dict[str, Any], key: str, default: str = "") -> str:
    val = item.get(key)
    if not val or "S" not in val:
        return default
    return str(val["S"])


def _policy_for_profile(bucket: str, prefix: str, sqs_arn: str, bus_arn: str) -> dict[str, Any]:
    statements: list[dict[str, Any]] = []

    if bucket and prefix:
        # Strictly constrain uploads to the server-issued UUID prefix.
        obj_arn = f"arn:aws:s3:::{bucket}/{prefix}*"
        statements.append(
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:AbortMultipartUpload"],
                "Resource": [obj_arn],
            }
        )

    if sqs_arn:
        statements.append(
            {
                "Effect": "Allow",
                "Action": ["sqs:SendMessage"],
                "Resource": [sqs_arn],
            }
        )

    if bus_arn:
        statements.append(
            {
                "Effect": "Allow",
                "Action": ["events:PutEvents"],
                "Resource": [bus_arn],
            }
        )

    return {"Version": "2012-10-17", "Statement": statements}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _aws_region() -> str | None:
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")


def _sts():
    global _sts_client
    if _sts_client is None:
        _sts_client = boto3.client("sts", region_name=_aws_region())
    return _sts_client


def _ddb():
    global _ddb_client
    if _ddb_client is None:
        _ddb_client = boto3.client("dynamodb", region_name=_aws_region())
    return _ddb_client


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    start = time.time()
    request_id = _get_request_id(event)

    wide_event: dict[str, Any] = {
        "event": "agent_bootstrap",
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id,
        "ts": _now_iso(),
    }

    status_code = 500
    body: dict[str, Any] = {}

    try:
        if not PROFILE_TABLE_NAME or not ASSUME_ROLE_ARN:
            status_code = 500
            body = {
                "errorCode": "MISCONFIGURED",
                "message": "Server misconfigured",
                "requestId": request_id,
            }
            wide_event["outcome"] = "error"
            return _response(status_code, body)

        claims = _get_claims(event)
        sub = claims.get("sub")
        iss = claims.get("iss")

        wide_event["principal"] = {"sub": sub, "issuer": iss}

        if not sub:
            status_code = 401
            body = {
                "errorCode": "UNAUTHORIZED",
                "message": "Missing subject claim",
                "requestId": request_id,
            }
            wide_event["outcome"] = "unauthorized"
            return _response(status_code, body)

        profile_item = _ddb_get_profile(sub)
        if not profile_item:
            status_code = 404
            body = {
                "errorCode": "PROFILE_NOT_FOUND",
                "message": "No profile for subject",
                "requestId": request_id,
            }
            wide_event["outcome"] = "not_found"
            return _response(status_code, body)

        enabled = _ddb_bool(profile_item, "enabled", default=False)
        if not enabled:
            status_code = 403
            body = {
                "errorCode": "UNAUTHORIZED",
                "message": "Profile disabled",
                "requestId": request_id,
            }
            wide_event["outcome"] = "unauthorized"
            return _response(status_code, body)

        assume_role_arn = _ddb_str(profile_item, "assumeRoleArn", default=ASSUME_ROLE_ARN)
        # v1 safety: do not allow profiles to escalate to arbitrary roles.
        if assume_role_arn != ASSUME_ROLE_ARN:
            status_code = 422
            body = {
                "errorCode": "INVALID_PROFILE",
                "message": "assumeRoleArn not permitted",
                "requestId": request_id,
            }
            wide_event["outcome"] = "invalid_profile"
            return _response(status_code, body)
        s3_bucket = _ddb_str(profile_item, "s3Bucket", default=UPLOAD_BUCKET)
        base_prefix = _ddb_str(profile_item, "s3BasePrefix", default=UPLOAD_BASE_PREFIX)
        sqs_arn = _ddb_str(profile_item, "sqsQueueArn", default=SQS_QUEUE_ARN)
        bus_arn = _ddb_str(profile_item, "eventBusArn", default=EVENT_BUS_ARN)
        instruction_text = _ddb_str(profile_item, "instructionText", default="")

        if not assume_role_arn:
            status_code = 422
            body = {
                "errorCode": "INVALID_PROFILE",
                "message": "Profile missing assumeRoleArn",
                "requestId": request_id,
            }
            wide_event["outcome"] = "invalid_profile"
            return _response(status_code, body)

        prefix_uuid = str(uuid.uuid4())
        base_prefix = base_prefix if base_prefix.endswith("/") else (base_prefix + "/")
        issued_prefix = f"{base_prefix}{prefix_uuid}/"

        policy = _policy_for_profile(s3_bucket, issued_prefix, sqs_arn, bus_arn)

        # Avoid issuing empty policies: if profile doesn't grant anything, reject.
        if not policy["Statement"]:
            status_code = 422
            body = {
                "errorCode": "INVALID_PROFILE",
                "message": "Profile grants no permissions",
                "requestId": request_id,
            }
            wide_event["outcome"] = "invalid_profile"
            return _response(status_code, body)

        wide_event["grants"] = {
            "s3_bucket": s3_bucket,
            "s3_prefix": issued_prefix,
            "sqs_queue_arn": sqs_arn,
            "event_bus_arn": bus_arn,
            "assume_role_arn": assume_role_arn,
        }

        assume_kwargs = {
            "RoleArn": assume_role_arn,
            "RoleSessionName": _session_name(sub),
            "DurationSeconds": _duration_seconds(),
            "Policy": json.dumps(policy),
            "SourceIdentity": sub,
            "Tags": [
                {"Key": "sub", "Value": sub},
                {"Key": "request_id", "Value": request_id[:256] if request_id else ""},
            ],
        }

        try:
            assumed = _sts().assume_role(**assume_kwargs)
        except Exception as exc:
            # IAM changes may take time to reflect in the Lambda's already-issued role session.
            # If tagging/source identity fails due to permission, retry without those optional fields.
            msg = str(exc)
            if "AccessDenied" in msg and ("SetSourceIdentity" in msg or "TagSession" in msg):
                assume_kwargs.pop("SourceIdentity", None)
                assume_kwargs.pop("Tags", None)
                assumed = _sts().assume_role(**assume_kwargs)
            else:
                raise

        creds = assumed.get("Credentials", {})
        expiration = creds.get("Expiration")
        if hasattr(expiration, "isoformat"):
            expiration_iso = expiration.isoformat()
        else:
            expiration_iso = str(expiration)

        issued_at = _now_iso()

        grants: list[dict[str, Any]] = []
        if s3_bucket:
            grants.append(
                {
                    "service": "s3",
                    "actions": ["s3:PutObject", "s3:AbortMultipartUpload"],
                    "resources": [f"arn:aws:s3:::{s3_bucket}/{issued_prefix}*"],
                    "instructions": "Upload only to the assigned prefix.",
                }
            )
        if sqs_arn:
            grants.append(
                {
                    "service": "sqs",
                    "actions": ["sqs:SendMessage"],
                    "resources": [sqs_arn],
                }
            )
        if bus_arn:
            grants.append(
                {
                    "service": "events",
                    "actions": ["events:PutEvents"],
                    "resources": [bus_arn],
                }
            )

        status_code = 200
        body = {
            "schemaVersion": SCHEMA_VERSION,
            "principal": {"sub": sub, "issuer": iss},
            "issuedAt": issued_at,
            "expiresAt": expiration_iso,
            "credentials": {
                "accessKeyId": creds.get("AccessKeyId"),
                "secretAccessKey": creds.get("SecretAccessKey"),
                "sessionToken": creds.get("SessionToken"),
                "expiration": expiration_iso,
            },
            "grants": grants,
            "constraints": {
                "ttlSeconds": _duration_seconds(),
                "uploadPrefixUuid": prefix_uuid,
            },
            "instructions": instruction_text,
        }

        wide_event["outcome"] = "success"
        wide_event["status_code"] = 200
        return _response(status_code, body)
    except Exception as exc:
        wide_event["outcome"] = "error"
        wide_event["status_code"] = status_code
        wide_event["error"] = {"type": type(exc).__name__, "message": str(exc)}
        status_code = 500
        body = {
            "errorCode": "STS_ISSUE_FAILED",
            "message": "Failed to generate bootstrap credentials",
            "requestId": request_id,
        }
        return _response(status_code, body)
    finally:
        wide_event["duration_ms"] = int((time.time() - start) * 1000)
        # Never log credential material.
        print(json.dumps(wide_event, separators=(",", ":"), sort_keys=True))
