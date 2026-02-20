import base64
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import boto3
from id58 import BASE58_ALPHABET

PROFILE_TABLE_NAME = os.environ.get("PROFILE_TABLE_NAME", "")
LINKS_TABLE_NAME = os.environ.get("LINKS_TABLE_NAME", "")
SCHEMA_VERSION = os.environ.get("SCHEMA_VERSION", "2026-02-14")

_ddb_client = None


CODE_ALPHABET = BASE58_ALPHABET
CODE_LEN = 22
MAX_URL_LENGTH = 4096


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _aws_region() -> str | None:
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")


def _ddb():
    global _ddb_client
    if _ddb_client is None:
        _ddb_client = boto3.client("dynamodb", region_name=_aws_region())
    return _ddb_client


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "content-type": "application/json",
            "cache-control": "no-store",
        },
        "body": json.dumps(body),
    }


def _parse_json_body(event: dict[str, Any]) -> dict[str, Any] | None:
    raw = event.get("body")
    if raw is None:
        return None
    if event.get("isBase64Encoded"):
        try:
            raw = base64.b64decode(raw).decode("utf-8")
        except Exception:
            return None
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        data = json.loads(raw)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _claims(event: dict[str, Any]) -> dict[str, Any]:
    rc = event.get("requestContext") or {}
    if not isinstance(rc, dict):
        return {}
    auth = rc.get("authorizer") or {}
    if not isinstance(auth, dict):
        return {}
    claims = auth.get("claims")
    if isinstance(claims, dict):
        return claims
    jwt_claims = (auth.get("jwt") or {}).get("claims")
    if isinstance(jwt_claims, dict):
        return jwt_claims
    return {}


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


def _normalize_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if ":" in host:
        host = host.split(":", 1)[0]
    return host


def _validate_target_url(url: str) -> tuple[bool, str, str]:
    if not isinstance(url, str):
        return False, "targetUrl must be a string", ""
    candidate = url.strip()
    if not candidate:
        return False, "targetUrl is required", ""
    if len(candidate) > MAX_URL_LENGTH:
        return False, "targetUrl too long", ""

    parsed = urlparse(candidate)
    if parsed.scheme.lower() != "https":
        return False, "targetUrl must use https", ""

    host = _normalize_host(parsed.netloc)
    if not host:
        return False, "targetUrl host is required", ""

    return True, "", candidate


def _validate_alias(alias: str | None) -> tuple[bool, str, str]:
    if alias is None:
        return True, "", ""
    if not isinstance(alias, str):
        return False, "alias must be a string", ""
    code = alias.strip()
    if not code:
        return False, "alias cannot be empty", ""
    if len(code) != CODE_LEN:
        return False, f"alias must be exactly {CODE_LEN} characters", ""
    if any(ch not in CODE_ALPHABET for ch in code):
        return False, "alias must use Bitcoin Base58 characters", ""
    return True, "", code


def _generate_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LEN))


def _request_id(event: dict[str, Any]) -> str:
    return str((event.get("requestContext") or {}).get("requestId") or "")


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    start = time.time()
    request_id = _request_id(event)

    wide_event: dict[str, Any] = {
        "event": "agents_accessaws_create_shortlink",
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id,
        "ts": _now_iso(),
    }

    status_code = 500
    body: dict[str, Any] = {}
    try:
        if not PROFILE_TABLE_NAME or not LINKS_TABLE_NAME:
            status_code = 500
            body = {
                "errorCode": "MISCONFIGURED",
                "message": "Server misconfigured",
                "requestId": request_id,
            }
            wide_event["outcome"] = "error"
            return _response(status_code, body)

        claims = _claims(event)
        sub = str(claims.get("sub") or "").strip()
        cognito_username = str(claims.get("cognito:username") or claims.get("username") or "").strip()
        if not sub:
            status_code = 401
            body = {
                "errorCode": "UNAUTHORIZED",
                "message": "missing authorizer claims",
                "requestId": request_id,
            }
            wide_event["outcome"] = "unauthorized"
            return _response(status_code, body)
        if not cognito_username:
            cognito_username = sub

        profile = _ddb_get_profile(sub)
        if not profile or not _ddb_bool(profile, "enabled", default=False):
            status_code = 403
            body = {
                "errorCode": "UNAUTHORIZED",
                "message": "Profile not enabled",
                "requestId": request_id,
            }
            wide_event["outcome"] = "unauthorized"
            return _response(status_code, body)

        payload = _parse_json_body(event)
        if payload is None:
            status_code = 400
            body = {
                "errorCode": "BAD_REQUEST",
                "message": "Request body must be a JSON object",
                "requestId": request_id,
            }
            wide_event["outcome"] = "bad_request"
            return _response(status_code, body)

        ok, err, target_url = _validate_target_url(payload.get("targetUrl", ""))
        if not ok:
            status_code = 400
            body = {
                "errorCode": "INVALID_TARGET_URL",
                "message": err,
                "requestId": request_id,
            }
            wide_event["outcome"] = "invalid_target"
            return _response(status_code, body)

        ok, err, alias = _validate_alias(payload.get("alias"))
        if not ok:
            status_code = 400
            body = {
                "errorCode": "INVALID_ALIAS",
                "message": err,
                "requestId": request_id,
            }
            wide_event["outcome"] = "invalid_alias"
            return _response(status_code, body)

        parsed = urlparse(target_url)
        target_host = _normalize_host(parsed.netloc)

        code = alias
        used_alias = bool(alias)
        if not code:
            for _ in range(5):
                candidate = _generate_code()
                try:
                    _ddb().put_item(
                        TableName=LINKS_TABLE_NAME,
                        Item={
                            "code": {"S": candidate},
                            "targetUrl": {"S": target_url},
                            "targetHost": {"S": target_host},
                            "createdAt": {"S": _now_iso()},
                            "createdBySub": {"S": str(sub)},
                            "createdByUsername": {"S": str(cognito_username)},
                            "disabled": {"BOOL": False},
                        },
                        ConditionExpression="attribute_not_exists(#code)",
                        ExpressionAttributeNames={"#code": "code"},
                    )
                    code = candidate
                    break
                except Exception:
                    continue
            if not code:
                status_code = 503
                body = {
                    "errorCode": "CODE_GENERATION_FAILED",
                    "message": "Could not allocate short code",
                    "requestId": request_id,
                }
                wide_event["outcome"] = "code_generation_failed"
                return _response(status_code, body)
        else:
            try:
                _ddb().put_item(
                    TableName=LINKS_TABLE_NAME,
                    Item={
                        "code": {"S": code},
                        "targetUrl": {"S": target_url},
                        "targetHost": {"S": target_host},
                        "createdAt": {"S": _now_iso()},
                        "createdBySub": {"S": str(sub)},
                        "createdByUsername": {"S": str(cognito_username)},
                        "disabled": {"BOOL": False},
                    },
                    ConditionExpression="attribute_not_exists(#code)",
                    ExpressionAttributeNames={"#code": "code"},
                )
            except Exception:
                status_code = 409
                body = {
                    "errorCode": "ALIAS_CONFLICT",
                    "message": "alias already exists",
                    "requestId": request_id,
                }
                wide_event["outcome"] = "alias_conflict"
                return _response(status_code, body)

        short_path = f"/l/{code}"
        status_code = 201
        body = {
            "schemaVersion": SCHEMA_VERSION,
            "code": code,
            "shortPath": short_path,
            "createdAt": _now_iso(),
            "createdBy": {
                "sub": sub,
                "username": cognito_username,
            },
            "target": {
                "host": target_host,
                "sha256": hashlib.sha256(target_url.encode("utf-8")).hexdigest(),
            },
            "requestId": request_id,
            "usedAlias": used_alias,
        }
        wide_event["outcome"] = "success"
        wide_event["principal"] = {"sub": sub, "username": cognito_username}
        wide_event["code"] = code
        wide_event["target_host"] = target_host
        return _response(status_code, body)
    except Exception as exc:
        wide_event["outcome"] = "error"
        wide_event["error"] = {"type": type(exc).__name__, "message": str(exc)}
        status_code = 500
        body = {
            "errorCode": "INTERNAL_ERROR",
            "message": "Failed to create short link",
            "requestId": request_id,
        }
        return _response(status_code, body)
    finally:
        wide_event["duration_ms"] = int((time.time() - start) * 1000)
        print(json.dumps(wide_event, separators=(",", ":"), sort_keys=True))
