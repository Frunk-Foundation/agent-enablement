from __future__ import annotations

import base64
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import boto3
from id58 import uuid4_base58_22

PROFILE_TABLE_NAME = os.environ.get("PROFILE_TABLE_NAME", "")
USER_POOL_CLIENT_ID = os.environ.get("USER_POOL_CLIENT_ID", "")
ENABLEMENT_BUNDLE_URL = os.environ.get("ENABLEMENT_BUNDLE_URL", "")
CREDENTIALS_INVOKE_URL = os.environ.get("CREDENTIALS_INVOKE_URL", "")
BUNDLE_INVOKE_URL = os.environ.get("BUNDLE_INVOKE_URL", "")
TASKBOARD_INVOKE_URL = os.environ.get("TASKBOARD_INVOKE_URL", "")
SHORTLINK_CREATE_URL = os.environ.get("SHORTLINK_CREATE_URL", "")
SHORTLINK_REDIRECT_BASE_URL = os.environ.get("SHORTLINK_REDIRECT_BASE_URL", "")
FILES_PUBLIC_BASE_URL = os.environ.get("FILES_PUBLIC_BASE_URL", "")
CREDENTIALS_PATH = os.environ.get("CREDENTIALS_PATH", "/v1/credentials")
BUNDLE_PATH = os.environ.get("BUNDLE_PATH", "/v1/bundle")
TASKBOARD_PATH = os.environ.get("TASKBOARD_PATH", "/v1/taskboard")
SHORTLINK_CREATE_PATH = os.environ.get("SHORTLINK_CREATE_PATH", "/v1/links")
SHORTLINK_REDIRECT_PREFIX = os.environ.get("SHORTLINK_REDIRECT_PREFIX", "/l/")
SSM_KEYS_STAGE = os.environ.get("SSM_KEYS_STAGE", "")

DEFAULT_BUNDLE_TTL_SECONDS = 900
MAX_BUNDLE_TTL_SECONDS = 3600
CONNECTION_SCHEMA_VERSION = "2026-02-17"

_s3_client: Any | None = None
_ddb_client: Any | None = None
_cognito_client: Any | None = None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _sanitize_path_segment(val: str, fallback: str) -> str:
    if not val:
        return fallback
    s = re.sub(r"[^a-zA-Z0-9._-]", "-", val)
    s = s.strip("-")
    return s or fallback


def _get_request_id(event: dict[str, Any]) -> str:
    rc = event.get("requestContext") or {}
    if isinstance(rc, dict):
        rid = str(rc.get("requestId") or "").strip()
        if rid:
            return rid
    return uuid4_base58_22()


def _query_param(event: dict[str, Any], name: str) -> str:
    qs = event.get("queryStringParameters") or {}
    if not isinstance(qs, dict):
        return ""
    v = qs.get(name)
    return str(v) if v is not None else ""


def _ttl_seconds(event: dict[str, Any]) -> int:
    raw = _query_param(event, "ttlSeconds").strip()
    if not raw:
        return DEFAULT_BUNDLE_TTL_SECONDS
    try:
        n = int(raw)
    except Exception:
        return DEFAULT_BUNDLE_TTL_SECONDS
    return min(max(n, 60), MAX_BUNDLE_TTL_SECONDS)


def _s3() -> Any:
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3")
    return _s3_client


def _aws_region() -> str:
    return str(os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "").strip()


def _ddb() -> Any:
    global _ddb_client
    if _ddb_client is None:
        _ddb_client = boto3.client("dynamodb")
    return _ddb_client


def _cognito() -> Any:
    global _cognito_client
    if _cognito_client is None:
        _cognito_client = boto3.client("cognito-idp")
    return _cognito_client


def _json_response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": json.dumps(body),
    }


def _get_header(event: dict[str, Any], name: str) -> str:
    headers = event.get("headers") or {}
    if not isinstance(headers, dict):
        return ""
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == name.lower():
            return str(v) if v is not None else ""
    return ""


def _parse_basic_auth(event: dict[str, Any]) -> tuple[str, str] | None:
    auth = _get_header(event, "authorization")
    if not auth:
        return None
    if not auth.lower().startswith("basic "):
        return None
    b64 = auth.split(" ", 1)[1].strip()
    if not b64:
        return None
    try:
        decoded = base64.b64decode(b64.encode("utf-8")).decode("utf-8")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    username, password = decoded.split(":", 1)
    if not username or not password:
        return None
    return username, password


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}


def _parse_user_pool_id_from_issuer(issuer: str) -> str:
    if not issuer:
        return ""
    try:
        path = str(urlparse(issuer).path or "")
        parts = [p for p in path.split("/") if p]
        return parts[-1] if parts else ""
    except Exception:
        return issuer.rstrip("/").split("/")[-1]


def _ssm_stage(event: dict[str, Any]) -> str:
    stage = str(SSM_KEYS_STAGE or "").strip()
    if stage:
        return stage
    request_stage = str(((event.get("requestContext") or {}).get("stage")) or "").strip()
    if request_stage:
        return request_stage
    return "prod"


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


def _bundle_bucket_and_key(bundle_url: str) -> tuple[str, str]:
    parsed = urlparse((bundle_url or "").strip())
    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lstrip("/")
    if parsed.scheme == "s3":
        bucket = parsed.netloc.strip()
        key = path
        if bucket and key:
            return bucket, key
    if not host or not path:
        raise ValueError("ENABLEMENT_BUNDLE_URL must include bucket and object key")

    if host.endswith(".amazonaws.com"):
        if ".s3." in host or host.startswith("s3."):
            if host.startswith("s3."):
                # path-style URL: s3.<region>.amazonaws.com/<bucket>/<key>
                parts = path.split("/", 1)
                if len(parts) != 2:
                    raise ValueError("ENABLEMENT_BUNDLE_URL path-style URL missing bucket or key")
                return parts[0], parts[1]
            # virtual-hosted-style URL: <bucket>.s3.<region>.amazonaws.com/<key>
            bucket = host.split(".s3.", 1)[0]
            if bucket and path:
                return bucket, path

    raise ValueError("ENABLEMENT_BUNDLE_URL must be an S3 URL")


def _presign_get_zip(bucket: str, key: str, ttl_seconds: int) -> str:
    return _s3().generate_presigned_url(
        "get_object",
        Params={
            "Bucket": bucket,
            "Key": key,
            "ResponseContentType": "application/zip",
            "ResponseContentDisposition": 'attachment; filename="agent-enablement-bundle.zip"',
        },
        ExpiresIn=ttl_seconds,
    )


def _best_effort_base_url(event: dict[str, Any]) -> str:
    headers = event.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    host = str(headers.get("host") or headers.get("Host") or "").strip()
    proto = str(headers.get("x-forwarded-proto") or headers.get("X-Forwarded-Proto") or "").strip().lower()
    if proto not in ("http", "https"):
        proto = "https"
    if host:
        base = f"{proto}://{host}"
        stage = str(((event.get("requestContext") or {}).get("stage")) or "").strip()
        if stage and ".execute-api." in host.lower():
            return f"{base}/{stage}"
        return base
    return ""


def _join_url(base: str, path: str) -> str:
    b = (base or "").rstrip("/")
    p = "/" + (path or "").lstrip("/")
    if not b:
        return p
    return f"{b}{p}"


def _connection_payload(event: dict[str, Any], *, claims: dict[str, Any]) -> dict[str, Any]:
    base_url = _best_effort_base_url(event)
    auth: dict[str, Any] = {}
    credentials_endpoint = CREDENTIALS_INVOKE_URL.strip() or _join_url(base_url, CREDENTIALS_PATH)
    if credentials_endpoint:
        auth["credentialsEndpoint"] = credentials_endpoint
    bundle_endpoint = BUNDLE_INVOKE_URL.strip() or _join_url(base_url, BUNDLE_PATH)
    if bundle_endpoint:
        auth["bundleEndpoint"] = bundle_endpoint

    shortlinks: dict[str, Any] = {}
    shortlinks_create = SHORTLINK_CREATE_URL.strip() or _join_url(base_url, SHORTLINK_CREATE_PATH)
    if shortlinks_create:
        shortlinks["createUrl"] = shortlinks_create
    shortlinks_redirect_base = SHORTLINK_REDIRECT_BASE_URL.strip() or _join_url(
        base_url, SHORTLINK_REDIRECT_PREFIX
    )
    if shortlinks_redirect_base:
        shortlinks["redirectBaseUrl"] = shortlinks_redirect_base

    taskboard: dict[str, Any] = {}
    taskboard_invoke = TASKBOARD_INVOKE_URL.strip() or _join_url(base_url, TASKBOARD_PATH)
    if taskboard_invoke:
        taskboard["invokeUrl"] = taskboard_invoke

    files: dict[str, Any] = {}
    files_public_base = FILES_PUBLIC_BASE_URL.strip()
    if files_public_base:
        files["publicBaseUrl"] = files_public_base

    issuer = str(claims.get("iss") or "").strip()
    cognito: dict[str, Any] = {
        "issuer": issuer,
        "userPoolId": _parse_user_pool_id_from_issuer(issuer),
        "userPoolClientId": USER_POOL_CLIENT_ID,
        "openidConfigurationUrl": _join_url(issuer, ".well-known/openid-configuration") if issuer else "",
        "jwksUrl": _join_url(issuer, ".well-known/jwks.json") if issuer else "",
        "reauth": {"mode": "call-enablement-api-again"},
    }

    stage = _ssm_stage(event)
    ssm_keys: dict[str, Any] = {
        "stage": stage,
        "sharedBasePath": f"/agent-enablement/{stage}/shared/",
        "agentBasePathTemplate": f"/agent-enablement/{stage}/agent/<principal.sub>/",
    }

    payload: dict[str, Any] = {
        "schemaVersion": CONNECTION_SCHEMA_VERSION,
        "awsRegion": _aws_region(),
    }
    if auth:
        payload["auth"] = auth
    if shortlinks:
        payload["shortlinks"] = shortlinks
    if taskboard:
        payload["taskboard"] = taskboard
    if files:
        payload["files"] = files
    payload["cognito"] = cognito
    payload["ssmKeys"] = ssm_keys
    return payload


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    start = time.time()
    request_id = _get_request_id(event)

    wide_event: dict[str, Any] = {
        "event": "agents_accessaws_issue_bundle",
        "request_id": request_id,
        "ts": _iso(_utc_now()),
    }

    try:
        if not PROFILE_TABLE_NAME or not USER_POOL_CLIENT_ID or not ENABLEMENT_BUNDLE_URL:
            wide_event["outcome"] = "error"
            return _json_response(
                500,
                {
                    "errorCode": "MISCONFIGURED",
                    "message": "Server misconfigured",
                    "requestId": request_id,
                },
            )

        try:
            bundle_bucket, bundle_key = _bundle_bucket_and_key(ENABLEMENT_BUNDLE_URL)
        except Exception:
            wide_event["outcome"] = "error"
            return _json_response(
                500,
                {
                    "errorCode": "MISCONFIGURED",
                    "message": "Server misconfigured",
                    "requestId": request_id,
                },
            )

        basic = _parse_basic_auth(event)
        if not basic:
            wide_event["outcome"] = "unauthorized"
            return _json_response(
                401,
                {
                    "errorCode": "UNAUTHORIZED",
                    "message": "Missing or invalid Basic authorization",
                    "requestId": request_id,
                },
            )
        username, password = basic

        try:
            auth = _cognito().initiate_auth(
                ClientId=USER_POOL_CLIENT_ID,
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={"USERNAME": username, "PASSWORD": password},
            )
        except Exception:
            wide_event["outcome"] = "unauthorized"
            return _json_response(
                401,
                {
                    "errorCode": "UNAUTHORIZED",
                    "message": "Incorrect username or password",
                    "requestId": request_id,
                },
            )

        auth_result = auth.get("AuthenticationResult") or {}
        id_token = str(auth_result.get("IdToken") or "")
        claims = _decode_jwt_claims(id_token)
        sub = str(claims.get("sub") or "").strip()
        username = str(claims.get("cognito:username") or username).strip()
        if not sub:
            wide_event["outcome"] = "unauthorized"
            return _json_response(
                401,
                {
                    "errorCode": "UNAUTHORIZED",
                    "message": "Missing subject claim",
                    "requestId": request_id,
                },
            )

        profile_item = _ddb_get_profile(sub)
        if not profile_item:
            wide_event["outcome"] = "not_found"
            return _json_response(
                404,
                {
                    "errorCode": "PROFILE_NOT_FOUND",
                    "message": "No profile for subject",
                    "requestId": request_id,
                },
            )

        if not _ddb_bool(profile_item, "enabled", default=False):
            wide_event["outcome"] = "unauthorized"
            return _json_response(
                403,
                {
                    "errorCode": "UNAUTHORIZED",
                    "message": "Profile disabled",
                    "requestId": request_id,
                },
            )

        ttl = _ttl_seconds(event)

        try:
            _s3().head_object(Bucket=bundle_bucket, Key=bundle_key)
        except Exception:
            wide_event["outcome"] = "unavailable"
            return _json_response(
                503,
                {
                    "errorCode": "BUNDLE_UNAVAILABLE",
                    "message": "Enablement bundle is unavailable",
                    "requestId": request_id,
                },
            )

        bundle_url = _presign_get_zip(bundle_bucket, bundle_key, ttl)

        wide_event["outcome"] = "success"
        wide_event["status_code"] = 200
        wide_event["principal"] = {
            "sub": _sanitize_path_segment(sub, "unknown-sub"),
            "username": _sanitize_path_segment(username, "unknown-user"),
        }
        wide_event["bundle"] = {
            "bucket": bundle_bucket,
            "key": bundle_key,
            "ttl_seconds": ttl,
        }

        return _json_response(
            200,
            {
                "bundleUrl": bundle_url,
                "connection": _connection_payload(event, claims=claims),
                "requestId": request_id,
            },
        )
    except Exception as exc:
        wide_event["outcome"] = "error"
        wide_event["status_code"] = 500
        wide_event["error"] = {"type": type(exc).__name__, "message": str(exc)}
        return _json_response(
            500,
            {
                "errorCode": "BUNDLE_UNAVAILABLE",
                "message": "Enablement bundle is unavailable",
                "requestId": request_id,
            },
        )
    finally:
        wide_event["duration_ms"] = int((time.time() - start) * 1000)
        print(json.dumps(wide_event, separators=(",", ":"), sort_keys=True))
