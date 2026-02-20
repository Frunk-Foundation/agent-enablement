from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from boto3.dynamodb.conditions import Attr
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from id58 import uuid4_base58_22
from id58 import uuid7_base58_22


TASKS_TABLE_NAME = os.environ.get("TASKBOARD_TASKS_TABLE", "")
AUDIT_TABLE_NAME = os.environ.get("TASKBOARD_AUDIT_TABLE", "")
SCHEMA_VERSION = os.environ.get("TASKBOARD_SCHEMA_VERSION", "2026-02-16")

BOARD_META_TASK_ID = "__board__"
STATUS_PENDING = "pending"
STATUS_CLAIMED = "claimed"
STATUS_DONE = "done"
STATUS_FAILED = "failed"
VALID_STATUSES = {STATUS_PENDING, STATUS_CLAIMED, STATUS_DONE, STATUS_FAILED}

DEFAULT_PAGE_LIMIT = 25
MAX_PAGE_LIMIT = 100
MAX_BOARD_ID_MATCHES = 10

_ddb_resource: Any | None = None


def _ddb() -> Any:
    global _ddb_resource
    if _ddb_resource is None:
        _ddb_resource = boto3.resource("dynamodb")
    return _ddb_resource


def _tasks_table() -> Any:
    return _ddb().Table(TASKS_TABLE_NAME)


def _audit_table() -> Any:
    return _ddb().Table(AUDIT_TABLE_NAME)


def _now_iso() -> str:
    # Fixed-format UTC timestamp for lexicographic ordering.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _response(status_code: int, body: dict[str, Any], request_id: str) -> dict[str, Any]:
    payload = dict(body)
    payload.setdefault("requestId", request_id)
    payload.setdefault("schemaVersion", SCHEMA_VERSION)
    return {
        "statusCode": int(status_code),
        "headers": {
            "content-type": "application/json",
            "cache-control": "no-store",
        },
        "body": json.dumps(payload),
    }


def _error(status_code: int, code: str, message: str, request_id: str) -> dict[str, Any]:
    return _response(
        status_code,
        {"errorCode": code, "message": message},
        request_id,
    )


def _request_id(event: dict[str, Any]) -> str:
    rc = event.get("requestContext") or {}
    if isinstance(rc, dict):
        rid = str(rc.get("requestId") or "").strip()
        if rid:
            return rid
    return uuid4_base58_22()


def _parse_body(event: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    raw = event.get("body")
    if raw is None:
        return {}, None
    if not isinstance(raw, str):
        return None, "request body must be a JSON object"
    if bool(event.get("isBase64Encoded")):
        try:
            raw_bytes = base64.b64decode(raw.encode("utf-8"))
            raw = raw_bytes.decode("utf-8")
        except Exception:
            return None, "request body base64 decode failed"
    if not raw.strip():
        return {}, None
    try:
        parsed = json.loads(raw)
    except Exception:
        return None, "request body must be valid JSON"
    if not isinstance(parsed, dict):
        return None, "request body must be a JSON object"
    return parsed, None


def _path(event: dict[str, Any]) -> str:
    p = str(event.get("path") or "").strip()
    # Best effort for custom-domain stage prefixes.
    marker = "/v1/taskboard"
    idx = p.find(marker)
    if idx >= 0:
        p = p[idx:]
    return p


def _query_param(event: dict[str, Any], key: str) -> str:
    qs = event.get("queryStringParameters") or {}
    if not isinstance(qs, dict):
        return ""
    val = qs.get(key)
    return str(val).strip() if val is not None else ""


def _decode_next_token(next_token: str) -> dict[str, Any]:
    s = (next_token or "").strip()
    if not s:
        return {}
    padded = s + ("=" * (-len(s) % 4))
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("nextToken must decode to an object")
    return parsed


def _encode_next_token(key: dict[str, Any] | None) -> str:
    if not key:
        return ""
    raw = json.dumps(key, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _page_limit(raw: str) -> int:
    if not raw:
        return DEFAULT_PAGE_LIMIT
    try:
        n = int(raw)
    except Exception:
        return DEFAULT_PAGE_LIMIT
    if n < 1:
        return DEFAULT_PAGE_LIMIT
    return min(n, MAX_PAGE_LIMIT)


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


def _actor(event: dict[str, Any]) -> tuple[str, str]:
    c = _claims(event)
    sub = str(c.get("sub") or "").strip()
    username = str(c.get("cognito:username") or c.get("username") or "").strip()
    if not username:
        username = sub
    return sub, username


def _board_exists(board_id: str) -> bool:
    if not board_id:
        return False
    resp = _tasks_table().get_item(Key={"boardId": board_id, "taskId": BOARD_META_TASK_ID})
    return bool(resp.get("Item"))


def _find_board_id_matches(partial: str, *, max_matches: int = MAX_BOARD_ID_MATCHES) -> list[str]:
    needle = str(partial or "").strip()
    if not needle:
        return []

    out: set[str] = set()
    start_key: dict[str, Any] | None = None
    while True:
        kwargs: dict[str, Any] = {
            "ProjectionExpression": "boardId, taskId",
            "FilterExpression": Attr("taskId").eq(BOARD_META_TASK_ID),
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        page = _tasks_table().scan(**kwargs)
        items = page.get("Items", []) or []
        for item in items:
            if not isinstance(item, dict):
                continue
            board_id = str(item.get("boardId") or "").strip()
            if not board_id:
                continue
            if needle in board_id:
                out.add(board_id)
                if len(out) >= max_matches:
                    return sorted(out)[:max_matches]
        start_key = page.get("LastEvaluatedKey")
        if not start_key:
            break
    return sorted(out)[:max_matches]


def _resolve_board_id_or_error(board_input: str, request_id: str) -> tuple[str | None, dict[str, Any] | None]:
    raw = str(board_input or "").strip()
    if not raw:
        return None, _error(404, "BOARD_NOT_FOUND", "board not found: ", request_id)

    # Fast path for full IDs.
    if _board_exists(raw):
        return raw, None

    matches = _find_board_id_matches(raw)
    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        return None, _response(
            409,
            {
                "errorCode": "AMBIGUOUS_BOARD_ID",
                "message": f"multiple boards match boardId: {raw}",
                "matches": matches,
            },
            request_id,
        )
    return None, _error(404, "BOARD_NOT_FOUND", f"board not found: {raw}", request_id)


def _is_task_item(item: dict[str, Any]) -> bool:
    return str(item.get("taskId") or "") != BOARD_META_TASK_ID


def _task_to_json(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "boardId": str(item.get("boardId") or ""),
        "taskId": str(item.get("taskId") or ""),
        "line": str(item.get("line") or ""),
        "status": str(item.get("status") or ""),
        "addedBy": str(item.get("addedBy") or ""),
        "addedByUsername": str(item.get("addedByUsername") or ""),
        "addedAt": str(item.get("addedAt") or ""),
        "claimedBy": str(item.get("claimedBy") or ""),
        "claimedByUsername": str(item.get("claimedByUsername") or ""),
        "claimedAt": str(item.get("claimedAt") or ""),
        "updatedAt": str(item.get("updatedAt") or ""),
    }


def _audit_to_json(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "boardId": str(item.get("boardId") or ""),
        "taskId": str(item.get("taskId") or ""),
        "action": str(item.get("action") or ""),
        "timestamp": str(item.get("timestamp") or ""),
        "line": str(item.get("line") or ""),
        "actorSub": str(item.get("actorSub") or ""),
        "actorUsername": str(item.get("actorUsername") or ""),
    }


def _write_audit(
    *,
    board_id: str,
    task_id: str,
    action: str,
    line: str,
    actor_sub: str,
    actor_username: str,
) -> None:
    ts = _now_iso()
    _audit_table().put_item(
        Item={
            "boardId": board_id,
            "tsActionTask": f"{ts}#{action}#{task_id}",
            "timestamp": ts,
            "taskId": task_id,
            "action": action,
            "line": line,
            "actorSub": actor_sub,
            "actorUsername": actor_username,
            "actorTsBoardTask": f"{ts}#{board_id}#{task_id}",
        }
    )


def _query_tasks(
    *,
    board_id: str,
    limit: int,
    next_key: dict[str, Any] | None,
    status_filter: str,
    q_filter: str,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    out: list[dict[str, Any]] = []
    start_key = dict(next_key or {})
    q_raw = q_filter
    q_lc = q_filter.lower()
    status = status_filter.lower()
    summary_out: list[dict[str, Any]] = []
    summary_has_more = False
    summary_last_task_id = ""

    def _query_match_kind(item: dict[str, Any]) -> str:
        if not q_raw:
            return "all"
        task_id = str(item.get("taskId") or "")
        if q_raw in task_id:
            return "id"
        line_lc = str(item.get("line") or "").lower()
        if q_lc in line_lc:
            return "summary"
        return ""

    while True:
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("boardId").eq(board_id),
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        page = _tasks_table().query(**kwargs)
        items = page.get("Items", []) or []

        for item in items:
            if not isinstance(item, dict) or not _is_task_item(item):
                continue
            item_status = str(item.get("status") or "").lower()
            if status and item_status != status:
                continue
            match_kind = _query_match_kind(item)
            if not match_kind:
                continue
            if match_kind == "id":
                out.append(_task_to_json(item))
                if len(out) >= limit:
                    return out, {"boardId": board_id, "taskId": str(item.get("taskId") or "")}
                continue
            if out:
                # Once task-id matches exist, ignore summary-only matches.
                continue
            if len(summary_out) < limit:
                summary_out.append(_task_to_json(item))
                summary_last_task_id = str(item.get("taskId") or "")
            else:
                summary_has_more = True

        start_key = page.get("LastEvaluatedKey")
        if not start_key:
            if out:
                return out, None
            if summary_has_more and summary_last_task_id:
                return summary_out, {"boardId": board_id, "taskId": summary_last_task_id}
            return summary_out, None


def _query_audit(
    *,
    board_id: str,
    limit: int,
    next_key: dict[str, Any] | None,
    task_id_filter: str,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    out: list[dict[str, Any]] = []
    start_key = dict(next_key or {})

    while True:
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("boardId").eq(board_id),
            "ScanIndexForward": False,  # newest first
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        page = _audit_table().query(**kwargs)
        items = page.get("Items", []) or []

        for item in items:
            if not isinstance(item, dict):
                continue
            if task_id_filter and str(item.get("taskId") or "") != task_id_filter:
                continue
            out.append(_audit_to_json(item))
            if len(out) >= limit:
                return out, {
                    "boardId": board_id,
                    "tsActionTask": str(item.get("tsActionTask") or ""),
                }

        start_key = page.get("LastEvaluatedKey")
        if not start_key:
            return out, None


def _query_activity(
    *,
    actor_sub: str,
    board_filter: str,
    limit: int,
    next_key: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    out: list[dict[str, Any]] = []
    start_key = dict(next_key or {})

    while True:
        kwargs: dict[str, Any] = {
            "IndexName": "ActorTimeIndex",
            "KeyConditionExpression": Key("actorSub").eq(actor_sub),
            "ScanIndexForward": False,  # newest first
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        page = _audit_table().query(**kwargs)
        items = page.get("Items", []) or []

        for item in items:
            if not isinstance(item, dict):
                continue
            if board_filter and str(item.get("boardId") or "") != board_filter:
                continue
            out.append(_audit_to_json(item))
            if len(out) >= limit:
                return out, {
                    "boardId": str(item.get("boardId") or ""),
                    "tsActionTask": str(item.get("tsActionTask") or ""),
                    "actorSub": str(item.get("actorSub") or ""),
                    "actorTsBoardTask": str(item.get("actorTsBoardTask") or ""),
                }

        start_key = page.get("LastEvaluatedKey")
        if not start_key:
            return out, None


def _find_task_by_query(
    *,
    board_id: str,
    q: str,
    actor_sub: str,
    statuses: set[str] | None,
    require_claimed_by_actor: bool,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    q_raw = q
    q_lc = q.lower()
    id_matches: list[dict[str, Any]] = []
    summary_matches: list[dict[str, Any]] = []
    start_key: dict[str, Any] | None = None

    while True:
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("boardId").eq(board_id),
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        page = _tasks_table().query(**kwargs)
        items = page.get("Items", []) or []

        for item in items:
            if not isinstance(item, dict) or not _is_task_item(item):
                continue
            status = str(item.get("status") or "").lower()
            if statuses and status not in statuses:
                continue
            if require_claimed_by_actor and str(item.get("claimedBy") or "") != actor_sub:
                continue
            task_id = str(item.get("taskId") or "")
            if q_raw in task_id:
                id_matches.append(item)
                continue
            line_lc = str(item.get("line") or "").lower()
            if q_lc in line_lc:
                summary_matches.append(item)

        start_key = page.get("LastEvaluatedKey")
        if not start_key:
            break

    matches = id_matches or summary_matches
    if not matches:
        return None, []
    if len(matches) > 1:
        return None, [_task_to_json(m) for m in matches[:10]]
    return matches[0], []


def _update_task(
    *,
    board_id: str,
    task_id: str,
    action: str,
    new_status: str,
    actor_sub: str,
    actor_username: str,
) -> tuple[dict[str, Any] | None, str | None]:
    now = _now_iso()
    expr_names = {"#status": "status"}
    expr_values: dict[str, Any] = {
        ":newStatus": new_status,
        ":now": now,
    }
    condition = None

    if action == "claim":
        update_expr = (
            "SET #status = :newStatus, updatedAt = :now, "
            "claimedBy = :actorSub, claimedByUsername = :actorUsername, claimedAt = :now"
        )
        expr_values[":actorSub"] = actor_sub
        expr_values[":actorUsername"] = actor_username
        expr_values[":pending"] = STATUS_PENDING
        condition = "#status = :pending"
    elif action == "unclaim":
        update_expr = "SET #status = :newStatus, updatedAt = :now REMOVE claimedBy, claimedByUsername, claimedAt"
        expr_values[":claimed"] = STATUS_CLAIMED
        expr_values[":actorSub"] = actor_sub
        condition = "#status = :claimed AND claimedBy = :actorSub"
    else:
        update_expr = "SET #status = :newStatus, updatedAt = :now"

    kwargs: dict[str, Any] = {
        "Key": {"boardId": board_id, "taskId": task_id},
        "UpdateExpression": update_expr,
        "ExpressionAttributeNames": expr_names,
        "ExpressionAttributeValues": expr_values,
        "ReturnValues": "ALL_NEW",
    }
    if condition:
        kwargs["ConditionExpression"] = condition

    try:
        out = _tasks_table().update_item(**kwargs)
    except ClientError as e:
        code = str(e.response.get("Error", {}).get("Code") or "")
        if code == "ConditionalCheckFailedException":
            return None, "conflict"
        raise
    return out.get("Attributes") or {}, None


def _create_board(event: dict[str, Any], request_id: str) -> dict[str, Any]:
    actor_sub, actor_username = _actor(event)
    if not actor_sub:
        return _error(401, "UNAUTHORIZED", "missing authorizer claims", request_id)

    body, err = _parse_body(event)
    if err:
        return _error(400, "INVALID_BODY", err, request_id)
    assert body is not None

    name = str(body.get("name") or "").strip()
    board_id = uuid4_base58_22()
    now = _now_iso()
    _tasks_table().put_item(
        Item={
            "boardId": board_id,
            "taskId": BOARD_META_TASK_ID,
            "itemType": "board",
            "name": name,
            "createdBy": actor_sub,
            "createdByUsername": actor_username,
            "createdAt": now,
            "updatedAt": now,
        }
    )

    return _response(
        201,
        {
            "boardId": board_id,
            "name": name,
            "createdAt": now,
        },
        request_id,
    )


def _add_tasks(event: dict[str, Any], request_id: str, board_id: str) -> dict[str, Any]:
    actor_sub, actor_username = _actor(event)
    if not actor_sub:
        return _error(401, "UNAUTHORIZED", "missing authorizer claims", request_id)
    if not _board_exists(board_id):
        return _error(404, "BOARD_NOT_FOUND", f"board not found: {board_id}", request_id)

    body, err = _parse_body(event)
    if err:
        return _error(400, "INVALID_BODY", err, request_id)
    assert body is not None

    lines = body.get("lines")
    if not isinstance(lines, list):
        return _error(400, "INVALID_BODY", "request body must include lines[]", request_id)

    normalized: list[str] = []
    for line in lines:
        s = str(line).strip()
        if s:
            normalized.append(s)
    if not normalized:
        return _error(400, "INVALID_BODY", "lines[] must include at least one non-empty line", request_id)

    now = _now_iso()
    items: list[dict[str, Any]] = []
    for line in normalized:
        task_id = uuid7_base58_22()
        items.append(
            {
                "boardId": board_id,
                "taskId": task_id,
                "itemType": "task",
                "line": line,
                "status": STATUS_PENDING,
                "addedBy": actor_sub,
                "addedByUsername": actor_username,
                "addedAt": now,
                "updatedAt": now,
            }
        )

    with _tasks_table().batch_writer() as batch:
        for item in items:
            batch.put_item(Item=item)

    for item in items:
        _write_audit(
            board_id=board_id,
            task_id=str(item["taskId"]),
            action="added",
            line=str(item["line"]),
            actor_sub=actor_sub,
            actor_username=actor_username,
        )

    return _response(
        201,
        {
            "boardId": board_id,
            "added": len(items),
            "taskIds": [str(i["taskId"]) for i in items],
        },
        request_id,
    )


def _list_tasks(event: dict[str, Any], request_id: str, board_id: str) -> dict[str, Any]:
    if not _board_exists(board_id):
        return _error(404, "BOARD_NOT_FOUND", f"board not found: {board_id}", request_id)

    limit = _page_limit(_query_param(event, "limit"))
    q_filter = _query_param(event, "q")
    status_filter = _query_param(event, "status")
    if status_filter and status_filter.lower() not in VALID_STATUSES:
        return _error(400, "INVALID_STATUS", f"invalid status: {status_filter}", request_id)

    try:
        next_key = _decode_next_token(_query_param(event, "nextToken"))
    except Exception:
        return _error(400, "INVALID_NEXT_TOKEN", "invalid nextToken", request_id)

    items, next_out = _query_tasks(
        board_id=board_id,
        limit=limit,
        next_key=next_key,
        status_filter=status_filter,
        q_filter=q_filter,
    )
    return _response(
        200,
        {
            "items": items,
            "nextToken": _encode_next_token(next_out),
            "limit": limit,
        },
        request_id,
    )


def _mutate_task(event: dict[str, Any], request_id: str, board_id: str, action: str) -> dict[str, Any]:
    actor_sub, actor_username = _actor(event)
    if not actor_sub:
        return _error(401, "UNAUTHORIZED", "missing authorizer claims", request_id)
    if not _board_exists(board_id):
        return _error(404, "BOARD_NOT_FOUND", f"board not found: {board_id}", request_id)

    body, err = _parse_body(event)
    if err:
        return _error(400, "INVALID_BODY", err, request_id)
    assert body is not None

    task_id = str(body.get("taskId") or "").strip()
    q = str(body.get("q") or "").strip()
    if not task_id and not q:
        return _error(400, "INVALID_BODY", "provide taskId or q", request_id)

    selected: dict[str, Any] | None = None
    if task_id:
        got = _tasks_table().get_item(Key={"boardId": board_id, "taskId": task_id})
        selected = got.get("Item") if isinstance(got, dict) else None
        if not selected or not _is_task_item(selected):
            return _error(404, "TASK_NOT_FOUND", f"task not found: {task_id}", request_id)
    else:
        if action == "claim":
            status_filter = {STATUS_PENDING}
            claimed_filter = False
        elif action == "unclaim":
            status_filter = {STATUS_CLAIMED}
            claimed_filter = True
        else:
            status_filter = None
            claimed_filter = False

        selected, ambiguous = _find_task_by_query(
            board_id=board_id,
            q=q,
            actor_sub=actor_sub,
            statuses=status_filter,
            require_claimed_by_actor=claimed_filter,
        )
        if ambiguous:
            return _response(
                409,
                {
                    "errorCode": "AMBIGUOUS_QUERY",
                    "message": f"multiple tasks match query: {q}",
                    "matches": ambiguous,
                },
                request_id,
            )
        if not selected:
            return _error(404, "TASK_NOT_FOUND", f"no task matches query: {q}", request_id)

    assert selected is not None
    selected_task_id = str(selected.get("taskId") or "")
    selected_line = str(selected.get("line") or "")

    if action == "claim":
        new_status = STATUS_CLAIMED
    elif action == "unclaim":
        new_status = STATUS_PENDING
    elif action == "done":
        new_status = STATUS_DONE
    elif action == "fail":
        new_status = STATUS_FAILED
    else:
        return _error(400, "INVALID_ACTION", f"unsupported action: {action}", request_id)

    try:
        updated, update_err = _update_task(
            board_id=board_id,
            task_id=selected_task_id,
            action=action,
            new_status=new_status,
            actor_sub=actor_sub,
            actor_username=actor_username,
        )
    except ClientError as e:
        return _error(500, "DDB_ERROR", str(e), request_id)

    if update_err == "conflict":
        return _error(
            409,
            "TASK_CONFLICT",
            f"task changed before {action} completed: {selected_task_id}",
            request_id,
        )
    if not updated:
        return _error(500, "UPDATE_FAILED", "task update returned no attributes", request_id)

    audit_action = {
        "claim": "claimed",
        "unclaim": "unclaimed",
        "done": "done",
        "fail": "failed",
    }[action]
    _write_audit(
        board_id=board_id,
        task_id=selected_task_id,
        action=audit_action,
        line=selected_line,
        actor_sub=actor_sub,
        actor_username=actor_username,
    )

    return _response(
        200,
        {
            "task": _task_to_json(updated),
        },
        request_id,
    )


def _board_status(event: dict[str, Any], request_id: str, board_id: str) -> dict[str, Any]:
    if not _board_exists(board_id):
        return _error(404, "BOARD_NOT_FOUND", f"board not found: {board_id}", request_id)

    counts = {
        STATUS_PENDING: 0,
        STATUS_CLAIMED: 0,
        STATUS_DONE: 0,
        STATUS_FAILED: 0,
    }
    total = 0
    start_key: dict[str, Any] | None = None

    while True:
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("boardId").eq(board_id),
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        page = _tasks_table().query(**kwargs)
        for item in page.get("Items", []) or []:
            if not isinstance(item, dict) or not _is_task_item(item):
                continue
            status = str(item.get("status") or STATUS_PENDING).lower()
            if status not in counts:
                status = STATUS_PENDING
            counts[status] += 1
            total += 1
        start_key = page.get("LastEvaluatedKey")
        if not start_key:
            break

    meta = _tasks_table().get_item(Key={"boardId": board_id, "taskId": BOARD_META_TASK_ID}).get("Item") or {}
    return _response(
        200,
        {
            "boardId": board_id,
            "name": str(meta.get("name") or ""),
            "total": total,
            STATUS_PENDING: counts[STATUS_PENDING],
            STATUS_CLAIMED: counts[STATUS_CLAIMED],
            STATUS_DONE: counts[STATUS_DONE],
            STATUS_FAILED: counts[STATUS_FAILED],
        },
        request_id,
    )


def _board_audit(event: dict[str, Any], request_id: str, board_id: str) -> dict[str, Any]:
    if not _board_exists(board_id):
        return _error(404, "BOARD_NOT_FOUND", f"board not found: {board_id}", request_id)

    task_id_filter = _query_param(event, "taskId")
    limit = _page_limit(_query_param(event, "limit"))
    try:
        next_key = _decode_next_token(_query_param(event, "nextToken"))
    except Exception:
        return _error(400, "INVALID_NEXT_TOKEN", "invalid nextToken", request_id)

    items, next_out = _query_audit(
        board_id=board_id,
        limit=limit,
        next_key=next_key,
        task_id_filter=task_id_filter,
    )
    return _response(
        200,
        {
            "items": items,
            "nextToken": _encode_next_token(next_out),
            "limit": limit,
        },
        request_id,
    )


def _my_activity(event: dict[str, Any], request_id: str, board_filter: str) -> dict[str, Any]:
    actor_sub, _actor_username = _actor(event)
    if not actor_sub:
        return _error(401, "UNAUTHORIZED", "missing authorizer claims", request_id)

    limit = _page_limit(_query_param(event, "limit"))
    try:
        next_key = _decode_next_token(_query_param(event, "nextToken"))
    except Exception:
        return _error(400, "INVALID_NEXT_TOKEN", "invalid nextToken", request_id)

    items, next_out = _query_activity(
        actor_sub=actor_sub,
        board_filter=board_filter,
        limit=limit,
        next_key=next_key,
    )
    return _response(
        200,
        {
            "items": items,
            "nextToken": _encode_next_token(next_out),
            "limit": limit,
        },
        request_id,
    )


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    request_id = _request_id(event)

    if not TASKS_TABLE_NAME or not AUDIT_TABLE_NAME:
        return _error(500, "MISCONFIGURED", "taskboard table env vars are required", request_id)

    method = str(event.get("httpMethod") or "").upper()
    path = _path(event)
    segments = [s for s in path.split("/") if s]

    try:
        # /v1/taskboard/boards
        if method == "POST" and segments == ["v1", "taskboard", "boards"]:
            return _create_board(event, request_id)

        # /v1/taskboard/boards/{boardId}/tasks
        if (
            len(segments) == 5
            and segments[0] == "v1"
            and segments[1] == "taskboard"
            and segments[2] == "boards"
            and segments[4] == "tasks"
        ):
            board_id, board_err = _resolve_board_id_or_error(segments[3], request_id)
            if board_err:
                return board_err
            assert board_id is not None
            if method == "POST":
                return _add_tasks(event, request_id, board_id)
            if method == "GET":
                return _list_tasks(event, request_id, board_id)

        # /v1/taskboard/boards/{boardId}/tasks/{action}
        if (
            method == "PATCH"
            and len(segments) == 6
            and segments[0] == "v1"
            and segments[1] == "taskboard"
            and segments[2] == "boards"
            and segments[4] == "tasks"
            and segments[5] in {"claim", "unclaim", "done", "fail"}
        ):
            board_id, board_err = _resolve_board_id_or_error(segments[3], request_id)
            if board_err:
                return board_err
            assert board_id is not None
            return _mutate_task(event, request_id, board_id, segments[5])

        # /v1/taskboard/boards/{boardId}/status
        if (
            method == "GET"
            and len(segments) == 5
            and segments[0] == "v1"
            and segments[1] == "taskboard"
            and segments[2] == "boards"
            and segments[4] == "status"
        ):
            board_id, board_err = _resolve_board_id_or_error(segments[3], request_id)
            if board_err:
                return board_err
            assert board_id is not None
            return _board_status(event, request_id, board_id)

        # /v1/taskboard/boards/{boardId}/audit
        if (
            method == "GET"
            and len(segments) == 5
            and segments[0] == "v1"
            and segments[1] == "taskboard"
            and segments[2] == "boards"
            and segments[4] == "audit"
        ):
            board_id, board_err = _resolve_board_id_or_error(segments[3], request_id)
            if board_err:
                return board_err
            assert board_id is not None
            return _board_audit(event, request_id, board_id)

        # /v1/taskboard/my/activity
        if method == "GET" and segments == ["v1", "taskboard", "my", "activity"]:
            return _my_activity(event, request_id, board_filter="")

        # /v1/taskboard/my/activity/{boardId}
        if (
            method == "GET"
            and len(segments) == 5
            and segments[0] == "v1"
            and segments[1] == "taskboard"
            and segments[2] == "my"
            and segments[3] == "activity"
        ):
            board_id, board_err = _resolve_board_id_or_error(segments[4], request_id)
            if board_err:
                return board_err
            assert board_id is not None
            return _my_activity(event, request_id, board_filter=board_id)

        return _error(404, "NOT_FOUND", f"route not found: {method} {path}", request_id)
    except ClientError as e:
        return _error(500, "DDB_ERROR", str(e), request_id)
    except Exception as e:
        return _error(500, "INTERNAL_ERROR", str(e), request_id)
