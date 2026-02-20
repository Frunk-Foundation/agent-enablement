import importlib
import json
import re
import sys


def _load_handler(monkeypatch):
    monkeypatch.setenv("TASKBOARD_TASKS_TABLE", "TaskboardTasks")
    monkeypatch.setenv("TASKBOARD_AUDIT_TABLE", "TaskboardAudit")
    monkeypatch.setenv("TASKBOARD_SCHEMA_VERSION", "2026-02-16")
    if "lambda" not in sys.path:
        sys.path.insert(0, "lambda")
    import taskboard_handler as mod

    return importlib.reload(mod)


def _claims_event(*, method: str, path: str, body: dict | None = None, qs: dict | None = None):
    return {
        "httpMethod": method,
        "path": path,
        "body": json.dumps(body) if body is not None else None,
        "queryStringParameters": qs or None,
        "requestContext": {
            "requestId": "req-1",
            "authorizer": {
                "claims": {
                    "sub": "sub-1",
                    "cognito:username": "agent-1",
                }
            },
        },
    }


def test_create_board_route_returns_201(monkeypatch):
    mod = _load_handler(monkeypatch)
    captured: dict = {}

    class FakeTasks:
        def put_item(self, *, Item):
            captured["item"] = Item

    monkeypatch.setattr(mod, "_tasks_table", lambda: FakeTasks())

    event = _claims_event(
        method="POST",
        path="/v1/taskboard/boards",
        body={"name": "alpha"},
    )
    out = mod.handler(event, None)
    body = json.loads(out["body"])

    assert int(out["statusCode"]) == 201
    assert body["name"] == "alpha"
    assert body["requestId"] == "req-1"
    assert re.match(r"^[1-9A-HJ-NP-Za-km-z]{22}$", str(body.get("boardId") or ""))
    assert captured["item"]["taskId"] == "__board__"
    assert re.match(r"^[1-9A-HJ-NP-Za-km-z]{22}$", str(captured["item"].get("boardId") or ""))
    assert captured["item"]["createdBy"] == "sub-1"


def test_list_tasks_uses_pagination_contract(monkeypatch):
    mod = _load_handler(monkeypatch)
    captured: dict = {}

    monkeypatch.setattr(mod, "_board_exists", lambda board_id: True)

    def fake_query_tasks(**kwargs):
        captured.update(kwargs)
        return (
            [
                {
                    "boardId": "board-1",
                    "taskId": "task-1",
                    "line": "do thing",
                    "status": "pending",
                }
            ],
            {"boardId": "board-1", "taskId": "task-1"},
        )

    monkeypatch.setattr(mod, "_query_tasks", fake_query_tasks)

    event = _claims_event(
        method="GET",
        path="/v1/taskboard/boards/board-1/tasks",
        qs={"limit": "10", "q": "do"},
    )
    out = mod.handler(event, None)
    body = json.loads(out["body"])

    assert int(out["statusCode"]) == 200
    assert body["limit"] == 10
    assert body["items"][0]["taskId"] == "task-1"
    assert body["nextToken"]
    assert captured["board_id"] == "board-1"
    assert captured["q_filter"] == "do"


def test_list_tasks_rejects_invalid_next_token(monkeypatch):
    mod = _load_handler(monkeypatch)
    monkeypatch.setattr(mod, "_board_exists", lambda board_id: True)

    event = _claims_event(
        method="GET",
        path="/v1/taskboard/boards/board-1/tasks",
        qs={"nextToken": "%%%not-base64%%%"},
    )
    out = mod.handler(event, None)
    body = json.loads(out["body"])

    assert int(out["statusCode"]) == 400
    assert body["errorCode"] == "INVALID_NEXT_TOKEN"


def test_mutation_prefers_task_id_over_query(monkeypatch):
    mod = _load_handler(monkeypatch)
    captured: dict = {"audit": False}
    monkeypatch.setattr(mod, "_board_exists", lambda board_id: True)

    class FakeTasks:
        def get_item(self, *, Key):
            assert Key["taskId"] == "task-1"
            return {
                "Item": {
                    "boardId": "board-1",
                    "taskId": "task-1",
                    "line": "line one",
                    "status": "pending",
                }
            }

    monkeypatch.setattr(mod, "_tasks_table", lambda: FakeTasks())

    def fake_update_task(**kwargs):
        captured["update"] = kwargs
        return (
            {
                "boardId": "board-1",
                "taskId": "task-1",
                "line": "line one",
                "status": "claimed",
                "updatedAt": "2026-02-16T00:00:00.000000Z",
            },
            None,
        )

    monkeypatch.setattr(mod, "_update_task", fake_update_task)

    def fake_write_audit(**kwargs):
        captured["audit"] = True
        captured["audit_kwargs"] = kwargs

    monkeypatch.setattr(mod, "_write_audit", fake_write_audit)

    event = _claims_event(
        method="PATCH",
        path="/v1/taskboard/boards/board-1/tasks/claim",
        body={"taskId": "task-1", "q": "ignored"},
    )
    out = mod.handler(event, None)
    body = json.loads(out["body"])

    assert int(out["statusCode"]) == 200
    assert body["task"]["status"] == "claimed"
    assert captured["update"]["task_id"] == "task-1"
    assert captured["audit"] is True
    assert captured["audit_kwargs"]["action"] == "claimed"


def test_update_task_done_and_fail_do_not_send_actor_sub_expr_value(monkeypatch):
    mod = _load_handler(monkeypatch)
    captured_calls: list[dict] = []

    class FakeTasks:
        def update_item(self, **kwargs):
            captured_calls.append(kwargs)
            return {
                "Attributes": {
                    "boardId": "board-1",
                    "taskId": "task-1",
                    "status": kwargs["ExpressionAttributeValues"][":newStatus"],
                    "updatedAt": "2026-02-16T00:00:00.000000Z",
                }
            }

    monkeypatch.setattr(mod, "_tasks_table", lambda: FakeTasks())

    updated_done, err_done = mod._update_task(
        board_id="board-1",
        task_id="task-1",
        action="done",
        new_status=mod.STATUS_DONE,
        actor_sub="sub-1",
        actor_username="agent-1",
    )
    updated_fail, err_fail = mod._update_task(
        board_id="board-1",
        task_id="task-1",
        action="fail",
        new_status=mod.STATUS_FAILED,
        actor_sub="sub-1",
        actor_username="agent-1",
    )

    assert err_done is None
    assert err_fail is None
    assert updated_done is not None
    assert updated_fail is not None
    assert len(captured_calls) == 2
    for call in captured_calls:
        expr_values = call["ExpressionAttributeValues"]
        assert ":newStatus" in expr_values
        assert ":now" in expr_values
        assert ":actorSub" not in expr_values
        assert "ConditionExpression" not in call


def test_update_task_claim_and_unclaim_keep_actor_sub_requirements(monkeypatch):
    mod = _load_handler(monkeypatch)
    captured_calls: list[dict] = []

    class FakeTasks:
        def update_item(self, **kwargs):
            captured_calls.append(kwargs)
            return {
                "Attributes": {
                    "boardId": "board-1",
                    "taskId": "task-1",
                    "status": kwargs["ExpressionAttributeValues"][":newStatus"],
                    "updatedAt": "2026-02-16T00:00:00.000000Z",
                }
            }

    monkeypatch.setattr(mod, "_tasks_table", lambda: FakeTasks())

    _, claim_err = mod._update_task(
        board_id="board-1",
        task_id="task-1",
        action="claim",
        new_status=mod.STATUS_CLAIMED,
        actor_sub="sub-1",
        actor_username="agent-1",
    )
    _, unclaim_err = mod._update_task(
        board_id="board-1",
        task_id="task-1",
        action="unclaim",
        new_status=mod.STATUS_PENDING,
        actor_sub="sub-1",
        actor_username="agent-1",
    )

    assert claim_err is None
    assert unclaim_err is None
    assert len(captured_calls) == 2

    claim_call, unclaim_call = captured_calls
    claim_values = claim_call["ExpressionAttributeValues"]
    assert ":actorSub" in claim_values
    assert ":actorUsername" in claim_values
    assert ":pending" in claim_values
    assert claim_call["ConditionExpression"] == "#status = :pending"

    unclaim_values = unclaim_call["ExpressionAttributeValues"]
    assert ":actorSub" in unclaim_values
    assert ":claimed" in unclaim_values
    assert unclaim_call["ConditionExpression"] == "#status = :claimed AND claimedBy = :actorSub"


def test_done_and_fail_routes_do_not_return_500_for_expr_value_mismatch(monkeypatch):
    mod = _load_handler(monkeypatch)
    monkeypatch.setattr(mod, "_board_exists", lambda _board_id: True)
    audit_actions: list[str] = []

    class FakeTasks:
        def get_item(self, *, Key):
            return {
                "Item": {
                    "boardId": "board-1",
                    "taskId": Key["taskId"],
                    "line": "line one",
                    "status": "claimed",
                }
            }

        def update_item(self, **kwargs):
            expr_values = kwargs["ExpressionAttributeValues"]
            # Regression guard: done/fail must not carry unused :actorSub.
            assert ":actorSub" not in expr_values
            return {
                "Attributes": {
                    "boardId": "board-1",
                    "taskId": kwargs["Key"]["taskId"],
                    "line": "line one",
                    "status": expr_values[":newStatus"],
                    "updatedAt": "2026-02-16T00:00:00.000000Z",
                }
            }

    monkeypatch.setattr(mod, "_tasks_table", lambda: FakeTasks())
    monkeypatch.setattr(mod, "_write_audit", lambda **kwargs: audit_actions.append(str(kwargs.get("action") or "")))

    done_event = _claims_event(
        method="PATCH",
        path="/v1/taskboard/boards/board-1/tasks/done",
        body={"taskId": "task-1"},
    )
    fail_event = _claims_event(
        method="PATCH",
        path="/v1/taskboard/boards/board-1/tasks/fail",
        body={"taskId": "task-2"},
    )

    done_out = mod.handler(done_event, None)
    fail_out = mod.handler(fail_event, None)
    done_body = json.loads(done_out["body"])
    fail_body = json.loads(fail_out["body"])

    assert int(done_out["statusCode"]) == 200
    assert int(fail_out["statusCode"]) == 200
    assert done_body["task"]["status"] == "done"
    assert fail_body["task"]["status"] == "failed"
    assert audit_actions == ["done", "failed"]


def test_query_tasks_prefers_task_id_matches_over_summary(monkeypatch):
    mod = _load_handler(monkeypatch)

    class FakeTasks:
        def query(self, **kwargs):
            _ = kwargs
            return {
                "Items": [
                    {
                        "boardId": "board-1",
                        "taskId": "task-aaa-e74292623aa8",
                        "line": "short summary",
                        "status": "pending",
                        "updatedAt": "2026-02-18T00:00:00.000000Z",
                    },
                    {
                        "boardId": "board-1",
                        "taskId": "task-bbb",
                        "line": "contains e74292623aa8 in summary text",
                        "status": "pending",
                        "updatedAt": "2026-02-18T00:00:00.000000Z",
                    },
                ]
            }

    monkeypatch.setattr(mod, "_tasks_table", lambda: FakeTasks())
    items, next_key = mod._query_tasks(
        board_id="board-1",
        limit=25,
        next_key=None,
        status_filter="",
        q_filter="e74292623aa8",
    )
    assert next_key is None
    assert len(items) == 1
    assert items[0]["taskId"] == "task-aaa-e74292623aa8"


def test_find_task_by_query_prefers_task_id_over_summary(monkeypatch):
    mod = _load_handler(monkeypatch)

    class FakeTasks:
        def query(self, **kwargs):
            _ = kwargs
            return {
                "Items": [
                    {
                        "boardId": "board-1",
                        "taskId": "task-summary",
                        "line": "contains partial-id e74292623aa8 in summary",
                        "status": "pending",
                    },
                    {
                        "boardId": "board-1",
                        "taskId": "task-id-e74292623aa8",
                        "line": "other summary",
                        "status": "pending",
                    },
                ]
            }

    monkeypatch.setattr(mod, "_tasks_table", lambda: FakeTasks())
    selected, ambiguous = mod._find_task_by_query(
        board_id="board-1",
        q="e74292623aa8",
        actor_sub="sub-1",
        statuses={mod.STATUS_PENDING},
        require_claimed_by_actor=False,
    )
    assert ambiguous == []
    assert selected is not None
    assert selected["taskId"] == "task-id-e74292623aa8"


def test_find_task_by_query_falls_back_to_summary_when_no_id_match(monkeypatch):
    mod = _load_handler(monkeypatch)

    class FakeTasks:
        def query(self, **kwargs):
            _ = kwargs
            return {
                "Items": [
                    {
                        "boardId": "board-1",
                        "taskId": "task-1",
                        "line": "hello query-token world",
                        "status": "pending",
                    }
                ]
            }

    monkeypatch.setattr(mod, "_tasks_table", lambda: FakeTasks())
    selected, ambiguous = mod._find_task_by_query(
        board_id="board-1",
        q="query-token",
        actor_sub="sub-1",
        statuses={mod.STATUS_PENDING},
        require_claimed_by_actor=False,
    )
    assert ambiguous == []
    assert selected is not None
    assert selected["taskId"] == "task-1"


def test_my_activity_board_route_passes_board_filter(monkeypatch):
    mod = _load_handler(monkeypatch)
    captured: dict = {}
    monkeypatch.setattr(mod, "_resolve_board_id_or_error", lambda _raw, _rid: ("board-9", None))

    def fake_query_activity(**kwargs):
        captured.update(kwargs)
        return (
            [
                {
                    "boardId": "board-9",
                    "taskId": "task-1",
                    "action": "done",
                    "timestamp": "2026-02-16T00:00:00.000000Z",
                }
            ],
            None,
        )

    monkeypatch.setattr(mod, "_query_activity", fake_query_activity)

    event = _claims_event(
        method="GET",
        path="/v1/taskboard/my/activity/board-9",
        qs={"limit": "5"},
    )
    out = mod.handler(event, None)
    body = json.loads(out["body"])

    assert int(out["statusCode"]) == 200
    assert body["items"][0]["boardId"] == "board-9"
    assert captured["board_filter"] == "board-9"


def test_resolve_board_id_or_error_returns_exact_id_when_present(monkeypatch):
    mod = _load_handler(monkeypatch)
    monkeypatch.setattr(mod, "_board_exists", lambda board_id: board_id == "board-exact")
    monkeypatch.setattr(mod, "_find_board_id_matches", lambda _partial: ["board-other"])
    resolved, err = mod._resolve_board_id_or_error("board-exact", "req-1")
    assert err is None
    assert resolved == "board-exact"


def test_resolve_board_id_or_error_resolves_unique_partial(monkeypatch):
    mod = _load_handler(monkeypatch)
    monkeypatch.setattr(mod, "_board_exists", lambda _board_id: False)
    monkeypatch.setattr(mod, "_find_board_id_matches", lambda _partial: ["board-11111111-2222-3333-4444-555555555555"])
    resolved, err = mod._resolve_board_id_or_error("11111111", "req-1")
    assert err is None
    assert resolved == "board-11111111-2222-3333-4444-555555555555"


def test_resolve_board_id_or_error_returns_ambiguous_board_id(monkeypatch):
    mod = _load_handler(monkeypatch)
    monkeypatch.setattr(mod, "_board_exists", lambda _board_id: False)
    monkeypatch.setattr(
        mod,
        "_find_board_id_matches",
        lambda _partial: [
            "board-11111111-2222-3333-4444-555555555555",
            "board-11111111-aaaa-bbbb-cccc-dddddddddddd",
        ],
    )
    resolved, err = mod._resolve_board_id_or_error("11111111", "req-1")
    assert resolved is None
    assert err is not None
    body = json.loads(err["body"])
    assert int(err["statusCode"]) == 409
    assert body["errorCode"] == "AMBIGUOUS_BOARD_ID"
    assert body["matches"] == [
        "board-11111111-2222-3333-4444-555555555555",
        "board-11111111-aaaa-bbbb-cccc-dddddddddddd",
    ]


def test_resolve_board_id_or_error_returns_not_found(monkeypatch):
    mod = _load_handler(monkeypatch)
    monkeypatch.setattr(mod, "_board_exists", lambda _board_id: False)
    monkeypatch.setattr(mod, "_find_board_id_matches", lambda _partial: [])
    resolved, err = mod._resolve_board_id_or_error("nope", "req-1")
    assert resolved is None
    assert err is not None
    body = json.loads(err["body"])
    assert int(err["statusCode"]) == 404
    assert body["errorCode"] == "BOARD_NOT_FOUND"


def test_find_board_id_matches_is_case_sensitive(monkeypatch):
    mod = _load_handler(monkeypatch)

    class FakeTasks:
        def scan(self, **kwargs):
            _ = kwargs
            return {
                "Items": [
                    {"boardId": "AbCdEf1234567890123456", "taskId": mod.BOARD_META_TASK_ID},
                    {"boardId": "abcDEF1234567890123456", "taskId": mod.BOARD_META_TASK_ID},
                ]
            }

    monkeypatch.setattr(mod, "_tasks_table", lambda: FakeTasks())
    assert mod._find_board_id_matches("AbC") == ["AbCdEf1234567890123456"]
    assert mod._find_board_id_matches("abc") == ["abcDEF1234567890123456"]


def test_find_task_by_query_uses_case_sensitive_id_matching(monkeypatch):
    mod = _load_handler(monkeypatch)

    class FakeTasks:
        def query(self, **kwargs):
            _ = kwargs
            return {
                "Items": [
                    {
                        "boardId": "board-1",
                        "taskId": "AbCdE12345678901234567",
                        "line": "no token here",
                        "status": "pending",
                    },
                    {
                        "boardId": "board-1",
                        "taskId": "task-summary",
                        "line": "contains abcde in summary",
                        "status": "pending",
                    },
                ]
            }

    monkeypatch.setattr(mod, "_tasks_table", lambda: FakeTasks())

    selected, ambiguous = mod._find_task_by_query(
        board_id="board-1",
        q="abcde",
        actor_sub="sub-1",
        statuses={mod.STATUS_PENDING},
        require_claimed_by_actor=False,
    )
    assert ambiguous == []
    assert selected is not None
    assert selected["taskId"] == "task-summary"

    selected, ambiguous = mod._find_task_by_query(
        board_id="board-1",
        q="AbCdE",
        actor_sub="sub-1",
        statuses={mod.STATUS_PENDING},
        require_claimed_by_actor=False,
    )
    assert ambiguous == []
    assert selected is not None
    assert selected["taskId"] == "AbCdE12345678901234567"


def test_list_route_resolves_partial_board_id_before_handler(monkeypatch):
    mod = _load_handler(monkeypatch)
    captured: dict = {}

    monkeypatch.setattr(mod, "_resolve_board_id_or_error", lambda _raw, _rid: ("board-full", None))

    def fake_list(event, request_id, board_id):
        captured["board_id"] = board_id
        return mod._response(200, {"ok": True}, request_id)

    monkeypatch.setattr(mod, "_list_tasks", fake_list)
    out = mod.handler(_claims_event(method="GET", path="/v1/taskboard/boards/abc/tasks"), None)
    body = json.loads(out["body"])
    assert int(out["statusCode"]) == 200
    assert body["ok"] is True
    assert captured["board_id"] == "board-full"


def test_add_route_resolves_partial_board_id_before_handler(monkeypatch):
    mod = _load_handler(monkeypatch)
    captured: dict = {}

    monkeypatch.setattr(mod, "_resolve_board_id_or_error", lambda _raw, _rid: ("board-full", None))

    def fake_add(event, request_id, board_id):
        captured["board_id"] = board_id
        return mod._response(200, {"ok": True}, request_id)

    monkeypatch.setattr(mod, "_add_tasks", fake_add)
    out = mod.handler(_claims_event(method="POST", path="/v1/taskboard/boards/abc/tasks", body={"lines": ["x"]}), None)
    body = json.loads(out["body"])
    assert int(out["statusCode"]) == 200
    assert body["ok"] is True
    assert captured["board_id"] == "board-full"


def test_mutate_route_resolves_partial_board_id_before_handler(monkeypatch):
    mod = _load_handler(monkeypatch)
    captured: dict = {}

    monkeypatch.setattr(mod, "_resolve_board_id_or_error", lambda _raw, _rid: ("board-full", None))

    def fake_mutate(event, request_id, board_id, action):
        captured["board_id"] = board_id
        captured["action"] = action
        return mod._response(200, {"ok": True}, request_id)

    monkeypatch.setattr(mod, "_mutate_task", fake_mutate)
    out = mod.handler(_claims_event(method="PATCH", path="/v1/taskboard/boards/abc/tasks/claim", body={"q": "x"}), None)
    body = json.loads(out["body"])
    assert int(out["statusCode"]) == 200
    assert body["ok"] is True
    assert captured["board_id"] == "board-full"
    assert captured["action"] == "claim"


def test_status_route_resolves_partial_board_id_before_handler(monkeypatch):
    mod = _load_handler(monkeypatch)
    captured: dict = {}

    monkeypatch.setattr(mod, "_resolve_board_id_or_error", lambda _raw, _rid: ("board-full", None))

    def fake_status(event, request_id, board_id):
        captured["board_id"] = board_id
        return mod._response(200, {"ok": True}, request_id)

    monkeypatch.setattr(mod, "_board_status", fake_status)
    out = mod.handler(_claims_event(method="GET", path="/v1/taskboard/boards/abc/status"), None)
    body = json.loads(out["body"])
    assert int(out["statusCode"]) == 200
    assert body["ok"] is True
    assert captured["board_id"] == "board-full"


def test_audit_route_resolves_partial_board_id_before_handler(monkeypatch):
    mod = _load_handler(monkeypatch)
    captured: dict = {}

    monkeypatch.setattr(mod, "_resolve_board_id_or_error", lambda _raw, _rid: ("board-full", None))

    def fake_audit(event, request_id, board_id):
        captured["board_id"] = board_id
        return mod._response(200, {"ok": True}, request_id)

    monkeypatch.setattr(mod, "_board_audit", fake_audit)
    out = mod.handler(_claims_event(method="GET", path="/v1/taskboard/boards/abc/audit"), None)
    body = json.loads(out["body"])
    assert int(out["statusCode"]) == 200
    assert body["ok"] is True
    assert captured["board_id"] == "board-full"


def test_my_activity_route_resolves_partial_board_id_before_handler(monkeypatch):
    mod = _load_handler(monkeypatch)
    captured: dict = {}

    monkeypatch.setattr(mod, "_resolve_board_id_or_error", lambda _raw, _rid: ("board-full", None))

    def fake_my_activity(event, request_id, board_filter):
        captured["board_filter"] = board_filter
        return mod._response(200, {"ok": True}, request_id)

    monkeypatch.setattr(mod, "_my_activity", fake_my_activity)
    out = mod.handler(_claims_event(method="GET", path="/v1/taskboard/my/activity/abc"), None)
    body = json.loads(out["body"])
    assert int(out["statusCode"]) == 200
    assert body["ok"] is True
    assert captured["board_filter"] == "board-full"


def test_board_routes_return_ambiguous_resolution_error(monkeypatch):
    mod = _load_handler(monkeypatch)
    err = mod._response(
        409,
        {
            "errorCode": "AMBIGUOUS_BOARD_ID",
            "message": "multiple boards match boardId: abc",
            "matches": ["board-1", "board-2"],
        },
        "req-1",
    )
    monkeypatch.setattr(mod, "_resolve_board_id_or_error", lambda _raw, _rid: (None, err))

    out = mod.handler(_claims_event(method="GET", path="/v1/taskboard/boards/abc/tasks"), None)
    body = json.loads(out["body"])
    assert int(out["statusCode"]) == 409
    assert body["errorCode"] == "AMBIGUOUS_BOARD_ID"
