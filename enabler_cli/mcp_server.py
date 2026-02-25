from __future__ import annotations

import argparse
import io
import json
import queue
import sys
import threading
import uuid
from contextlib import redirect_stdout
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from . import __version__
from .runtime_core import (
    OpError,
    UsageError,
    _apply_global_env,
    _artifact_root,
    _credential_process_doc_to_output,
    _credential_set_doc,
    _credentials_cache_file,
    _credentials_expires_at,
    _credentials_freshness,
    _namespace,
    _resolve_runtime_credentials_doc,
    _select_runtime_agent_doc,
    cmd_files_share,
    cmd_messages_ack,
    cmd_messages_recv,
    cmd_messages_send,
    cmd_shortlinks_create,
    cmd_shortlinks_resolve_url,
    cmd_taskboard_add,
    cmd_taskboard_audit,
    cmd_taskboard_claim,
    cmd_taskboard_create,
    cmd_taskboard_done,
    cmd_taskboard_fail,
    cmd_taskboard_list,
    cmd_taskboard_my_activity,
    cmd_taskboard_status,
    cmd_taskboard_unclaim,
)
from .cli_shared import GlobalOpts
from .cli_shared import ENABLER_AGENT_ID

ToolFunc = Callable[[dict[str, Any]], Any]


@dataclass
class ToolDef:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolFunc


@dataclass
class OperationRecord:
    operation_id: str
    tool_name: str
    action: str
    state: str
    submitted_at: str
    started_at: str = ""
    finished_at: str = ""
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


class EnablerMcp:
    def __init__(self, *, agent_id: str = "") -> None:
        ns = _namespace(
            profile=None,
            region=None,
            stack=None,
            creds_cache=None,
            agent_id=agent_id,
            auto_refresh_creds=True,
            plain_json=False,
            quiet=True,
        )
        self.g: GlobalOpts = _apply_global_env(ns)
        if not self.g.agent_id:
            raise UsageError(f"missing agent id (pass --agent-id or set {ENABLER_AGENT_ID})")
        self.tools: dict[str, ToolDef] = {}
        self._operations: dict[str, OperationRecord] = {}
        self._operations_lock = threading.Lock()
        self._op_queue: queue.Queue[tuple[str, ToolDef, dict[str, Any]]] = queue.Queue()
        self._worker = threading.Thread(target=self._operation_worker_loop, daemon=True)
        self._worker.start()
        self._register_tools()

    def _register(self, tool: ToolDef) -> None:
        self.tools[tool.name] = tool

    def _register_tools(self) -> None:
        self._register(
            ToolDef(
                name="credentials.status",
                description="Return credentials cache freshness and available sets.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                handler=self._tool_credentials_status,
            )
        )
        self._register(
            ToolDef(
                name="credentials.ensure",
                description="Ensure credentials are present/fresh and return readiness metadata.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "set": {"type": "string"},
                        "requireIdToken": {"type": "boolean"},
                    },
                    "additionalProperties": False,
                },
                handler=self._tool_credentials_ensure,
            )
        )
        self._register(
            ToolDef(
                name="taskboard.exec",
                description="Execute a taskboard action.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "create",
                                "add",
                                "list",
                                "claim",
                                "unclaim",
                                "done",
                                "fail",
                                "status",
                                "audit",
                                "my_activity",
                            ],
                        },
                        "args": {"type": "object"},
                        "async": {"type": "boolean"},
                    },
                    "required": ["action"],
                    "additionalProperties": False,
                },
                handler=self._tool_taskboard_exec,
            )
        )
        self._register(
            ToolDef(
                name="messages.exec",
                description="Execute a messages action.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "enum": ["send", "recv", "ack"]},
                        "args": {"type": "object"},
                        "async": {"type": "boolean"},
                    },
                    "required": ["action"],
                    "additionalProperties": False,
                },
                handler=self._tool_messages_exec,
            )
        )
        self._register(
            ToolDef(
                name="shortlinks.exec",
                description="Execute a shortlinks action.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "enum": ["create", "resolve_url"]},
                        "args": {"type": "object"},
                        "async": {"type": "boolean"},
                    },
                    "required": ["action"],
                    "additionalProperties": False,
                },
                handler=self._tool_shortlinks_exec,
            )
        )
        self._register(
            ToolDef(
                name="files.exec",
                description="Execute a files action.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "enum": ["share"]},
                        "args": {"type": "object"},
                        "async": {"type": "boolean"},
                    },
                    "required": ["action"],
                    "additionalProperties": False,
                },
                handler=self._tool_files_exec,
            )
        )
        self._register(
            ToolDef(
                name="ops.result",
                description="Fetch status/result for an asynchronous operation.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "operationId": {"type": "string"},
                    },
                    "required": ["operationId"],
                    "additionalProperties": False,
                },
                handler=self._tool_ops_result,
            )
        )

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _ensure_doc(
        self,
        *,
        required_set: str | None = None,
        require_id_token: bool = False,
    ) -> dict[str, Any]:
        doc = _resolve_runtime_credentials_doc(argparse.Namespace(), self.g)
        if required_set:
            _credential_set_doc(root_doc=doc, set_name=required_set)
        if require_id_token and not self._id_token_from_doc(doc):
            raise UsageError("MISSING_ID_TOKEN: cached credentials missing cognitoTokens.idToken")
        return doc

    def _id_token_from_doc(self, doc: dict[str, Any]) -> str:
        tokens = doc.get("cognitoTokens")
        if isinstance(tokens, dict):
            tok = str(tokens.get("idToken") or "").strip()
            if tok:
                return tok
        sets = doc.get("credentialSets")
        if isinstance(sets, dict):
            for entry in sets.values():
                if not isinstance(entry, dict):
                    continue
                tok = self._id_token_from_doc(entry)
                if tok:
                    return tok
        return ""

    def _error_info(self, err: Exception) -> dict[str, Any]:
        msg = str(err).strip()
        lower = msg.lower()
        code = "TOOL_EXECUTION_FAILED"
        retryable = False

        if "operation_not_found" in lower:
            code = "OPERATION_NOT_FOUND"
        elif "missing credential set" in lower:
            code = "MISSING_CREDENTIAL_SET"
        elif "missing_id_token" in lower or "cognitotokens.idtoken" in lower:
            code = "MISSING_ID_TOKEN"
        elif (
            "missing api key" in lower
            or "missing username" in lower
            or "missing password" in lower
            or "missing credentials endpoint" in lower
        ):
            code = "MISSING_FALLBACK_AUTH_INPUTS"
        elif (
            "credential auto-refresh failed" in lower
            or "refresh-token renewal failed" in lower
            or "credentials refresh request failed" in lower
        ):
            code = "AUTH_REFRESH_FAILED"
        elif "missing credentials cache" in lower or "cached credentials expired" in lower:
            code = "CREDENTIALS_UNAVAILABLE"
            retryable = True

        return {"code": code, "message": msg, "retryable": retryable}

    def _cmd_json(self, func: Callable[[argparse.Namespace, GlobalOpts], int], **kwargs: Any) -> Any:
        args = argparse.Namespace(**kwargs)
        out_buf = io.StringIO()
        with redirect_stdout(out_buf):
            rc = int(func(args, self.g))
        if rc != 0:
            raise OpError(f"command failed with exit code {rc}")
        raw = out_buf.getvalue().strip()
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except Exception:
            return {"text": raw}

    def _tool_credentials_status(self, _args: dict[str, Any]) -> Any:
        doc = self._ensure_doc()
        expires_at = _credentials_expires_at(doc)
        freshness, seconds_to_expiry = _credentials_freshness(expires_at)
        sets = doc.get("credentialSets") if isinstance(doc.get("credentialSets"), dict) else {}
        return {
            "kind": "enabler.creds.status.v1",
            "agentId": self.g.agent_id,
            "profileType": str((doc.get("principal") or {}).get("profileType") or ""),
            "expiresAt": expires_at,
            "freshness": {"status": freshness, "secondsToExpiry": seconds_to_expiry},
            "credentialSets": sorted(list(sets.keys())),
            "cachePath": str(_credentials_cache_file(self.g)),
        }

    def _tool_credentials_ensure(self, args: dict[str, Any]) -> Any:
        set_name = str(args.get("set") or "").strip()
        require_id_token = bool(args.get("requireIdToken", False))
        doc = self._ensure_doc(
            required_set=set_name if set_name else None,
            require_id_token=require_id_token,
        )
        selected = _select_runtime_agent_doc(doc)
        if set_name:
            selected = _credential_set_doc(root_doc=doc, set_name=set_name)
        process = _credential_process_doc_to_output(selected)
        expires_at = _credentials_expires_at(doc)
        freshness, seconds_to_expiry = _credentials_freshness(expires_at)
        return {
            "kind": "enabler.creds.ensure.v1",
            "agentId": self.g.agent_id,
            "profileType": str((doc.get("principal") or {}).get("profileType") or ""),
            "set": set_name or "agentEnablement",
            "expiration": process.get("Expiration", ""),
            "ready": True,
            "artifactRoot": str(_artifact_root(self.g)),
            "freshness": {"status": freshness, "secondsToExpiry": seconds_to_expiry},
        }

    def _dispatch_taskboard(self, action: str, args: dict[str, Any]) -> Any:
        if action == "create":
            return self._cmd_json(cmd_taskboard_create, name=args.get("name"), json_output=True)
        if action == "add":
            return self._cmd_json(
                cmd_taskboard_add,
                board_id=args.get("boardId"),
                lines=args.get("lines") or [],
                file=None,
                json_output=True,
            )
        if action == "list":
            return self._cmd_json(
                cmd_taskboard_list,
                board_id=args.get("boardId"),
                search=None,
                query=args.get("query"),
                status=args.get("status"),
                limit=args.get("limit"),
                next_token=args.get("nextToken"),
                json_output=True,
            )
        if action in {"claim", "unclaim", "done", "fail"}:
            func = {
                "claim": cmd_taskboard_claim,
                "unclaim": cmd_taskboard_unclaim,
                "done": cmd_taskboard_done,
                "fail": cmd_taskboard_fail,
            }[action]
            return self._cmd_json(
                func,
                board_id=args.get("boardId"),
                target=None,
                task_id=args.get("taskId"),
                query=args.get("query"),
                json_output=True,
            )
        if action == "status":
            return self._cmd_json(cmd_taskboard_status, board_id=args.get("boardId"), json_output=True)
        if action == "audit":
            return self._cmd_json(
                cmd_taskboard_audit,
                board_id=args.get("boardId"),
                task_id=args.get("taskId"),
                limit=args.get("limit"),
                next_token=args.get("nextToken"),
                json_output=True,
            )
        if action == "my_activity":
            return self._cmd_json(
                cmd_taskboard_my_activity,
                board_id=args.get("boardId"),
                limit=args.get("limit"),
                next_token=args.get("nextToken"),
                json_output=True,
            )
        raise UsageError(f"unknown taskboard action: {action}")

    def _dispatch_messages(self, action: str, args: dict[str, Any]) -> Any:
        if action == "send":
            msg_json = args.get("messageJson")
            meta_json = args.get("metaJson")
            return self._cmd_json(
                cmd_messages_send,
                to=args.get("to"),
                text=args.get("text"),
                message_json=json.dumps(msg_json) if isinstance(msg_json, dict) else None,
                kind=args.get("kind"),
                meta_json=json.dumps(meta_json) if isinstance(meta_json, dict) else None,
                event_bus_arn=None,
            )
        if action == "recv":
            return self._cmd_json(
                cmd_messages_recv,
                queue_url=args.get("queueUrl"),
                max_number=str(args.get("maxNumber", "1")),
                wait_seconds=str(args.get("waitSeconds", "10")),
                visibility_timeout=args.get("visibilityTimeout"),
                ack_all=bool(args.get("ackAll", False)),
            )
        if action == "ack":
            return self._cmd_json(
                cmd_messages_ack,
                ack_token=args.get("ackToken"),
                receipt_handle=args.get("receiptHandle"),
                queue_url=args.get("queueUrl"),
            )
        raise UsageError(f"unknown messages action: {action}")

    def _dispatch_shortlinks(self, action: str, args: dict[str, Any]) -> Any:
        if action == "create":
            return self._cmd_json(
                cmd_shortlinks_create,
                target_url=args.get("targetUrl"),
                alias=args.get("alias"),
                json_output=True,
            )
        if action == "resolve_url":
            out = self._cmd_json(cmd_shortlinks_resolve_url, code=args.get("code"))
            return {"url": str(out.get("text") or "").strip()}
        raise UsageError(f"unknown shortlinks action: {action}")

    def _dispatch_files(self, action: str, args: dict[str, Any]) -> Any:
        if action == "share":
            return self._cmd_json(
                cmd_files_share,
                file_path=args.get("filePath"),
                name=args.get("name"),
                json_output=True,
            )
        raise UsageError(f"unknown files action: {action}")

    def _tool_taskboard_exec(self, args: dict[str, Any]) -> Any:
        action = str(args.get("action") or "").strip()
        action_args = args.get("args")
        if not isinstance(action_args, dict):
            action_args = {}
        return self._dispatch_taskboard(action, action_args)

    def _tool_messages_exec(self, args: dict[str, Any]) -> Any:
        action = str(args.get("action") or "").strip()
        action_args = args.get("args")
        if not isinstance(action_args, dict):
            action_args = {}
        return self._dispatch_messages(action, action_args)

    def _tool_shortlinks_exec(self, args: dict[str, Any]) -> Any:
        action = str(args.get("action") or "").strip()
        action_args = args.get("args")
        if not isinstance(action_args, dict):
            action_args = {}
        return self._dispatch_shortlinks(action, action_args)

    def _tool_files_exec(self, args: dict[str, Any]) -> Any:
        action = str(args.get("action") or "").strip()
        action_args = args.get("args")
        if not isinstance(action_args, dict):
            action_args = {}
        return self._dispatch_files(action, action_args)

    def _tool_ops_result(self, args: dict[str, Any]) -> Any:
        op_id = str(args.get("operationId") or "").strip()
        if not op_id:
            raise UsageError("OPERATION_NOT_FOUND: missing operationId")
        with self._operations_lock:
            record = self._operations.get(op_id)
        if record is None:
            raise UsageError(f"OPERATION_NOT_FOUND: {op_id}")
        payload: dict[str, Any] = {
            "kind": "enabler.mcp.operation.result.v1",
            "operationId": record.operation_id,
            "tool": record.tool_name,
            "action": record.action,
            "state": record.state,
            "submittedAt": record.submitted_at,
            "startedAt": record.started_at,
            "finishedAt": record.finished_at,
        }
        if record.result is not None:
            payload["result"] = record.result
        if record.error is not None:
            payload["error"] = record.error
        return payload

    def _auth_requirements(self, tool_name: str, arguments: dict[str, Any]) -> tuple[str | None, bool]:
        if tool_name == "taskboard.exec":
            return None, True
        if tool_name == "messages.exec":
            return "agentEnablement", False
        if tool_name == "files.exec":
            return "agentEnablement", False
        if tool_name == "shortlinks.exec":
            action = str(arguments.get("action") or "").strip()
            return None, action == "create"
        return None, False

    def _execute_tool_now(self, tool: ToolDef, arguments: dict[str, Any]) -> Any:
        required_set, require_id_token = self._auth_requirements(tool.name, arguments)
        self._ensure_doc(required_set=required_set, require_id_token=require_id_token)
        return tool.handler(arguments)

    def _operation_worker_loop(self) -> None:
        while True:
            op_id, tool, arguments = self._op_queue.get()
            try:
                with self._operations_lock:
                    rec = self._operations.get(op_id)
                    if rec is None:
                        continue
                    rec.state = "running"
                    rec.started_at = self._now_iso()
                result = self._execute_tool_now(tool, arguments)
                with self._operations_lock:
                    rec = self._operations.get(op_id)
                    if rec is None:
                        continue
                    rec.state = "succeeded"
                    rec.result = result if isinstance(result, dict) else {"result": result}
                    rec.finished_at = self._now_iso()
            except (UsageError, OpError, ValueError) as e:
                info = self._error_info(e)
                with self._operations_lock:
                    rec = self._operations.get(op_id)
                    if rec is None:
                        continue
                    rec.state = "failed"
                    rec.error = info
                    rec.finished_at = self._now_iso()
            finally:
                self._op_queue.task_done()

    def _enqueue_operation(self, tool: ToolDef, arguments: dict[str, Any]) -> dict[str, Any]:
        op_id = uuid.uuid4().hex
        action = str(arguments.get("action") or "").strip()
        rec = OperationRecord(
            operation_id=op_id,
            tool_name=tool.name,
            action=action,
            state="queued",
            submitted_at=self._now_iso(),
        )
        with self._operations_lock:
            self._operations[op_id] = rec
        self._op_queue.put((op_id, tool, arguments))
        return {
            "kind": "enabler.mcp.operation.accepted.v1",
            "operationId": op_id,
            "state": "queued",
            "submittedAt": rec.submitted_at,
        }

    def handle_request(self, req: dict[str, Any]) -> dict[str, Any] | None:
        method = req.get("method")
        req_id = req.get("id")

        if method == "initialized" and req_id is None:
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "enabler-mcp", "version": __version__},
                },
            }

        if method == "tools/list":
            tools = [
                {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                }
                for t in self.tools.values()
            ]
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools}}

        if method == "tools/call":
            params = req.get("params") if isinstance(req.get("params"), dict) else {}
            name = str(params.get("name") or "").strip()
            arguments = params.get("arguments")
            if not isinstance(arguments, dict):
                arguments = {}

            tool = self.tools.get(name)
            if tool is None:
                return self._error(req_id, -32602, f"unknown tool: {name}")

            try:
                wants_async = bool(arguments.get("async", False))
                if wants_async and name in {"taskboard.exec", "messages.exec", "shortlinks.exec", "files.exec"}:
                    result = self._enqueue_operation(tool, arguments)
                else:
                    result = self._execute_tool_now(tool, arguments)
            except (UsageError, OpError, ValueError) as e:
                info = self._error_info(e)
                return self._error(req_id, -32001, info["message"], data=info)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, separators=(",", ":"), sort_keys=True),
                        }
                    ]
                },
            }

        if req_id is None:
            return None
        return self._error(req_id, -32601, f"method not found: {method}")

    @staticmethod
    def _error(
        req_id: Any,
        code: int,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }
        if isinstance(data, dict):
            payload["error"]["data"] = data
        return payload


def _read_message(stdin: Any) -> dict[str, Any] | None:
    while True:
        line = stdin.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            continue
        decoded = line.decode("utf-8").strip()
        if not decoded:
            continue
        parsed = json.loads(decoded)
        break
    if not isinstance(parsed, dict):
        raise ValueError("message must be a JSON object")
    return parsed


def _write_message(stdout: Any, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    stdout.write(body + b"\n")
    stdout.flush()


def serve_stdio(*, agent_id: str = "") -> int:
    server = EnablerMcp(agent_id=agent_id)
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    while True:
        try:
            req = _read_message(stdin)
        except Exception as exc:
            _write_message(
                stdout,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error", "data": {"detail": str(exc)}},
                },
            )
            continue
        if req is None:
            break
        resp = server.handle_request(req)
        if resp is not None:
            _write_message(stdout, resp)
    return 0
