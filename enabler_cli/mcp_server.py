from __future__ import annotations

import argparse
import io
import json
import os
import queue
import sys
import threading
import uuid
from contextlib import redirect_stdout
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse, urlunparse

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
    _credentials_location_manifest,
    _namespace,
    _resolve_runtime_credentials_doc,
    _select_runtime_agent_doc,
    _write_cognito_env_file_from_doc,
    _write_credentials_cache_from_text,
    _write_sts_env_files_from_doc,
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
from .apps.agent_admin_cli import _http_post_json
from .cli_shared import ENABLER_API_KEY
from .cli_shared import ENABLER_CREDENTIALS_ENDPOINT
from .cli_shared import GlobalOpts

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
    agent_id: str
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
        self._context_lock = threading.Lock()
        self._default_agent_id = self.g.agent_id or ""
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
                name="help",
                description="Explain MCP tools and actions with usage examples.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "action": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
                handler=self._tool_help,
            )
        )
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
                name="credentials.exec",
                description="Execute credential lifecycle actions.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "delegation_approve",
                                "delegation_redeem",
                                "delegation_request",
                                "delegation_status",
                                "ensure",
                                "help",
                                "list_sessions",
                                "set_agentid",
                            ],
                        },
                        "args": {"type": "object"},
                        "async": {"type": "boolean"},
                    },
                    "required": ["action"],
                    "additionalProperties": False,
                },
                handler=self._tool_credentials_exec,
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
                                "help",
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
                        "action": {"type": "string", "enum": ["send", "recv", "ack", "help"]},
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
                        "action": {"type": "string", "enum": ["create", "resolve_url", "help"]},
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
                        "action": {"type": "string", "enum": ["share", "help"]},
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

    def _g_for_agent(self, agent_id: str) -> GlobalOpts:
        return GlobalOpts(
            stack=self.g.stack,
            pretty=self.g.pretty,
            quiet=self.g.quiet,
            auto_refresh_creds=self.g.auto_refresh_creds,
            agent_id=agent_id,
        )

    def _current_agent_id(self) -> str:
        with self._context_lock:
            return self._default_agent_id

    def _is_bound(self) -> bool:
        return bool(self._current_agent_id().strip())

    def _require_bound_agent_id(self) -> str:
        agent_id = self._current_agent_id().strip()
        if not agent_id:
            raise UsageError("UNBOUND_IDENTITY: No active agent identity; redeem delegation request first")
        return agent_id

    def _ensure_doc(
        self,
        *,
        g: GlobalOpts,
        required_set: str | None = None,
        require_id_token: bool = False,
    ) -> dict[str, Any]:
        doc = _resolve_runtime_credentials_doc(argparse.Namespace(), g)
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

    def _runtime_credentials_endpoint(self, doc: dict[str, Any]) -> str:
        auth = doc.get("auth")
        if isinstance(auth, dict):
            endpoint = str(auth.get("credentialsEndpoint") or "").strip()
            if endpoint:
                return endpoint
        refs = doc.get("references")
        if isinstance(refs, dict):
            for key in ("credentials", "auth"):
                item = refs.get(key)
                if not isinstance(item, dict):
                    continue
                endpoint = str(item.get("invokeUrl") or item.get("endpoint") or "").strip()
                if endpoint:
                    return endpoint
        return ""

    def _derive_endpoint(self, credentials_endpoint: str, *, suffix: str) -> str:
        raw = str(credentials_endpoint or "").strip()
        if not raw:
            raise UsageError("missing credentials endpoint in cached auth metadata")
        parsed = urlparse(raw)
        path = str(parsed.path or "").rstrip("/")
        if not path.endswith("/v1/credentials"):
            raise UsageError(
                "cannot derive endpoint from credentials endpoint "
                f"{raw!r} (expected path ending with /v1/credentials)"
            )
        target_path = path[: -len("/v1/credentials")] + suffix
        return urlunparse(parsed._replace(path=target_path))

    def _bootstrap_credentials_endpoint(self, *, g: GlobalOpts) -> str:
        if self._is_bound():
            doc = self._ensure_doc(g=g)
            endpoint = self._runtime_credentials_endpoint(doc)
            if endpoint:
                return endpoint
        endpoint = str(os.environ.get(ENABLER_CREDENTIALS_ENDPOINT) or "").strip()
        if endpoint:
            return endpoint
        raise UsageError(
            f"missing credentials endpoint in cached auth metadata and env {ENABLER_CREDENTIALS_ENDPOINT}"
        )

    def _json_obj_or_error(self, *, raw: bytes, label: str) -> dict[str, Any]:
        text = raw.decode("utf-8", errors="replace")
        try:
            parsed = json.loads(text)
        except Exception as e:
            raise OpError(f"invalid JSON from {label}: {e}; body={text}") from e
        if not isinstance(parsed, dict):
            raise OpError(f"invalid JSON from {label}: expected object")
        return parsed

    def _post_json_checked(
        self,
        *,
        url: str,
        headers: dict[str, str],
        body_obj: dict[str, Any] | None = None,
        label: str,
    ) -> dict[str, Any]:
        body = b""
        if isinstance(body_obj, dict):
            body = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")
        status, _hdrs, raw = _http_post_json(url=url, headers=headers, body=body)
        if status < 200 or status >= 300:
            text = raw.decode("utf-8", errors="replace")
            raise OpError(f"{label} failed: status={status} body={text}")
        return self._json_obj_or_error(raw=raw, label=label)

    def _write_exchange_artifacts(self, *, g: GlobalOpts, response_obj: dict[str, Any]) -> dict[str, Any]:
        raw_text = json.dumps(response_obj, separators=(",", ":"), sort_keys=True)
        path = _write_credentials_cache_from_text(g=g, raw_text=raw_text)
        sts_env_paths = _write_sts_env_files_from_doc(g=g, root_doc=response_obj)
        cognito_env_path = str(_write_cognito_env_file_from_doc(g=g, root_doc=response_obj))
        manifest = _credentials_location_manifest(
            g=g,
            doc=response_obj,
            sts_env_paths=sts_env_paths,
            cognito_env_path=cognito_env_path,
        )
        return {"cachePath": str(path), "manifest": manifest}

    def _profile_type_from_doc(self, doc: dict[str, Any]) -> str:
        principal = doc.get("principal")
        if isinstance(principal, dict):
            val = str(principal.get("profileType") or "").strip().lower()
            if val:
                return val
        return "named"

    def _error_info(self, err: Exception) -> dict[str, Any]:
        msg = str(err).strip()
        lower = msg.lower()
        code = "TOOL_EXECUTION_FAILED"
        retryable = False

        if "operation_not_found" in lower:
            code = "OPERATION_NOT_FOUND"
        elif "unbound_identity" in lower:
            code = "UNBOUND_IDENTITY"
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

    def _cmd_json(self, func: Callable[[argparse.Namespace, GlobalOpts], int], *, g: GlobalOpts, **kwargs: Any) -> Any:
        args = argparse.Namespace(**kwargs)
        out_buf = io.StringIO()
        with redirect_stdout(out_buf):
            rc = int(func(args, g))
        if rc != 0:
            raise OpError(f"command failed with exit code {rc}")
        raw = out_buf.getvalue().strip()
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except Exception:
            return {"text": raw}

    @staticmethod
    def _help_catalog() -> dict[str, dict[str, Any]]:
        return {
            "help": {
                "brief": "Explain MCP tools and actions with usage examples.",
            },
            "credentials.status": {
                "brief": "Show cache freshness, active identity, and available credential sets.",
            },
            "credentials.exec": {
                "brief": "Credential lifecycle actions (bootstrap, switching, delegation).",
                "actions": {
                    "help": "Describe credential actions and examples.",
                    "ensure": "Validate required credential set/token availability.",
                    "set_agentid": "Switch default runtime identity to another local session.",
                    "list_sessions": "List local session ids available for switching.",
                    "delegation_request": "Create request code for named-agent approval.",
                    "delegation_approve": "Approve delegation request (named profiles only).",
                    "delegation_status": "Get delegation request status by requestCode.",
                    "delegation_redeem": "Redeem approved request and persist artifacts.",
                },
            },
            "taskboard.exec": {
                "brief": "Taskboard operations for creating and managing tasks.",
                "actions": {
                    "help": "Describe taskboard actions and examples.",
                    "create": "Create a board.",
                    "add": "Add task lines to a board.",
                    "list": "List tasks with filters and pagination.",
                    "claim": "Claim one task.",
                    "unclaim": "Unclaim one task.",
                    "done": "Mark a task done.",
                    "fail": "Mark a task failed.",
                    "status": "Get board status summary.",
                    "audit": "Get task/board audit events.",
                    "my_activity": "Get activity for current agent.",
                },
            },
            "messages.exec": {
                "brief": "Inbox messaging operations.",
                "actions": {
                    "help": "Describe message actions and examples.",
                    "send": "Send message to another agent.",
                    "recv": "Receive pending messages.",
                    "ack": "Acknowledge a received message.",
                },
            },
            "shortlinks.exec": {
                "brief": "Shortlink creation and URL resolution.",
                "actions": {
                    "help": "Describe shortlinks actions and examples.",
                    "create": "Create short code for target URL.",
                    "resolve_url": "Render full resolve URL from short code.",
                },
            },
            "files.exec": {
                "brief": "File-sharing helper actions.",
                "actions": {
                    "help": "Describe file-share action and examples.",
                    "share": "Upload/share one file payload.",
                },
            },
            "ops.result": {
                "brief": "Fetch status/result for async operations.",
            },
        }

    def _help_text(self, *, tool_name: str = "", action: str = "") -> str:
        catalog = self._help_catalog()
        ordered_tools = [
            "help",
            "credentials.status",
            "credentials.exec",
            "taskboard.exec",
            "messages.exec",
            "shortlinks.exec",
            "files.exec",
            "ops.result",
        ]
        if not tool_name:
            lines = ["# Tool Help Index", "", "Brief MCP tool summary:"]
            for name in ordered_tools:
                item = catalog[name]
                lines.append(f"- `{name}`: {item['brief']}")
            lines.extend(
                [
                    "",
                    "Example:",
                    "```json",
                    '{"method":"tools/call","params":{"name":"help","arguments":{"tool":"messages.exec"}}}',
                    "```",
                ]
            )
            return "\n".join(lines)
        if tool_name not in catalog:
            valid = ", ".join(f"`{n}`" for n in ordered_tools)
            raise UsageError(f"unknown tool for help: {tool_name}; valid tools: {valid}")
        item = catalog[tool_name]
        actions = item.get("actions")
        if action:
            if not isinstance(actions, dict):
                raise UsageError(f"tool {tool_name} has no actions")
            if action not in actions:
                valid_actions = ", ".join(f"`{a}`" for a in sorted(actions.keys()))
                raise UsageError(f"unknown action for {tool_name}: {action}; valid actions: {valid_actions}")
            lines = [
                f"# Help: `{tool_name}` action `{action}`",
                "",
                str(actions[action]),
                "",
                "Example:",
                "```json",
                json.dumps(
                    {
                        "method": "tools/call",
                        "params": {
                            "name": tool_name,
                            "arguments": {
                                "action": action,
                                "args": {},
                            },
                        },
                    },
                    separators=(",", ":"),
                ),
                "```",
            ]
            if action != "help":
                lines.extend(
                    [
                        "",
                        "Detail lookup example:",
                        "```json",
                        json.dumps(
                            {
                                "method": "tools/call",
                                "params": {
                                    "name": tool_name,
                                    "arguments": {
                                        "action": "help",
                                        "args": {"action": action},
                                    },
                                },
                            },
                            separators=(",", ":"),
                        ),
                        "```",
                    ]
                )
            return "\n".join(lines)

        lines = [f"# Help: `{tool_name}`", "", str(item["brief"])]
        if isinstance(actions, dict):
            lines.extend(["", "Actions:"])
            for act, desc in actions.items():
                lines.append(f"- `{act}`: {desc}")
            lines.extend(
                [
                    "",
                    "Examples:",
                    "```json",
                    json.dumps(
                        {
                            "method": "tools/call",
                            "params": {"name": tool_name, "arguments": {"action": "help", "args": {}}},
                        },
                        separators=(",", ":"),
                    ),
                    "```",
                    "```json",
                    json.dumps(
                        {
                            "method": "tools/call",
                            "params": {
                                "name": tool_name,
                                "arguments": {"action": "help", "args": {"action": "help"}},
                            },
                        },
                        separators=(",", ":"),
                    ),
                    "```",
                ]
            )
        else:
            lines.extend(
                [
                    "",
                    "Example:",
                    "```json",
                    json.dumps(
                        {"method": "tools/call", "params": {"name": tool_name, "arguments": {}}},
                        separators=(",", ":"),
                    ),
                    "```",
                ]
            )
        return "\n".join(lines)

    def _tool_help(self, args: dict[str, Any]) -> Any:
        tool_name = str(args.get("tool") or "").strip()
        action = str(args.get("action") or "").strip()
        if action and not tool_name:
            raise UsageError("tool is required when action is set")
        return {
            "kind": "enabler.mcp.help.v1",
            "tool": tool_name,
            "action": action,
            "text": self._help_text(tool_name=tool_name, action=action),
        }

    def _tool_credentials_status(self, _args: dict[str, Any]) -> Any:
        agent_id = self._current_agent_id()
        if not agent_id:
            return {
                "kind": "enabler.creds.status.v1",
                "defaultAgentId": "",
                "agentId": "",
                "bound": False,
                "profileType": "",
                "expiresAt": "",
                "freshness": {"status": "missing", "secondsToExpiry": 0},
                "credentialSets": [],
                "cachePath": "",
                "hint": "Run credentials.exec action=delegation_request, approve from a named agent, then delegation_redeem.",
            }
        g = self._g_for_agent(agent_id)
        doc = self._ensure_doc(g=g)
        expires_at = _credentials_expires_at(doc)
        freshness, seconds_to_expiry = _credentials_freshness(expires_at)
        sets = doc.get("credentialSets") if isinstance(doc.get("credentialSets"), dict) else {}
        return {
            "kind": "enabler.creds.status.v1",
            "defaultAgentId": agent_id,
            "agentId": agent_id,
            "profileType": str((doc.get("principal") or {}).get("profileType") or ""),
            "expiresAt": expires_at,
            "freshness": {"status": freshness, "secondsToExpiry": seconds_to_expiry},
            "credentialSets": sorted(list(sets.keys())),
            "cachePath": str(_credentials_cache_file(g)),
        }

    def _credentials_ensure_payload(self, args: dict[str, Any], *, g: GlobalOpts) -> Any:
        agent_id = g.agent_id
        set_name = str(args.get("set") or "").strip()
        require_id_token = bool(args.get("requireIdToken", False))
        doc = self._ensure_doc(
            g=g,
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
            "agentId": agent_id,
            "profileType": str((doc.get("principal") or {}).get("profileType") or ""),
            "set": set_name or "agentEnablement",
            "expiration": process.get("Expiration", ""),
            "ready": True,
            "artifactRoot": str(_artifact_root(g)),
            "freshness": {"status": freshness, "secondsToExpiry": seconds_to_expiry},
        }

    def _dispatch_credentials(self, action: str, args: dict[str, Any], *, g: GlobalOpts) -> Any:
        if action == "help":
            target_action = str(args.get("action") or "").strip()
            return {
                "kind": "enabler.mcp.help.v1",
                "tool": "credentials.exec",
                "action": target_action,
                "text": self._help_text(tool_name="credentials.exec", action=target_action),
            }
        if action == "ensure":
            self._require_bound_agent_id()
            return self._credentials_ensure_payload(args, g=g)

        if action == "set_agentid":
            self._require_bound_agent_id()
            new_agent_id = str(args.get("agentId") or "").strip()
            if not new_agent_id:
                raise UsageError("missing agentId")
            trial_g = self._g_for_agent(new_agent_id)
            _ = self._ensure_doc(g=trial_g)
            with self._context_lock:
                previous = self._default_agent_id
                self._default_agent_id = new_agent_id
            return {
                "kind": "enabler.mcp.credentials.set-agentid.v1",
                "previousAgentId": previous,
                "agentId": new_agent_id,
                "switchedAt": self._now_iso(),
            }

        if action == "list_sessions":
            self._require_bound_agent_id()
            root = _artifact_root(g)
            sessions_root = root.parent
            sessions: list[dict[str, Any]] = []
            if sessions_root.exists():
                for session_dir in sorted([p for p in sessions_root.iterdir() if p.is_dir()]):
                    session_file = session_dir / "session.json"
                    if not session_file.exists():
                        continue
                    sessions.append(
                        {
                            "agentId": session_dir.name,
                            "sessionPath": str(session_file.resolve()),
                            "exists": True,
                        }
                    )
            return {"kind": "enabler.mcp.credentials.sessions.v1", "sessions": sessions}

        if action == "delegation_request":
            api_key = str(os.environ.get(ENABLER_API_KEY) or "").strip()
            if not api_key:
                raise UsageError(f"missing {ENABLER_API_KEY} (set env var)")
            credentials_endpoint = self._bootstrap_credentials_endpoint(g=g)
            request_endpoint = self._derive_endpoint(credentials_endpoint, suffix="/v1/delegation/requests")
            scopes_raw = args.get("scopes")
            if isinstance(scopes_raw, list):
                scopes = [str(v).strip() for v in scopes_raw if str(v).strip()]
            else:
                scopes = ["taskboard", "messages"]
            ttl_seconds = int(args.get("ttlSeconds") or 600)
            purpose = str(args.get("purpose") or "")
            request_resp = self._post_json_checked(
                url=request_endpoint,
                headers={
                    "x-api-key": api_key,
                    "content-type": "application/json",
                },
                body_obj={"scopes": scopes, "ttlSeconds": ttl_seconds, "purpose": purpose},
                label="delegation request create",
            )
            return {
                "kind": "enabler.mcp.credentials.delegation-request.v1",
                "agentId": self._current_agent_id(),
                "request": request_resp,
            }

        if action == "delegation_approve":
            self._require_bound_agent_id()
            source_doc = self._ensure_doc(g=g, require_id_token=True)
            if self._profile_type_from_doc(source_doc) != "named":
                raise UsageError("Only named agent profiles may approve delegation requests")
            request_code = str(args.get("requestCode") or "").strip()
            if not request_code:
                raise UsageError("missing requestCode")

            id_token = self._id_token_from_doc(source_doc)
            if not id_token:
                raise UsageError("cached credentials missing cognitoTokens.idToken")
            credentials_endpoint = self._runtime_credentials_endpoint(source_doc)
            approval_endpoint = self._derive_endpoint(credentials_endpoint, suffix="/v1/delegation/approvals")
            approval_resp = self._post_json_checked(
                url=approval_endpoint,
                headers={
                    "authorization": f"Bearer {id_token}",
                    "content-type": "application/json",
                },
                body_obj={"requestCode": request_code},
                label="delegation request approve",
            )
            return {
                "kind": "enabler.mcp.credentials.delegation-approve.v1",
                "agentId": self._current_agent_id(),
                "approval": approval_resp,
            }

        if action == "delegation_status":
            api_key = str(os.environ.get(ENABLER_API_KEY) or "").strip()
            if not api_key:
                raise UsageError(f"missing {ENABLER_API_KEY} (set env var)")
            request_code = str(args.get("requestCode") or "").strip()
            if not request_code:
                raise UsageError("missing requestCode")
            credentials_endpoint = self._bootstrap_credentials_endpoint(g=g)
            status_endpoint = self._derive_endpoint(credentials_endpoint, suffix="/v1/delegation/status")
            status_resp = self._post_json_checked(
                url=status_endpoint,
                headers={
                    "x-api-key": api_key,
                    "content-type": "application/json",
                },
                body_obj={"requestCode": request_code},
                label="delegation request status",
            )
            return {
                "kind": "enabler.mcp.credentials.delegation-status.v1",
                "agentId": self._current_agent_id(),
                "status": status_resp,
            }

        if action == "delegation_redeem":
            api_key = str(os.environ.get(ENABLER_API_KEY) or "").strip()
            if not api_key:
                raise UsageError(f"missing {ENABLER_API_KEY} (set env var)")
            request_code = str(args.get("requestCode") or "").strip()
            if not request_code:
                raise UsageError("missing requestCode")
            was_unbound = not self._is_bound()
            target_agent_id = str(args.get("targetAgentId") or "").strip()
            switch_to_target = bool(args.get("switchToTarget", False))
            credentials_endpoint = self._bootstrap_credentials_endpoint(g=g)
            redeem_endpoint = self._derive_endpoint(credentials_endpoint, suffix="/v1/delegation/redeem")
            redeem_resp = self._post_json_checked(
                url=redeem_endpoint,
                headers={
                    "x-api-key": api_key,
                    "content-type": "application/json",
                },
                body_obj={"requestCode": request_code},
                label="delegation request redeem",
            )
            server_ephemeral_agent_id = str(redeem_resp.get("ephemeralAgentId") or "").strip()
            if not server_ephemeral_agent_id:
                principal = redeem_resp.get("principal")
                if isinstance(principal, dict):
                    puser = str(principal.get("username") or "").strip()
                    if puser.startswith("ephem-"):
                        server_ephemeral_agent_id = puser
            if was_unbound:
                if not server_ephemeral_agent_id:
                    raise OpError("delegation redeem response missing ephemeralAgentId")
                target_agent_id = server_ephemeral_agent_id
                switch_to_target = True
            if not target_agent_id:
                target_agent_id = server_ephemeral_agent_id or g.agent_id
            if not target_agent_id:
                raise OpError("unable to determine targetAgentId for redeemed session")
            target_g = self._g_for_agent(target_agent_id)
            artifacts = self._write_exchange_artifacts(g=target_g, response_obj=redeem_resp)
            switched = False
            if switch_to_target:
                with self._context_lock:
                    self._default_agent_id = target_agent_id
                switched = True
            return {
                "kind": "enabler.mcp.credentials.delegation-redeem.v1",
                "agentId": self._current_agent_id(),
                "targetAgentId": target_agent_id,
                "serverEphemeralAgentId": server_ephemeral_agent_id,
                "switched": switched,
                "currentDefaultAgentId": self._current_agent_id(),
                "principal": redeem_resp.get("principal"),
                "credentialSets": sorted(list((redeem_resp.get("credentialSets") or {}).keys()))
                if isinstance(redeem_resp.get("credentialSets"), dict)
                else [],
                **artifacts,
            }

        raise UsageError(f"unknown credentials action: {action}")

    def _dispatch_taskboard(self, action: str, args: dict[str, Any], *, g: GlobalOpts) -> Any:
        if action == "help":
            target_action = str(args.get("action") or "").strip()
            return {
                "kind": "enabler.mcp.help.v1",
                "tool": "taskboard.exec",
                "action": target_action,
                "text": self._help_text(tool_name="taskboard.exec", action=target_action),
            }
        if action == "create":
            return self._cmd_json(cmd_taskboard_create, g=g, name=args.get("name"), json_output=True)
        if action == "add":
            return self._cmd_json(
                cmd_taskboard_add,
                g=g,
                board_id=args.get("boardId"),
                lines=args.get("lines") or [],
                file=None,
                json_output=True,
            )
        if action == "list":
            return self._cmd_json(
                cmd_taskboard_list,
                g=g,
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
                g=g,
                board_id=args.get("boardId"),
                target=None,
                task_id=args.get("taskId"),
                query=args.get("query"),
                json_output=True,
            )
        if action == "status":
            return self._cmd_json(cmd_taskboard_status, g=g, board_id=args.get("boardId"), json_output=True)
        if action == "audit":
            return self._cmd_json(
                cmd_taskboard_audit,
                g=g,
                board_id=args.get("boardId"),
                task_id=args.get("taskId"),
                limit=args.get("limit"),
                next_token=args.get("nextToken"),
                json_output=True,
            )
        if action == "my_activity":
            return self._cmd_json(
                cmd_taskboard_my_activity,
                g=g,
                board_id=args.get("boardId"),
                limit=args.get("limit"),
                next_token=args.get("nextToken"),
                json_output=True,
            )
        raise UsageError(f"unknown taskboard action: {action}")

    def _dispatch_messages(self, action: str, args: dict[str, Any], *, g: GlobalOpts) -> Any:
        if action == "help":
            target_action = str(args.get("action") or "").strip()
            return {
                "kind": "enabler.mcp.help.v1",
                "tool": "messages.exec",
                "action": target_action,
                "text": self._help_text(tool_name="messages.exec", action=target_action),
            }
        if action == "send":
            msg_json = args.get("messageJson")
            meta_json = args.get("metaJson")
            return self._cmd_json(
                cmd_messages_send,
                g=g,
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
                g=g,
                queue_url=args.get("queueUrl"),
                max_number=str(args.get("maxNumber", "1")),
                wait_seconds=str(args.get("waitSeconds", "10")),
                visibility_timeout=args.get("visibilityTimeout"),
                ack_all=bool(args.get("ackAll", False)),
            )
        if action == "ack":
            return self._cmd_json(
                cmd_messages_ack,
                g=g,
                ack_token=args.get("ackToken"),
                receipt_handle=args.get("receiptHandle"),
                queue_url=args.get("queueUrl"),
            )
        raise UsageError(f"unknown messages action: {action}")

    def _dispatch_shortlinks(self, action: str, args: dict[str, Any], *, g: GlobalOpts) -> Any:
        if action == "help":
            target_action = str(args.get("action") or "").strip()
            return {
                "kind": "enabler.mcp.help.v1",
                "tool": "shortlinks.exec",
                "action": target_action,
                "text": self._help_text(tool_name="shortlinks.exec", action=target_action),
            }
        if action == "create":
            return self._cmd_json(
                cmd_shortlinks_create,
                g=g,
                target_url=args.get("targetUrl"),
                alias=args.get("alias"),
                json_output=True,
            )
        if action == "resolve_url":
            out = self._cmd_json(cmd_shortlinks_resolve_url, g=g, code=args.get("code"))
            return {"url": str(out.get("text") or "").strip()}
        raise UsageError(f"unknown shortlinks action: {action}")

    def _dispatch_files(self, action: str, args: dict[str, Any], *, g: GlobalOpts) -> Any:
        if action == "help":
            target_action = str(args.get("action") or "").strip()
            return {
                "kind": "enabler.mcp.help.v1",
                "tool": "files.exec",
                "action": target_action,
                "text": self._help_text(tool_name="files.exec", action=target_action),
            }
        if action == "share":
            return self._cmd_json(
                cmd_files_share,
                g=g,
                file_path=args.get("filePath"),
                name=args.get("name"),
                json_output=True,
            )
        raise UsageError(f"unknown files action: {action}")

    def _tool_taskboard_exec(self, args: dict[str, Any]) -> Any:
        g = self._g_for_agent(self._require_bound_agent_id())
        action = str(args.get("action") or "").strip()
        action_args = args.get("args")
        if not isinstance(action_args, dict):
            action_args = {}
        return self._dispatch_taskboard(action, action_args, g=g)

    def _tool_messages_exec(self, args: dict[str, Any]) -> Any:
        g = self._g_for_agent(self._require_bound_agent_id())
        action = str(args.get("action") or "").strip()
        action_args = args.get("args")
        if not isinstance(action_args, dict):
            action_args = {}
        return self._dispatch_messages(action, action_args, g=g)

    def _tool_shortlinks_exec(self, args: dict[str, Any]) -> Any:
        g = self._g_for_agent(self._require_bound_agent_id())
        action = str(args.get("action") or "").strip()
        action_args = args.get("args")
        if not isinstance(action_args, dict):
            action_args = {}
        return self._dispatch_shortlinks(action, action_args, g=g)

    def _tool_files_exec(self, args: dict[str, Any]) -> Any:
        g = self._g_for_agent(self._require_bound_agent_id())
        action = str(args.get("action") or "").strip()
        action_args = args.get("args")
        if not isinstance(action_args, dict):
            action_args = {}
        return self._dispatch_files(action, action_args, g=g)

    def _tool_credentials_exec(self, args: dict[str, Any]) -> Any:
        g = self._g_for_agent(self._current_agent_id())
        action = str(args.get("action") or "").strip()
        action_args = args.get("args")
        if not isinstance(action_args, dict):
            action_args = {}
        return self._dispatch_credentials(action, action_args, g=g)

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
            "agentId": record.agent_id,
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

    def _execute_tool_now(self, tool: ToolDef, arguments: dict[str, Any], *, g: GlobalOpts) -> Any:
        if tool.name == "credentials.exec":
            action = str(arguments.get("action") or "").strip()
            action_args = arguments.get("args")
            if not isinstance(action_args, dict):
                action_args = {}
            return self._dispatch_credentials(action, action_args, g=g)
        if tool.name == "help":
            return tool.handler(arguments)
        if tool.name == "credentials.status":
            return tool.handler(arguments)
        if tool.name in {"taskboard.exec", "messages.exec", "shortlinks.exec", "files.exec"}:
            action = str(arguments.get("action") or "").strip()
            action_args = arguments.get("args")
            if not isinstance(action_args, dict):
                action_args = {}
            if action == "help":
                if tool.name == "taskboard.exec":
                    return self._dispatch_taskboard(action, action_args, g=g)
                if tool.name == "messages.exec":
                    return self._dispatch_messages(action, action_args, g=g)
                if tool.name == "shortlinks.exec":
                    return self._dispatch_shortlinks(action, action_args, g=g)
                if tool.name == "files.exec":
                    return self._dispatch_files(action, action_args, g=g)
        if tool.name != "credentials.status" and not self._is_bound():
            self._require_bound_agent_id()
        required_set, require_id_token = self._auth_requirements(tool.name, arguments)
        self._ensure_doc(g=g, required_set=required_set, require_id_token=require_id_token)
        if tool.name == "taskboard.exec":
            action = str(arguments.get("action") or "").strip()
            action_args = arguments.get("args")
            if not isinstance(action_args, dict):
                action_args = {}
            return self._dispatch_taskboard(action, action_args, g=g)
        if tool.name == "messages.exec":
            action = str(arguments.get("action") or "").strip()
            action_args = arguments.get("args")
            if not isinstance(action_args, dict):
                action_args = {}
            return self._dispatch_messages(action, action_args, g=g)
        if tool.name == "shortlinks.exec":
            action = str(arguments.get("action") or "").strip()
            action_args = arguments.get("args")
            if not isinstance(action_args, dict):
                action_args = {}
            return self._dispatch_shortlinks(action, action_args, g=g)
        if tool.name == "files.exec":
            action = str(arguments.get("action") or "").strip()
            action_args = arguments.get("args")
            if not isinstance(action_args, dict):
                action_args = {}
            return self._dispatch_files(action, action_args, g=g)
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
                assert rec is not None
                g = self._g_for_agent(rec.agent_id)
                result = self._execute_tool_now(tool, arguments, g=g)
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
        agent_id = self._current_agent_id()
        if not self._is_bound():
            allow_unbound = (
                (tool.name == "credentials.exec" and action in {"delegation_request", "delegation_status", "delegation_redeem"})
                or (tool.name in {"credentials.exec", "taskboard.exec", "messages.exec", "shortlinks.exec", "files.exec"} and action == "help")
                or tool.name == "help"
                or tool.name == "credentials.status"
            )
            if not allow_unbound:
                self._require_bound_agent_id()
        rec = OperationRecord(
            operation_id=op_id,
            tool_name=tool.name,
            action=action,
            agent_id=agent_id,
            state="queued",
            submitted_at=self._now_iso(),
        )
        with self._operations_lock:
            self._operations[op_id] = rec
        self._op_queue.put((op_id, tool, arguments))
        return {
            "kind": "enabler.mcp.operation.accepted.v1",
            "operationId": op_id,
            "agentId": agent_id,
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
                if wants_async and name in {"taskboard.exec", "messages.exec", "shortlinks.exec", "files.exec", "credentials.exec"}:
                    result = self._enqueue_operation(tool, arguments)
                else:
                    result = self._execute_tool_now(
                        tool,
                        arguments,
                        g=self._g_for_agent(self._current_agent_id()),
                    )
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
