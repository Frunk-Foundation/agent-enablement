# Implementation Plan: MCP Startup Green Recovery

## Goal
Restore reliable startup for `agent-enablement` MCP in Codex sessions.

## Scope
- Make `enabler-mcp` launcher cwd-independent.
- Keep strict startup identity requirement (`--agent-id` / `ENABLER_AGENT_ID`) and improve startup error clarity.
- Add regression tests for non-repo cwd startup and identity contract.
- Update local Codex MCP config with explicit `agent_id`.
- Update README/SKILL with operational guidance.
