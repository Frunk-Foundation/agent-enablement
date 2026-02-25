# Implementation Plan: MCP Runtime Agent Switching

## Goal
Allow MCP runtime identity switching via a single `context.set_agentid` tool while preserving startup `--agent-id` as initial default.

## Scope
- Add `context.set_agentid` tool.
- Pin `agent_id` per async operation to prevent identity drift.
- Keep existing tool input surfaces unchanged.
- Update tests/docs and expose identity in status/ops results.
