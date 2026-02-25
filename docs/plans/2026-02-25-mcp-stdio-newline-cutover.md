# Implementation Plan: MCP stdio newline framing cutover

## Goal
Fix Codex MCP startup timeout by aligning `./enabler-mcp` stdio transport with MCP newline-delimited JSON-RPC framing.

## Scope
- In: `enabler_cli/mcp_server.py` stdio framing, one transport regression test, docs updates.
- Out: runtime tool business logic and credential issuance behavior.

## Decisions
- Hard cutover now: newline-delimited JSON only.
- No `Content-Length` compatibility mode.

## Steps
1. Replace `Content-Length` read/write in `enabler_cli/mcp_server.py` with newline-delimited JSON message handling.
2. Keep process alive on malformed frames and return JSON-RPC parse error (`-32700`).
3. Add a single subprocess-based transport test that validates `initialize` and `tools/list` over newline framing.
4. Document newline framing and timeout troubleshooting in `README.md`.
5. Add SKILL note capturing the framing mismatch lesson.
6. Run targeted tests and smoke handshake.
7. Commit with Conventional Commit + BREAKING CHANGE footer.

## Acceptance
- `./enabler-mcp` responds to newline-delimited `initialize` within startup window.
- `tools/list` succeeds over same session.
- New transport test passes.
