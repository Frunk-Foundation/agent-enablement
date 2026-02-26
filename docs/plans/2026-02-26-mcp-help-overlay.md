# Implementation Plan: MCP Help Overlay (`help` tool + `action=help`)

## Summary
Add two help surfaces to `enabler-mcp`:
1. A top-level `help` tool for brief and targeted help.
2. A `help` action on all action-driven `*.exec` tools for detailed usage.

This improves discoverability in bound and unbound sessions without changing existing operational actions.

## Behavior Contract
- Add a new MCP tool `help`.
- Add `help` to action enums for:
  - `credentials.exec`
  - `taskboard.exec`
  - `messages.exec`
  - `shortlinks.exec`
  - `files.exec`
- `help` tool behavior:
  - no args: brief index of all tools.
  - `tool`: detail for one tool.
  - `tool` + `action`: detail for one action.
- `*.exec` with `action=help` behavior:
  - no `args.action`: tool-level detail.
  - with `args.action`: action-level detail.
- Unbound mode:
  - allow `help` tool.
  - allow `*.exec action=help` without identity/credential gates.

## Output Shape
- Help responses are markdown text in normal MCP content payloads.
- Include MCP `tools/call` payload examples.

## Error Contract
- `help` with `action` but no `tool` => usage error.
- Unknown tool/action in help lookups => usage error with valid options.
- Existing error envelope remains unchanged.

## Files
- `enabler_cli/mcp_server.py`
  - register new `help` tool
  - add static help catalog
  - add `help` action branches in all action dispatchers
  - bypass bound/auth checks for `action=help`
- `tests/test_enabler_mcp.py`
  - add/adjust tests for top-level help, per-tool/action help, and unbound behavior
- `README.md`
  - document the new `help` tool and new `help` actions
- `SKILL.md`
  - add one note about using MCP help during bootstrap

## Test Plan
1. `tools/list` includes `help`.
2. top-level `help` index works.
3. `help` with `tool` works.
4. `help` with `tool+action` works.
5. invalid help lookups return usage errors.
6. unbound `*.exec action=help` succeeds.
7. existing actions remain unchanged.
