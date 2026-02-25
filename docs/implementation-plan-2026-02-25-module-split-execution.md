# Implementation Plan - Module Split Execution (2026-02-25)

## Goal
Split runtime/admin/mcp/creds internals into separate module groups in-repo and remove `enabler_cli.cli` as a public import path.

## Decisions
- Hard break: no compatibility import path for `enabler_cli.cli`.
- Single distributable package remains.
- Keep wrapper scripts (`enabler-mcp`, `enabler-creds`, `enabler-admin`) stable.

## Steps
1. Create module groups:
   - `enabler_cli/runtime_core/`
   - `enabler_cli/admin_core/`
   - `enabler_cli/apps/`
2. Move monolithic CLI implementation file to `enabler_cli/apps/agent_admin_cli.py` and delete `enabler_cli/cli.py`.
3. Add `runtime_core` and `admin_core` re-export modules as the new import surfaces for shared/runtime/admin functions currently consumed by MCP/creds/tests.
4. Rewire entrypoints:
   - `enabler_cli/mcp_main.py`
   - `enabler_cli/creds_main.py`
   - `enabler_cli/admin_main.py`
   - `enabler_cli/__main__.py`
   to import from new modules.
5. Rewire MCP server imports to `runtime_core`.
6. Rewrite tests to import from the new surfaces.
7. Run focused tests:
   - `tests/test_enabler_mcp.py`
   - `tests/test_enabler_creds_cli.py`
   - `tests/test_enabler_cli_data_plane.py`
   - `tests/test_enabler_cli_taskboard.py`
   - `tests/test_enabler_cli_utils.py`
   - `tests/test_enabler_cli_handoff.py`
8. Run smoke checks:
   - `./enabler-creds --help`
   - `./enabler-mcp` startup handshake check via tests.
9. Commit with Conventional Commit + BREAKING CHANGE.
