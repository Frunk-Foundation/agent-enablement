# Add Client SSM Retrieval to Agent MCP (`ssm.exec`)

## Summary
Implement a new MCP tool `ssm.exec` for client-side SSM discovery and retrieval using issued STS credentials.

Scope for v1:
- Tool shape: new `ssm.exec`
- Actions: `paths`, `list`, `get`
- Secret output: plaintext value returned with explicit warnings

## Public Interface Changes
- New MCP tool: `ssm.exec`
  - args: `action` (`help|paths|list|get`), `args` object, optional `async`
- `help` index updated to include `ssm.exec` and action examples.

## Action Contracts
### `ssm.exec` + `action=paths`
Return:
- `kind=enabler.ssm.paths.v1`
- `stage`, `sharedBasePath`, `agentBasePath`, `agentSub`, `agentId`, `awsRegion`

### `ssm.exec` + `action=list`
Input args:
- `scope` (`shared|agent`, default `agent`)
- `path` (optional override, must remain under allowed prefix)
- `recursive` (default `true`)
- `maxResults`, `nextToken` (optional)
Return:
- `kind=enabler.ssm.list.v1`
- `scope`, `path`, `names`, `nextToken`, `count`

### `ssm.exec` + `action=get`
Input args:
- `name` (required full SSM name)
- `withDecryption` (default `true`)
Return:
- `kind=enabler.ssm.get.v1`
- `name`, `value`, `type`, `version`, `lastModifiedDate`

## Implementation
1. Add tests first in `tests/test_enabler_mcp.py` covering tool registration/help + `paths/list/get` behavior and boundary checks.
2. Add runtime SSM helper functions in `enabler_cli/runtime_core/__init__.py` for:
   - allowed path resolution from credentials doc
   - prefix validation
   - SSM `get` and `get_parameters_by_path`
3. Register and dispatch `ssm.exec` in `enabler_cli/mcp_server.py`.
4. Add auth requirement mapping for `ssm.exec` (`agentEnablement`, no ID token requirement).
5. Permit async for `ssm.exec` in operation enqueue path.
6. Update docs:
   - `README.md`
   - root `SKILL.md`
   - `skills/ssm-key-access/SKILL.md` (MCP-first usage)

## Validation
- Run focused tests:
  - `tests/test_enabler_mcp.py`
  - `tests/test_enabler_mcp_cli.py`
- Run smoke checks with `enabler-mcp-cli`:
  - `list` contains `ssm.exec`
  - `call ssm.exec --action paths`
  - `call ssm.exec --action list`
  - `call ssm.exec --action get`

## Notes
- No admin mutation actions are added to MCP runtime.
- No migration/fallback shims.
