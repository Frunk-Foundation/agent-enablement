# Rename `share` to `fileshare` in Agent Command Surface

## Summary
Hard-rename agent-facing `share` surfaces to `fileshare` with no compatibility alias.

## Scope
- MCP tool rename: `share.exec` -> `fileshare.exec`
- Agent CLI group rename: `share` -> `fileshare`
- Update help catalogs, examples, tests, docs, and skills.
- No fallback aliases.

## Behavioral Contract
- Old names (`share.exec`, `enabler share ...`) fail immediately.
- New names (`fileshare.exec`, `enabler fileshare ...`) provide same actions and args (`help|file|folder`).

## Validation
- Focused tests: MCP + MCP CLI + CLI command wiring/data-plane tests.
- Smoke: list tools, call `fileshare.exec`, verify old tool fails.
