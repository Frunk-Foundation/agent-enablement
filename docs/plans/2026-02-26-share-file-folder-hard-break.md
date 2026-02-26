# Share File/Folder Hard Break

## Summary
Replace legacy `files` surfaces with a new `share` surface:
- `share.file` uploads one file
- `share.folder` recursively uploads a folder preserving relative paths under one shared prefix

This supports static-site style uploads where multiple pages/assets share one key prefix.

## Decisions
- Hard break: remove `files.exec` and `files` CLI group.
- Folder recursion preserves full tree rooted at the given folder.
- Default output for folder uploads is a manifest + site base metadata.
- Hidden files excluded by default; symlinks not followed by default.

## Interface Changes
- MCP tool: `files.exec` -> `share.exec` actions `help|file|folder`
- CLI group: `files share` -> `share file` and `share folder`
- Output kinds:
  - `enabler.share.file-upload.v1`
  - `enabler.share.folder-upload.v1`

## Implementation
1. Add file/folder share command functions in runtime command module.
2. Replace CLI command group wiring and handlers.
3. Replace MCP tool registration/dispatch/help catalog/examples.
4. Update runtime exports and docs.
5. Add/adjust tests for new names and folder recursion behavior.

## Validation
- Targeted MCP tests pass.
- Targeted data-plane tests pass (file + folder paths).
- Tool/docs references no longer mention `files.exec`.
