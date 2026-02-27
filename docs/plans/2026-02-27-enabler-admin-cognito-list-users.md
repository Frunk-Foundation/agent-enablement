# Implementation Plan: `enabler-admin cognito list-users`

## Behavior Contract
- Add a new command: `enabler-admin cognito list-users`.
- Default behavior excludes ephemeral users (usernames prefixed with `ephem-`).
- Add explicit opt-in to include ephemeral users: `--include-ephemeral`.
- Command targets the resolved Cognito user pool:
  - default from stack output `UserPoolId`,
  - optional override via `--user-pool-id`.
- Human-readable output (default): one line per user with username, status, enabled flag, and create timestamp.
- JSON output (optional): `--json` prints a machine-readable object with:
  - `userPoolId`,
  - `includeEphemeral`,
  - `count`,
  - `users[]` entries including `username`, `status`, `enabled`, `createdAt`, `updatedAt`, `attributes`.
- Pagination is handled transparently so all users are returned.
- Fail fast with existing admin error primitives when AWS calls fail.

## CLI Surface
- New subcommand under Cognito app:
  - `enabler-admin cognito list-users [--include-ephemeral] [--json] [--user-pool-id <id>]`
- Keep output conventions aligned with existing CLI:
  - pretty JSON controlled by global pretty settings,
  - compact JSON where applicable using existing `_print_json` path.

## Implementation Steps
1. Add command handler in `enabler_cli/admin_commands.py`:
   - call Cognito `list_users` with paginator,
   - normalize returned fields into stable output shape,
   - filter `ephem-` usernames unless `--include-ephemeral` is true,
   - emit JSON or human-readable output depending on args.
2. Wire command in `enabler_cli/apps/agent_admin_cli.py`:
   - add `@cognito_app.command("list-users")`,
   - add flags `--include-ephemeral`, `--json`, `--user-pool-id`.
3. Update docs in `README.md`:
   - add usage examples for default (non-ephemeral) listing,
   - add example with `--include-ephemeral`,
   - add JSON example with `--json`.
4. Record any unexpected implementation gotchas in `SKILL.md` (only if encountered).

## Tests (Red -> Green -> Refactor)
- Add CLI tests that fail first, then implement:
  - default run excludes `ephem-` users,
  - `--include-ephemeral` includes them,
  - `--json` returns expected top-level keys and user objects,
  - pagination path merges multiple pages,
  - empty result set prints valid empty output in both modes.
- Keep tests focused on meaningful behavior paths and command output contract.

## Files
- `enabler_cli/admin_commands.py`
- `enabler_cli/apps/agent_admin_cli.py`
- `tests/...` (new/updated admin CLI coverage for Cognito list-users)
- `README.md`
- `SKILL.md` (only if unexpected issues occur)

## Acceptance Criteria
- `enabler-admin cognito list-users` exists and succeeds against current pool.
- By default, output contains no `ephem-` users.
- `--include-ephemeral` includes `ephem-` users.
- `--json` emits stable machine-readable output for scripting.
- Tests cover default filter, opt-in inclusion, pagination, and output shape.
