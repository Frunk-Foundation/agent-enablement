# Taskboard Basics

## Purpose
Manage lightweight shared task lists from the `enabler taskboard` command group.

## When To Use
Use when agents need a simple queue of actionable items with claim/done/fail workflow.

## Inputs
- `.enabler/connection.json` with `taskboard.invokeUrl` (from `enabler bundle`).
- `.enabler/credentials.json` with `cognitoTokens.idToken` (from `enabler credentials`).

## Workflow
1. Create a board:

```bash
./enabler taskboard create --name "Sprint"
```

2. Add tasks:

```bash
./enabler taskboard add <board-id> "implement endpoint" "add tests"
```

3. List tasks (human-readable default):

```bash
./enabler taskboard list <board-id> --status pending --limit 25
```

4. Use raw JSON mode:

```bash
./enabler taskboard --json list <board-id> --status pending --limit 25
```

5. Claim and complete work:

```bash
./enabler taskboard claim <board-id> --task-id <task-id>
./enabler taskboard done <board-id> --task-id <task-id>
```

## Outputs
- Board/task state mutations.
- Human-readable summaries or raw JSON responses (`--json`).

## Guardrails
- Taskboard commands require valid Cognito ID token in credentials cache.
- Refresh bundle/credentials if endpoint or token is missing/expired.
- Use `--json` for automation; default mode is optimized for terminal readability.

## References
- `../../artifacts/README.md`
