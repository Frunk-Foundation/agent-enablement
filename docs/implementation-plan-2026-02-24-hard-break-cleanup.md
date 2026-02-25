# Implementation Plan: Hard-Break Cleanup After Enabler Split

## Behavior First
- Bundle/runtime path is removed from agent/runtime code.
- Runtime commands/tools resolve from credentials references only.
- `connection.json` is no longer part of credential artifact summaries.
- Migration docs and examples no longer reference `./enabler` runtime commands.

## Deliverables
1. Remove agent bundle command wiring and implementation from runtime CLI module.
2. Remove connection-cache runtime fallback helpers.
3. Update credentials summaries/docs to omit `connection.json` as primary artifact.
4. Update tests to remove/replace bundle-runtime assumptions.
5. Remove admin handoff bundle endpoint/env outputs.

## Sequence
1. Remove `bundle` command + helper functions from `enabler_cli/cli.py` and command registration.
2. Remove connection-cache fallback usage for taskboard/shortlinks/files in runtime paths.
3. Remove `bundleEndpoint` and `ENABLER_BUNDLE_ENDPOINT` from admin handoff flows.
4. Update summaries/help strings and docs (`README`, migration docs).
5. Update tests to reflect hard break and credentials-reference-only behavior.
6. Run targeted tests and smoke checks.
7. Commit with BREAKING CHANGE footer.
