# Hard Cleanup: Remove Obsolete Bundle/Pack Surface End-to-End

## Summary
Execute a single breaking cleanup that fully removes the obsolete bundle/enablement-pack architecture and legacy monolithic CLI surface. Keep only the active model: `enabler-creds` + `enabler-mcp` + `enabler-mcp-cli` + `enabler-admin` (admin-only controls). No fallback behavior, no compatibility aliases.

## Scope and Success Criteria
1. Remove all repo code, tests, docs, and infra wiring for:
   - `enablement_pack/*`
   - `/v1/bundle` route and `BundleHandler`
   - `BundleInvokeUrl` output
   - Legacy bundle/pack CLI commands and references
   - `ENABLER_BUNDLE_ENDPOINT` references
   - `runtime.bundlePolicy` in credentials response
   - Dormant legacy monolith `enabler_cli/cli.py`
2. Preserve and verify active flows:
   - Credentials lifecycle (`enabler-creds`)
   - MCP server (`enabler-mcp`)
   - MCP local wrapper (`enabler-mcp-cli`)
   - Admin CLI (`enabler-admin`)
   - Taskboard/messages/share/shortlinks
3. Deploys cleanly and smoke checks pass in `us-east-2` with the normal profile.

## Public Interface Changes (Breaking)
1. API:
   - Remove `POST /v1/bundle`.
   - `BundleInvokeUrl` CloudFormation output removed.
   - Any call to `/v1/bundle` now returns API Gateway not-found behavior (404).
2. Credentials payload:
   - Remove `runtime.bundlePolicy` object from `agent-enablement.credentials.v2`.
3. CLI/env:
   - Remove bundle endpoint env usage (`ENABLER_BUNDLE_ENDPOINT`) from active docs/examples/tests.
   - Remove all bundle/pack command references from user-facing docs and helper recipes.
4. Python module surface:
   - Remove legacy `enabler_cli/cli.py` module and any dead references to it.

## Implementation
1. Remove obsolete source trees and handlers.
2. Remove bundle infra from CDK.
3. Remove bundle metadata from credentials response.
4. Remove dormant legacy monolithic CLI.
5. Clean repo command/document surfaces.
6. Update and prune tests.
7. Verify, deploy, and smoke.
