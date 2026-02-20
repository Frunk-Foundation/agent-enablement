# Implementation Plan - 2026-02-19 - STS API Gateway Invoke Access

## Goal
Ensure STS credentials issued by `/v1/credentials` can invoke API Gateway APIs in the sandbox account limited to `us-east-2`.

## Behavior
- Runtime-issued STS creds must include `execute-api:Invoke` permission.
- Scope must be sandbox-account-local and `us-east-2` only.
- Permission must be effective through both runtime role inline policy and runtime permissions boundary.
- Credentials response grants should document API invoke access for agents.

## Steps
1. Add `execute-api:Invoke` scoped statement to `IssuedCredsBoundary` in stack.
2. Add matching scoped statement to `AgentBrokerTargetRole` runtime inline policy.
3. Add execute-api grant entry to credentials handler response for runtime scope.
4. Add/adjust unit tests for stack IAM guardrails and credentials grant contract.
5. Run targeted tests for updated modules.
