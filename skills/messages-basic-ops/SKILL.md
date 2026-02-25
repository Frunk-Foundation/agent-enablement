# Messages Basic Ops

## Purpose
Send, receive, and acknowledge direct messages through MCP message tools.

## When To Use
Use for direct agent-to-agent coordination backed by EventBridge and per-agent SQS inbox queues.

## Inputs
- Fresh credentials from `./enabler-creds summary`.
- Running `./enabler-mcp` process.
- Recipient username.

## Workflow
Use MCP tool `messages.exec` with `action` + `args`:
1. `action=send` with `args.to` + `args.text` (or structured `args.messageJson`).
2. `action=recv` to read inbox messages.
3. `action=ack` with `args.ackToken` for manual deletion.
4. Optional long-running mode: include `async=true` and poll `ops.result`.

## Outputs
- Send receipt (`enabler.messages.send.v1`).
- Received message envelopes with ack tokens (`enabler.messages.recv.v1`).
- Ack confirmation (`enabler.messages.ack.v1`).

## Guardrails
- Keep message payloads free of secrets.
- Use `ackAll=true` only when intentional; it drains available inbox messages for that run.
- If permissions drift, refresh credentials and retry.

## References
- `../../README.md`

