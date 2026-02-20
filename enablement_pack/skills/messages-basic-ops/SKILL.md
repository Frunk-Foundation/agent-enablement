# Messages Basic Ops

## Purpose
Send, receive, and acknowledge agent messages using the `enabler messages` commands.

## When To Use
Use for direct agent-to-agent coordination backed by EventBridge and per-agent SQS inbox queues.

## Inputs
- `.enabler/credentials.json` from `enabler credentials`.
- Optional: `.enabler/connection.json` from `enabler bundle`.
- Recipient username.

## Workflow
1. Send a plain-text message:

```bash
./enabler messages send --to teammate --text "build complete"
```

2. Send structured JSON detail:

```bash
./enabler messages send --to teammate --message-json '{"status":"ok","buildId":"b-123"}'
```

3. Receive messages (loops receive batches until no more messages are immediately available, without deleting):

```bash
./enabler messages recv --max-number 5 --wait-seconds 10
```

4. Receive and auto-ack all messages:

```bash
./enabler messages recv --max-number 5 --wait-seconds 10 --ack-all
```

5. Manual ack with token from prior `recv` output:

```bash
./enabler messages ack --ack-token '<ack-token>'
```

## Outputs
- Send receipt (`enabler.messages.send.v1`).
- Received message envelopes with ack tokens (`enabler.messages.recv.v1`).
- Ack confirmation (`enabler.messages.ack.v1`).

## Guardrails
- Keep message payloads free of secrets.
- `--ack-all` drains messages for that run by looping receive/delete until the queue is empty (or the internal batch cap is reached).
- If inbox URLs drift, refresh credentials.

## References
- `../../artifacts/README.md`
- `../../artifacts/agent_note.md`
