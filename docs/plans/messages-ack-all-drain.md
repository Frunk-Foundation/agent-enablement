# messages recv --ack-all drain behavior

## Behavior first
- `./enabler messages recv --ack-all` must keep receiving and deleting messages until SQS returns no messages for the invocation.
- Non-ack mode keeps existing single-receive behavior.
- Default `--max-number` remains batch size per receive call, not total drained count.
- Prevent infinite drain loops with a bounded max batch count.

## Red -> Green -> Refactor
1. Red
   - Update/add tests that fail under current single-batch ack-all behavior.
   - Cover multi-batch drain and max-batch guardrail.
2. Green
   - Implement ack-all drain loop in `cmd_messages_recv`.
   - Keep `_ack` token + delete status fields stable.
3. Refactor
   - Keep message formatting/ack logic readable and avoid duplicated code paths.

## Acceptance checks
- `messages recv --ack-all` deletes all currently available messages in one invocation.
- Output indicates ack-all was requested and whether drain loop was truncated by batch cap.
- Existing `messages ack` behavior unchanged.

## Smoke check
- Send two messages to self.
- Run `./enabler messages recv --ack-all --max-number 1` once.
- Immediate second run should report `received: 0`.
