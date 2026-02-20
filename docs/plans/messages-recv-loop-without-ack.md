# messages recv loop behavior without --ack-all

## Behavior first
- `./enabler messages recv` should loop receive batches until no messages are returned for this run.
- `--ack-all` continues to mean delete each received message while looping.
- Without `--ack-all`, messages are never deleted; output includes ack tokens only.

## Red -> Green -> Refactor
1. Red
   - Add tests that prove non-ack mode loops across multiple receive batches.
   - Add tests for non-ack mode respecting bounded batch safety cap.
2. Green
   - Remove the current single-batch break in non-ack mode.
   - Apply a shared bounded-loop guard for both ack and non-ack receive loops.
3. Refactor
   - Keep loop control and output metadata readable with minimal branch complexity.

## Acceptance checks
- Non-ack recv returns multiple messages from multiple receive calls in one invocation.
- Ack-all still deletes and reports drain details.
- Non-ack mode does not delete messages and does not claim drain in output.

## Smoke check
- Enqueue 2+ messages.
- Run `./enabler messages recv --max-number 1 --wait-seconds 1` once; it should return more than one message in one invocation.
- Run `./enabler messages recv --max-number 1 --wait-seconds 1 --ack-all`; subsequent receive should return 0.
