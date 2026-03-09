# JMAP Mail/Contacts Adoption and `eventbus.exec` Rebrand

## Summary

Adopt JMAP as the only agent-facing interface for mail by adding two MCP tools,
`jmap-mail.exec` and `jmap-contacts.exec`, backed by durable AWS storage. Rebrand
the current EventBridge + SQS direct-message surface from `messages.exec` to
`eventbus.exec` and describe it as non-mail event transport for agent workflows.
Mail state will no longer be modeled as queue receive/delete; SQS remains
available only for event-driven agent messaging outside the JMAP mail model.

## Key Changes

- Add `jmap-mail.exec` with `help`, `mailbox_get`, `email_get`, `email_query`,
  `email_set`, and `emailsubmission_set`.
- Add `jmap-contacts.exec` with `help`, `contact_get`, `contact_query`, and
  `contact_set`.
- Rebrand the current `messages.exec` tool and CLI surface to `eventbus.exec`
  while preserving the existing EventBridge/SQS behavior.
- Use DynamoDB as the durable source of truth for contacts, mailboxes, emails,
  and mail state.
- Keep EventBridge/SQS for `eventbus.exec` and optional internal async mail
  delivery plumbing, but not as the public mail interface.

## Test Plan

- MCP tool discovery and help advertise `jmap-mail.exec`,
  `jmap-contacts.exec`, and `eventbus.exec`, and remove `messages.exec`.
- `jmap-contacts.exec` supports create/update, get, query, and owner scoping.
- `jmap-mail.exec` supports submit, query, get, and state updates without queue
  receipt handle semantics.
- `eventbus.exec` preserves the current direct event send/recv/ack behavior.
- Stack, credential, and IAM tests cover the new mail/contact references and
  DynamoDB access.

## Assumptions

- `jmap-mail.exec` and `jmap-contacts.exec` remain dispatcher tools with
  documented action names.
- v1 mail starts with a single logical inbox mailbox per agent.
- v1 excludes attachments, full JMAP Session/capabilities negotiation, calendar,
  and vacation-response features.
- Stable ids use the repo's fixed 22-character base58 format.
