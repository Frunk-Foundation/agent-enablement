# JMAP Mail Attachments via Fileshare-Backed Assets

## Summary

Add first-class mail attachments to `jmap-mail.exec` using the existing
fileshare/S3 upload path as the backing store. V1 attachments are durable
attachment metadata on mail records plus public file URLs, and
`emailsubmission_set` supports both pre-uploaded attachment references and
direct local file path uploads before mail submission.

## Key Changes

- Extend `jmap-mail.exec` `emailsubmission_set` to accept `attachments` and
  `attachmentFilePaths`.
- Persist normalized attachment metadata on each email record.
- Return attachments from `email_get` and `email_query`.
- Reuse existing fileshare upload behavior and public URL shape.

## Test Plan

- Submit mail with pre-uploaded attachments.
- Submit mail with local file path uploads.
- Submit mail with both modes together.
- Verify `email_query` and `email_get` return normalized attachments.
- Reject malformed attachment objects and missing local files.

## Assumptions

- V1 attachments use public fileshare-backed URLs.
- V1 supports both pre-uploaded references and direct local file path upload.
- V1 keeps attachment metadata embedded in each email record.
