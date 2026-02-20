# S3 Upload Guide (Read Carefully)

You have permission to upload to S3, but it is intentionally constrained.

What you can do:
- Upload objects only under your principal-scoped prefix: `f/<principal-sub-base58-22>/...`
- Use simple PUT uploads for small files.
- Use multipart upload for large files (initiate, upload parts, complete, abort).

Important behaviors:
- The issued prefix is deterministic per principal (`sub`). Refreshing credentials keeps the same prefix.
- Object retention is controlled by bucket lifecycle rules (this stack commonly expires objects after ~30 days).

What you cannot do (expected AccessDenied):
- List all buckets.
- Upload outside your issued ID prefix.
- Read/download objects outside your issued ID prefix.

How to find the bucket and allowed prefix:
- In `credentials.json`, use `references.s3.bucket` and `references.s3.allowedPrefix`.
- The allowed resource ARN in `grants` also includes the bucket name and your principal prefix.

Key format:
- Always write keys like: `<allowedPrefix><filename>` (where `allowedPrefix` comes from the response).
- The prefix ends with `/`. Do not drop that slash when building keys.

Presigned URLs:
- You may generate presigned PUT URLs using the issued credentials.
- You may generate presigned GET URLs for objects you uploaded within your issued prefix.
- Presigned URLs are bearer secrets. Anyone with the URL can upload until it expires.
- Prefer short expirations (for example 60 to 900 seconds).

Multipart notes:
- Multipart uploads may require bucket-level listing for multipart state; that is allowed only for multipart-related listing.
- If you get AccessDenied, double-check the key starts with your principal-scoped prefix.
