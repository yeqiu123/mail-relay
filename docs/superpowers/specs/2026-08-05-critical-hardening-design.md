# Critical Security and Refresh Hardening

## Scope

This change fixes the confirmed critical and high-priority issues in public-link verification, Microsoft authorization validation, refresh task durability, cross-process token rotation, mailbox synchronization completeness, and disabled-user isolation.

## Architecture

- Public CAPTCHA answers are stored server-side. The browser receives only a random challenge ID.
- The web process creates durable refresh jobs and exposes their status. It does not call Microsoft token or IMAP endpoints for full refreshes.
- The worker process claims queued job items, performs forced token refresh followed by inbox synchronization, and persists the final account and job states.
- Automatic token refresh and mailbox synchronization are also owned by the worker, preventing cross-process refresh-token rotation.
- Mailbox synchronization stores IMAP UIDVALIDITY and a UID watermark, then fetches all unseen messages in bounded batches.
- Public mailbox pages load newest-first pages instead of rendering every archived body in one response.
- Public links require an enabled owner; disabling a user immediately blocks their links without deleting them.

## Failure Handling

- Permanent Microsoft authorization errors remain `invalid`; transient errors remain `error`.
- Interrupted refresh job items are reclaimed after a lease expires.
- CAPTCHA challenges expire, have a maximum attempt count, and are consumed on success.
- UIDVALIDITY changes reset the synchronization watermark before the mailbox is scanned again.

## Compatibility

- Existing account, mailbox, public-link, and user-management APIs remain available.
- The existing refresh-job polling response shape is preserved.
- Existing archived messages and public-link tokens are retained during migration.

## Verification

- Database initialization and migration complete on an existing database.
- CAPTCHA cookies do not contain answers.
- Manual refresh performs a real token request and preserves permanent failures.
- Refresh jobs survive process restart and are completed by the worker.
- More than one configured page of unseen IMAP messages is archived without gaps.
- Disabled users' public links return not found.
- Python compilation, JavaScript syntax checks, and production health checks pass.
