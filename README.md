# Mail Relay

Mail Relay is a self-hosted Outlook mailbox management service with encrypted credential storage, scheduled token rotation, and protected public inbox links.

## Features

- Import Outlook accounts in bulk using `email----password----client_id----refresh_token`.
- Refresh Microsoft OAuth refresh tokens on a configurable schedule and store the latest token.
- Read mailbox messages through IMAP with XOAUTH2 authentication.
- Add an Outlook account through Microsoft device authorization with an Azure application client ID.
- Isolate mailbox data, messages, exports, and refresh logs between users.
- Define hidden-mail aliases under each Outlook account, filter archived messages by the recipient address, and create a protected public link for each alias.
- Group aliases with tags and search them by alias, mailbox, or tag from the management view.
- Create public mailbox links on a separate domain. Visitors complete a server-validated CAPTCHA before browsing newest-first message pages.
- Copy, export, refresh, and manage accounts from the web interface.

## Security

Passwords, refresh tokens, and access tokens are encrypted with Fernet before they are stored in SQLite. Exported files contain plaintext credentials, so keep them secure.

The public share domain is configured with `PUBLIC_SHARE_ORIGIN`. The main management interface is served from `/admin`; the public domain only accepts valid shared mailbox links.

Shared links can be configured with an expiry period or revoked immediately. Expired and revoked tokens no longer expose mailbox content.

Responses include a restrictive content security policy and standard browser security headers. Browser icons are served locally so the management page does not execute third-party CDN scripts. The container applies a private file-creation mask to the database and backup files.

The provided Nginx configurations rate-limit login attempts, CAPTCHA generation, verification attempts, and public refresh requests. Public mailbox refreshes also have a server-side 10-second cooldown with a disabled-button countdown in the shared mailbox view.

## Microsoft Device Authorization

Register or use a Microsoft Entra application that permits public client and device-code flows, with delegated `IMAP.AccessAsUser.All` and `offline_access` permissions. In Mail Relay, choose **Authorization Add**, enter the Outlook address and that application's client ID, then complete the code on the Microsoft page.

The device code is encrypted in SQLite while it is pending and is cleared after authorization completes or fails. It is intended only for the person who owns the mailbox; do not share an authorization code with anyone else.

New accounts created through device authorization export an empty password field because IMAP XOAUTH2 uses the OAuth tokens instead of the Outlook password.

## Getting Started

1. Copy `.env.example` to `.env` and set real secrets and administrator credentials.
2. Run `docker compose up -d --build`.
3. The container listens on `127.0.0.1:8765`; place Nginx or another HTTPS reverse proxy in front of it.

Docker Compose starts a web container and a separate task worker. The browser does not poll the mailbox list automatically. The worker exclusively rotates tokens, processes durable manual refresh jobs, and synchronizes all unseen IMAP UIDs every `MAIL_SYNC_INTERVAL_SECONDS` (five minutes by default). Each mailbox sync uses one IMAP session and writes bounded batches. If IMAP UIDVALIDITY changes, a complete replacement snapshot is staged before the existing archive is atomically replaced. Shared links read the local archive in newest-first pages. Token rotation defaults to seven days. A refresh token can still be invalidated by revoked consent, password changes, account protection, or Microsoft policy.
