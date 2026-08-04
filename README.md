# Mail Relay

Mail Relay is a self-hosted Outlook mailbox management service with encrypted credential storage, scheduled token rotation, and protected public inbox links.

## Features

- Import Outlook accounts in bulk using `email----password----client_id----refresh_token`.
- Refresh Microsoft OAuth refresh tokens on a configurable schedule and store the latest token.
- Read mailbox messages through IMAP with XOAUTH2 authentication.
- Isolate mailbox data, messages, exports, and refresh logs between users.
- Define hidden-mail aliases under each Outlook account, filter archived messages by the recipient address, and create a protected public link for each alias.
- Group aliases with tags and search them by alias, mailbox, or tag from the management view.
- Create public mailbox links on a separate domain. Visitors complete a CAPTCHA before viewing the newest message.
- Copy, export, refresh, and manage accounts from the web interface.

## Security

Passwords, refresh tokens, and access tokens are encrypted with Fernet before they are stored in SQLite. Exported files contain plaintext credentials, so keep them secure.

The public share domain is configured with `PUBLIC_SHARE_ORIGIN`. The main management interface is served from `/admin`; the public domain only accepts valid shared mailbox links.

Shared links can be configured with an expiry period or revoked immediately. Expired and revoked tokens no longer expose mailbox content.

Responses include a restrictive content security policy and standard browser security headers.

## Getting Started

1. Copy `.env.example` to `.env` and set real secrets and administrator credentials.
2. Run `docker compose up -d --build`.
3. The container listens on `127.0.0.1:8765`; place Nginx or another HTTPS reverse proxy in front of it.

Docker Compose starts a web container and a separate mail archive worker. The browser does not poll the mailbox list automatically. The archive worker synchronizes the latest configured mailbox window every `MAIL_SYNC_INTERVAL_SECONDS` (five minutes by default), and shared links read that local archive. The web container rotates tokens at the configured interval, which defaults to seven days. A refresh token can still be invalidated by revoked consent, password changes, account protection, or Microsoft policy.
