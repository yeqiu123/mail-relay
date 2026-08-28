from __future__ import annotations

import hmac
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

from .security import Vault, hash_password, verify_password


DEFAULT_SETTINGS = {
    "tenant": "consumers",
    "refresh_interval_days": "7",
    "mail_page_size": "30",
}
MAX_ACTIVE_REFRESH_ITEMS_PER_OWNER = 5000
RECIPIENT_HEADER_VERSION = "2"


class Store:
    def __init__(self, database_path: Path, vault: Vault) -> None:
        self.database_path = database_path
        self.vault = vault
        self._write_lock = threading.RLock()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 30000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
        return {
            str(row["name"])
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }

    @staticmethod
    def _has_owner_email_unique(connection: sqlite3.Connection) -> bool:
        for index in connection.execute("PRAGMA index_list(accounts)").fetchall():
            if not int(index["unique"]):
                continue
            columns = [
                str(row["name"])
                for row in connection.execute(
                    f"PRAGMA index_info({index['name']})"
                ).fetchall()
            ]
            if columns == ["owner_id", "email"]:
                return True
        return False

    @staticmethod
    def _create_accounts_table(
        connection: sqlite3.Connection,
        table: str = "accounts",
    ) -> None:
        connection.execute(
            f"""
            CREATE TABLE {table} (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id              INTEGER NOT NULL,
                provider              TEXT NOT NULL DEFAULT 'outlook',
                email                 TEXT NOT NULL COLLATE NOCASE,
                icloud_alias          TEXT,
                password_cipher       TEXT NOT NULL,
                client_id             TEXT NOT NULL,
                refresh_token_cipher  TEXT NOT NULL,
                access_token_cipher   TEXT,
                access_expires_at     INTEGER,
                status                TEXT NOT NULL DEFAULT 'pending',
                full_refresh_pending  INTEGER NOT NULL DEFAULT 0,
                last_refresh_at       INTEGER,
                next_refresh_at       INTEGER,
                last_mail_at          INTEGER,
                last_archive_sync_at  INTEGER,
                imap_uid_validity     TEXT,
                last_synced_uid       INTEGER,
                last_error            TEXT,
                last_mail_error       TEXT,
                last_error_code       TEXT,
                last_error_source     TEXT,
                last_error_at         INTEGER,
                created_at            INTEGER NOT NULL,
                updated_at            INTEGER NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(owner_id, email)
            )
            """
        )

    @staticmethod
    def _create_refresh_logs_table(
        connection: sqlite3.Connection,
        table: str = "refresh_logs",
    ) -> None:
        connection.execute(
            f"""
            CREATE TABLE {table} (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id  INTEGER,
                owner_id    INTEGER NOT NULL,
                email       TEXT NOT NULL,
                outcome     TEXT NOT NULL,
                message     TEXT,
                created_at  INTEGER NOT NULL,
                FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE SET NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

    @staticmethod
    def _create_share_links_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS share_links (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id        INTEGER NOT NULL,
                account_id      INTEGER NOT NULL,
                token           TEXT NOT NULL UNIQUE,
                created_at      INTEGER NOT NULL,
                updated_at      INTEGER NOT NULL,
                last_access_at  INTEGER,
                expires_at      INTEGER,
                revoked_at      INTEGER,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE,
                UNIQUE(owner_id, account_id)
            )
            """
        )

    @staticmethod
    def _create_mail_messages_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mail_messages (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id        INTEGER NOT NULL,
                account_id      INTEGER NOT NULL,
                uid             TEXT NOT NULL,
                message_id      TEXT,
                subject         TEXT NOT NULL,
                sender_name     TEXT,
                sender_address  TEXT,
                received_at     INTEGER,
                body            TEXT NOT NULL,
                created_at      INTEGER NOT NULL,
                updated_at      INTEGER NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE,
                UNIQUE(account_id, uid)
            )
            """
        )

    @staticmethod
    def _create_mail_recipients_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mail_recipients (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                mail_message_id INTEGER NOT NULL,
                email           TEXT NOT NULL COLLATE NOCASE,
                recipient_type  TEXT NOT NULL,
                FOREIGN KEY(mail_message_id) REFERENCES mail_messages(id) ON DELETE CASCADE,
                UNIQUE(mail_message_id, email, recipient_type)
            )
            """
        )

    @staticmethod
    def _create_mail_sync_staging_tables(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS mail_sync_state (
                account_id       INTEGER PRIMARY KEY,
                uid_validity     TEXT NOT NULL,
                last_synced_uid  INTEGER NOT NULL DEFAULT 0,
                started_at       INTEGER NOT NULL,
                updated_at       INTEGER NOT NULL,
                FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS mail_sync_messages (
                account_id      INTEGER NOT NULL,
                uid             TEXT NOT NULL,
                message_id      TEXT,
                subject         TEXT NOT NULL,
                sender_name     TEXT,
                sender_address  TEXT,
                received_at     INTEGER,
                body            TEXT NOT NULL,
                created_at      INTEGER NOT NULL,
                updated_at      INTEGER NOT NULL,
                PRIMARY KEY(account_id, uid),
                FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS mail_sync_recipients (
                account_id      INTEGER NOT NULL,
                uid             TEXT NOT NULL,
                email           TEXT NOT NULL COLLATE NOCASE,
                recipient_type  TEXT NOT NULL,
                PRIMARY KEY(account_id, uid, email, recipient_type),
                FOREIGN KEY(account_id, uid)
                    REFERENCES mail_sync_messages(account_id, uid) ON DELETE CASCADE
            );
            """
        )

    @staticmethod
    def _create_mail_targets_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mail_targets (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id    INTEGER NOT NULL,
                account_id  INTEGER NOT NULL,
                email       TEXT NOT NULL COLLATE NOCASE,
                enabled     INTEGER NOT NULL DEFAULT 1,
                created_at  INTEGER NOT NULL,
                updated_at  INTEGER NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE,
                UNIQUE(owner_id, account_id, email)
            )
            """
        )

    @staticmethod
    def _create_target_share_links_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS target_share_links (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id        INTEGER NOT NULL,
                target_id       INTEGER NOT NULL,
                token           TEXT NOT NULL UNIQUE,
                created_at      INTEGER NOT NULL,
                updated_at      INTEGER NOT NULL,
                last_access_at  INTEGER,
                expires_at      INTEGER,
                revoked_at      INTEGER,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(target_id) REFERENCES mail_targets(id) ON DELETE CASCADE,
                UNIQUE(owner_id, target_id)
            )
            """
        )

    @staticmethod
    def _create_mail_tags_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mail_tags (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id    INTEGER NOT NULL,
                name        TEXT NOT NULL COLLATE NOCASE,
                created_at  INTEGER NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(owner_id, name)
            )
            """
        )

    @staticmethod
    def _create_mail_target_tags_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mail_target_tags (
                target_id  INTEGER NOT NULL,
                tag_id     INTEGER NOT NULL,
                PRIMARY KEY(target_id, tag_id),
                FOREIGN KEY(target_id) REFERENCES mail_targets(id) ON DELETE CASCADE,
                FOREIGN KEY(tag_id) REFERENCES mail_tags(id) ON DELETE CASCADE
            )
            """
        )

    @staticmethod
    def _create_oauth_device_flows_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_device_flows (
                id                         TEXT PRIMARY KEY,
                owner_id                   INTEGER NOT NULL,
                email                      TEXT NOT NULL COLLATE NOCASE,
                client_id                  TEXT NOT NULL,
                tenant                     TEXT NOT NULL,
                device_code_cipher         TEXT,
                verification_uri           TEXT NOT NULL,
                verification_uri_complete  TEXT,
                user_code                  TEXT NOT NULL,
                expires_at                 INTEGER NOT NULL,
                interval_seconds           INTEGER NOT NULL,
                status                     TEXT NOT NULL DEFAULT 'pending',
                account_id                 INTEGER,
                last_error                 TEXT,
                created_at                 INTEGER NOT NULL,
                updated_at                 INTEGER NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE SET NULL
            )
            """
        )

    @staticmethod
    def _create_captcha_challenges_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS captcha_challenges (
                id             TEXT PRIMARY KEY,
                share_token    TEXT NOT NULL,
                answer_digest  TEXT NOT NULL,
                attempts       INTEGER NOT NULL DEFAULT 0,
                expires_at     INTEGER NOT NULL,
                created_at     INTEGER NOT NULL
            )
            """
        )

    @staticmethod
    def _create_refresh_jobs_tables(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS refresh_jobs (
                id             TEXT PRIMARY KEY,
                owner_id       INTEGER NOT NULL,
                mode           TEXT NOT NULL,
                public_token   TEXT,
                status         TEXT NOT NULL DEFAULT 'queued',
                total          INTEGER NOT NULL DEFAULT 0,
                completed      INTEGER NOT NULL DEFAULT 0,
                succeeded      INTEGER NOT NULL DEFAULT 0,
                failed         INTEGER NOT NULL DEFAULT 0,
                created_at     INTEGER NOT NULL,
                updated_at     INTEGER NOT NULL,
                completed_at   INTEGER,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS refresh_job_items (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id         TEXT NOT NULL,
                account_id     INTEGER,
                status         TEXT NOT NULL DEFAULT 'queued',
                error          TEXT,
                claimed_at     INTEGER,
                completed_at   INTEGER,
                FOREIGN KEY(job_id) REFERENCES refresh_jobs(id) ON DELETE CASCADE,
                FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE SET NULL,
                UNIQUE(job_id, account_id)
            );
            """
        )

    @staticmethod
    def _create_service_heartbeats_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS service_heartbeats (
                name        TEXT PRIMARY KEY,
                updated_at  INTEGER NOT NULL
            )
            """
        )

    @staticmethod
    def _ensure_share_link_columns(connection: sqlite3.Connection) -> None:
        for table in ("share_links", "target_share_links"):
            columns = Store._columns(connection, table)
            if "expires_at" not in columns:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN expires_at INTEGER")
            if "revoked_at" not in columns:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN revoked_at INTEGER")

    @staticmethod
    def _link_is_active(row: sqlite3.Row, now: int) -> bool:
        return row["revoked_at"] is None and (
            row["expires_at"] is None or int(row["expires_at"]) > now
        )

    def _ensure_admin(
        self,
        connection: sqlite3.Connection,
        username: str,
        password: str,
    ) -> int:
        now = int(time.time())
        existing = connection.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
        if existing:
            admin_id = int(existing["id"])
            password_changed = not verify_password(
                password,
                str(existing["password_hash"]),
            )
            session_changed = (
                password_changed
                or str(existing["role"]) != "admin"
                or not bool(existing["enabled"])
            )
            connection.execute(
                """
                UPDATE users
                SET password_hash = ?, role = 'admin', enabled = 1,
                    session_version = session_version + ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    hash_password(password)
                    if password_changed
                    else str(existing["password_hash"]),
                    1 if session_changed else 0,
                    now,
                    admin_id,
                ),
            )
            return admin_id

        cursor = connection.execute(
            """
            INSERT INTO users(username, password_hash, role, enabled, created_at, updated_at)
            VALUES (?, ?, 'admin', 1, ?, ?)
            """,
            (username, hash_password(password), now, now),
        )
        return int(cursor.lastrowid)

    def _rebuild_account_tables(
        self,
        connection: sqlite3.Connection,
        admin_id: int,
    ) -> None:
        account_columns = self._columns(connection, "accounts")
        has_logs = bool(self._columns(connection, "refresh_logs"))
        log_columns = self._columns(connection, "refresh_logs") if has_logs else set()

        connection.commit()
        connection.execute("PRAGMA foreign_keys = OFF")
        if has_logs:
            connection.execute("ALTER TABLE refresh_logs RENAME TO refresh_logs_legacy")
        connection.execute("ALTER TABLE accounts RENAME TO accounts_legacy")
        self._create_accounts_table(connection)
        self._create_refresh_logs_table(connection)

        owner_expression = "owner_id" if "owner_id" in account_columns else str(admin_id)
        connection.execute(
            f"""
            INSERT INTO accounts (
                id, owner_id, provider, email, icloud_alias, password_cipher, client_id,
                refresh_token_cipher, access_token_cipher, access_expires_at,
                status, last_refresh_at, next_refresh_at, last_mail_at,
                last_error, created_at, updated_at
            )
            SELECT
                id, COALESCE({owner_expression}, ?), 'outlook', email, NULL, password_cipher, client_id,
                refresh_token_cipher, access_token_cipher, access_expires_at,
                status, last_refresh_at, next_refresh_at, last_mail_at,
                last_error, created_at, updated_at
            FROM accounts_legacy
            """,
            (admin_id,),
        )

        if has_logs:
            log_owner_expression = (
                "l.owner_id" if "owner_id" in log_columns else "a.owner_id"
            )
            connection.execute(
                f"""
                INSERT INTO refresh_logs (
                    id, account_id, owner_id, email, outcome, message, created_at
                )
                SELECT
                    l.id,
                    l.account_id,
                    COALESCE({log_owner_expression}, a.owner_id, ?),
                    l.email,
                    l.outcome,
                    l.message,
                    l.created_at
                FROM refresh_logs_legacy AS l
                LEFT JOIN accounts AS a ON a.id = l.account_id
                """,
                (admin_id,),
            )

        connection.execute("DROP TABLE accounts_legacy")
        if has_logs:
            connection.execute("DROP TABLE refresh_logs_legacy")
        connection.commit()
        connection.execute("PRAGMA foreign_keys = ON")

    def initialize(self, admin_username: str, admin_password: str) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._write_lock, self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    username      TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    password_hash TEXT NOT NULL,
                    role          TEXT NOT NULL DEFAULT 'user',
                    enabled       INTEGER NOT NULL DEFAULT 1,
                    session_version INTEGER NOT NULL DEFAULT 1,
                    created_at    INTEGER NOT NULL,
                    updated_at    INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key     TEXT PRIMARY KEY,
                    value   TEXT NOT NULL
                );
                """
            )
            if "session_version" not in self._columns(connection, "users"):
                connection.execute(
                    "ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1"
                )
            admin_id = self._ensure_admin(
                connection,
                admin_username,
                admin_password,
            )

            account_columns = self._columns(connection, "accounts")
            if not account_columns:
                self._create_accounts_table(connection)
            elif "owner_id" not in account_columns or not self._has_owner_email_unique(connection):
                self._rebuild_account_tables(connection, admin_id)
            else:
                if "provider" not in account_columns:
                    connection.execute(
                        "ALTER TABLE accounts ADD COLUMN provider TEXT NOT NULL DEFAULT 'outlook'"
                    )
                if "icloud_alias" not in account_columns:
                    connection.execute("ALTER TABLE accounts ADD COLUMN icloud_alias TEXT")
                if "last_archive_sync_at" not in account_columns:
                    connection.execute(
                        "ALTER TABLE accounts ADD COLUMN last_archive_sync_at INTEGER"
                    )
                if "imap_uid_validity" not in account_columns:
                    connection.execute(
                        "ALTER TABLE accounts ADD COLUMN imap_uid_validity TEXT"
                    )
                if "last_synced_uid" not in account_columns:
                    connection.execute(
                        "ALTER TABLE accounts ADD COLUMN last_synced_uid INTEGER"
                    )
                if "last_mail_error" not in account_columns:
                    connection.execute(
                        "ALTER TABLE accounts ADD COLUMN last_mail_error TEXT"
                    )
                if "full_refresh_pending" not in account_columns:
                    connection.execute(
                        "ALTER TABLE accounts ADD COLUMN full_refresh_pending INTEGER NOT NULL DEFAULT 0"
                    )
                if "last_error_code" not in account_columns:
                    connection.execute("ALTER TABLE accounts ADD COLUMN last_error_code TEXT")
                if "last_error_source" not in account_columns:
                    connection.execute("ALTER TABLE accounts ADD COLUMN last_error_source TEXT")
                if "last_error_at" not in account_columns:
                    connection.execute("ALTER TABLE accounts ADD COLUMN last_error_at INTEGER")

            # 旧版本将 IMAP 错误写入通用错误字段，升级后保留为收件箱读取异常。
            connection.execute(
                """
                UPDATE accounts
                SET last_mail_error = last_error
                WHERE last_mail_error IS NULL AND last_error LIKE 'IMAP %'
                """
            )

            # 旧版本会把 Outlook 的可重试会话响应误判为授权异常，升级时清理遗留状态。
            connection.execute(
                """
                UPDATE accounts
                SET last_error = CASE
                        WHEN last_error = last_mail_error THEN NULL
                        ELSE last_error
                    END,
                    last_mail_error = NULL
                WHERE last_mail_error LIKE '%User is authenticated but not connected%'
                """
            )

            connection.execute(
                "UPDATE accounts SET owner_id = ? WHERE owner_id IS NULL",
                (admin_id,),
            )
            log_columns = self._columns(connection, "refresh_logs")
            if not log_columns:
                self._create_refresh_logs_table(connection)
            elif "owner_id" not in log_columns:
                connection.execute(
                    """
                    ALTER TABLE refresh_logs
                    ADD COLUMN owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE
                    """
                )
            connection.execute(
                """
                UPDATE refresh_logs
                SET owner_id = COALESCE(
                    (SELECT owner_id FROM accounts WHERE accounts.id = refresh_logs.account_id),
                    ?
                )
                WHERE owner_id IS NULL
                """,
                (admin_id,),
            )
            self._create_share_links_table(connection)
            self._create_mail_messages_table(connection)
            self._create_mail_recipients_table(connection)
            self._create_mail_sync_staging_tables(connection)
            self._create_mail_targets_table(connection)
            self._create_target_share_links_table(connection)
            self._create_mail_tags_table(connection)
            self._create_mail_target_tags_table(connection)
            self._create_oauth_device_flows_table(connection)
            self._create_captcha_challenges_table(connection)
            self._create_refresh_jobs_tables(connection)
            self._create_service_heartbeats_table(connection)
            self._ensure_share_link_columns(connection)
            connection.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_accounts_owner
                    ON accounts(owner_id);
                CREATE INDEX IF NOT EXISTS idx_accounts_status
                    ON accounts(status);
                CREATE INDEX IF NOT EXISTS idx_accounts_next_refresh
                    ON accounts(next_refresh_at);
                CREATE INDEX IF NOT EXISTS idx_refresh_logs_owner_created
                    ON refresh_logs(owner_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_share_links_token
                    ON share_links(token);
                CREATE INDEX IF NOT EXISTS idx_share_links_account
                    ON share_links(account_id);
                CREATE INDEX IF NOT EXISTS idx_mail_messages_account_received
                    ON mail_messages(account_id, received_at DESC, id DESC);
                CREATE INDEX IF NOT EXISTS idx_mail_messages_owner_account
                    ON mail_messages(owner_id, account_id);
                CREATE INDEX IF NOT EXISTS idx_mail_recipients_email
                    ON mail_recipients(email, mail_message_id);
                CREATE INDEX IF NOT EXISTS idx_mail_sync_state_updated
                    ON mail_sync_state(updated_at);
                CREATE INDEX IF NOT EXISTS idx_mail_sync_recipients_email
                    ON mail_sync_recipients(email, account_id, uid);
                CREATE INDEX IF NOT EXISTS idx_mail_targets_owner_account
                    ON mail_targets(owner_id, account_id);
                CREATE INDEX IF NOT EXISTS idx_target_share_links_token
                    ON target_share_links(token);
                CREATE INDEX IF NOT EXISTS idx_mail_tags_owner
                    ON mail_tags(owner_id, name);
                CREATE INDEX IF NOT EXISTS idx_mail_target_tags_tag
                    ON mail_target_tags(tag_id, target_id);
                CREATE INDEX IF NOT EXISTS idx_oauth_device_flows_owner
                    ON oauth_device_flows(owner_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_captcha_challenges_expiry
                    ON captcha_challenges(expires_at);
                CREATE INDEX IF NOT EXISTS idx_refresh_jobs_owner_created
                    ON refresh_jobs(owner_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_refresh_jobs_public_token
                    ON refresh_jobs(public_token, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_refresh_job_items_status
                    ON refresh_job_items(status, id);
                CREATE INDEX IF NOT EXISTS idx_refresh_job_items_account
                    ON refresh_job_items(account_id, status);
                """
            )
            # 旧内存任务在升级时已经丢失，清理无法继续执行的遗留状态。
            connection.execute(
                """
                UPDATE accounts
                SET full_refresh_pending = 0
                WHERE full_refresh_pending = 1
                  AND NOT EXISTS (
                      SELECT 1
                      FROM refresh_job_items
                      JOIN refresh_jobs ON refresh_jobs.id = refresh_job_items.job_id
                      WHERE refresh_job_items.account_id = accounts.id
                        AND refresh_jobs.mode = 'full'
                        AND refresh_job_items.status IN ('queued', 'running')
                  )
                """
            )
            recipient_version = connection.execute(
                "SELECT value FROM settings WHERE key = 'recipient_header_version'"
            ).fetchone()
            if not recipient_version or str(recipient_version["value"]) != RECIPIENT_HEADER_VERSION:
                # 收件人解析规则升级后重扫归档，补齐隐藏邮箱的投递头。
                connection.execute("DELETE FROM mail_sync_messages")
                connection.execute("DELETE FROM mail_sync_state")
                connection.execute(
                    "UPDATE accounts SET last_synced_uid = 0, last_archive_sync_at = NULL"
                )
                connection.execute(
                    """
                    INSERT INTO settings(key, value) VALUES ('recipient_header_version', ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (RECIPIENT_HEADER_VERSION,),
                )
            connection.executemany(
                "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)",
                DEFAULT_SETTINGS.items(),
            )

            refresh_days = int(
                connection.execute(
                    "SELECT value FROM settings WHERE key = 'refresh_interval_days'"
                ).fetchone()[0]
            )
            now = int(time.time())
            # AADSTS50196 是短时间重复刷新导致的临时限制，不代表刷新令牌永久失效。
            connection.execute(
                """
                UPDATE accounts
                SET status = CASE
                        WHEN access_expires_at > ? THEN 'active'
                        ELSE 'error'
                    END,
                    next_refresh_at = CASE
                        WHEN access_expires_at > ?
                            THEN COALESCE(last_refresh_at, ?) + ?
                        ELSE ?
                    END,
                    last_error = CASE
                        WHEN access_expires_at > ? THEN NULL
                        ELSE last_error
                    END,
                    updated_at = ?
                WHERE status = 'invalid'
                  AND (
                      SELECT message
                      FROM refresh_logs
                      WHERE refresh_logs.account_id = accounts.id
                      ORDER BY refresh_logs.id DESC
                      LIMIT 1
                  ) LIKE 'invalid_grant: AADSTS50196:%'
                """,
                (
                    now + 120,
                    now + 120,
                    now,
                    refresh_days * 86400,
                    now + 30 * 60,
                    now + 120,
                    now,
                ),
            )
            connection.execute(
                """
                UPDATE refresh_logs
                SET outcome = 'error'
                WHERE outcome = 'invalid'
                  AND message LIKE 'invalid_grant: AADSTS50196:%'
                """
            )

            # 为旧数据补齐当前异常的结构化信息，历史异常正文保持不变。
            connection.execute(
                """
                UPDATE accounts
                SET last_error_code = COALESCE(last_error_code, 'legacy_error'),
                    last_error_source = COALESCE(
                        last_error_source,
                        CASE WHEN last_mail_error IS NOT NULL THEN 'imap' ELSE 'token' END
                    ),
                    last_error_at = COALESCE(last_error_at, updated_at)
                WHERE COALESCE(last_mail_error, last_error) IS NOT NULL
                """
            )
            connection.execute(
                """
                UPDATE accounts
                SET last_error_code = NULL,
                    last_error_source = NULL,
                    last_error_at = NULL
                WHERE last_mail_error IS NULL AND last_error IS NULL
                """
            )

    def health_check(self) -> None:
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()

    def touch_service_heartbeat(self, name: str) -> None:
        with self._write_lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO service_heartbeats(name, updated_at)
                VALUES (?, ?)
                ON CONFLICT(name) DO UPDATE SET updated_at = excluded.updated_at
                """,
                (name, int(time.time())),
            )

    def service_heartbeat_is_fresh(self, name: str, max_age_seconds: int) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT updated_at FROM service_heartbeats WHERE name = ?",
                (name,),
            ).fetchone()
        return bool(
            row and int(row["updated_at"]) >= int(time.time()) - max_age_seconds
        )

    @staticmethod
    def _public_user(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "username": row["username"],
            "role": row["role"],
            "enabled": bool(row["enabled"]),
            "session_version": int(row["session_version"]),
            "created_at": int(row["created_at"]),
            "updated_at": int(row["updated_at"]),
        }

    def authenticate_user(self, username: str, password: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
                (username,),
            ).fetchone()
        if not row or not bool(row["enabled"]):
            return None
        if not verify_password(password, str(row["password_hash"])):
            return None
        return self._public_user(row)

    def get_user(self, user_id: int) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        return self._public_user(row) if row else None

    def list_users(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT users.*, COUNT(accounts.id) AS account_count
                FROM users
                LEFT JOIN accounts ON accounts.owner_id = users.id
                GROUP BY users.id
                ORDER BY users.role = 'admin' DESC, users.id ASC
                """
            ).fetchall()
        return [
            {
                **self._public_user(row),
                "account_count": int(row["account_count"] or 0),
            }
            for row in rows
        ]

    def create_user(self, username: str, password: str) -> dict[str, Any]:
        now = int(time.time())
        try:
            with self._write_lock, self._connect() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO users(
                        username, password_hash, role, enabled, created_at, updated_at
                    ) VALUES (?, ?, 'user', 1, ?, ?)
                    """,
                    (username, hash_password(password), now, now),
                )
                user_id = int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ValueError("用户名已存在") from exc
        user = self.get_user(user_id)
        if not user:
            raise RuntimeError("用户创建失败")
        return user

    def reset_user_password(self, user_id: int, password: str) -> bool:
        with self._write_lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE users
                SET password_hash = ?, session_version = session_version + 1,
                    updated_at = ?
                WHERE id = ?
                """,
                (hash_password(password), int(time.time()), user_id),
            )
        return cursor.rowcount > 0

    def set_user_enabled(self, user_id: int, enabled: bool) -> bool:
        with self._write_lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE users
                SET session_version = session_version + CASE WHEN enabled != ? THEN 1 ELSE 0 END,
                    enabled = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    1 if enabled else 0,
                    1 if enabled else 0,
                    int(time.time()),
                    user_id,
                ),
            )
        return cursor.rowcount > 0

    def delete_user(self, user_id: int) -> bool:
        with self._write_lock, self._connect() as connection:
            cursor = connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cursor.rowcount > 0

    @staticmethod
    def _public_account(row: sqlite3.Row) -> dict[str, Any]:
        mail_error = row["last_mail_error"] if "last_mail_error" in row.keys() else None
        current_error = mail_error or row["last_error"]
        full_refresh_pending = bool(
            row["full_refresh_pending"]
            if "full_refresh_pending" in row.keys()
            else False
        )
        return {
            "id": row["id"],
            "provider": row["provider"] if "provider" in row.keys() else "outlook",
            "email": row["email"],
            "icloud_alias": row["icloud_alias"] if "icloud_alias" in row.keys() else None,
            "client_id": row["client_id"],
            "status": (
                "pending"
                if full_refresh_pending
                else ("error" if mail_error else row["status"])
            ),
            "last_refresh_at": row["last_refresh_at"],
            "next_refresh_at": row["next_refresh_at"],
            "last_mail_at": row["last_mail_at"],
            "last_archive_sync_at": row["last_archive_sync_at"] if "last_archive_sync_at" in row.keys() else None,
            "last_error": current_error,
            "last_mail_error": mail_error,
            "last_error_code": row["last_error_code"] if current_error else None,
            "last_error_source": row["last_error_source"] if current_error else None,
            "last_error_at": row["last_error_at"] if current_error else None,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def import_accounts(
        self,
        owner_id: int,
        records: list[dict[str, str]],
    ) -> dict[str, Any]:
        now = int(time.time())
        imported = 0
        updated = 0
        account_ids: list[int] = []

        with self._write_lock, self._connect() as connection:
            for record in records:
                existing = connection.execute(
                    """
                    SELECT id FROM accounts
                    WHERE owner_id = ? AND email = ? COLLATE NOCASE
                    """,
                    (owner_id, record["email"]),
                ).fetchone()
                has_password = "password" in record
                encrypted_password = self.vault.encrypt(record.get("password", ""))
                encrypted_refresh = self.vault.encrypt(record.get("refresh_token", ""))

                if existing:
                    account_id = int(existing["id"])
                    connection.execute(
                        """
                        UPDATE accounts
                        SET provider = 'outlook', icloud_alias = NULL,
                            password_cipher = CASE WHEN ? THEN ? ELSE password_cipher END,
                            client_id = ?, refresh_token_cipher = ?,
                            access_token_cipher = NULL, access_expires_at = NULL,
                            status = 'pending', full_refresh_pending = 0,
                            last_refresh_at = NULL,
                            next_refresh_at = ?, last_error = NULL,
                            last_mail_error = NULL, last_error_code = NULL,
                            last_error_source = NULL, last_error_at = NULL,
                            updated_at = ?
                        WHERE id = ? AND owner_id = ?
                        """,
                        (
                            1 if has_password else 0,
                            encrypted_password,
                            record.get("client_id", ""),
                            encrypted_refresh,
                            now,
                            now,
                            account_id,
                            owner_id,
                        ),
                    )
                    updated += 1
                else:
                    cursor = connection.execute(
                        """
                        INSERT INTO accounts (
                            owner_id, provider, email, icloud_alias, password_cipher, client_id,
                            refresh_token_cipher, status, next_refresh_at,
                            created_at, updated_at
                        ) VALUES (?, 'outlook', ?, NULL, ?, ?, ?, 'pending', ?, ?, ?)
                        """,
                        (
                            owner_id,
                            record["email"],
                            encrypted_password,
                            record.get("client_id", ""),
                            encrypted_refresh,
                            now,
                            now,
                            now,
                        ),
                    )
                    account_id = int(cursor.lastrowid)
                    imported += 1
                account_ids.append(account_id)

        return {"imported": imported, "updated": updated, "account_ids": account_ids}

    def list_accounts(
        self,
        owner_id: int,
        search: str,
        status: str,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        where = ["owner_id = ?"]
        params: list[Any] = [owner_id]
        if search:
            where.append("email LIKE ?")
            params.append(f"%{search}%")
        if status == "active":
            where.append(
                "status = 'active' AND last_mail_error IS NULL AND full_refresh_pending = 0"
            )
        elif status == "error":
            where.append(
                "(status = 'error' OR last_mail_error IS NOT NULL) AND full_refresh_pending = 0"
            )
        elif status == "pending":
            where.append("(status = 'pending' OR full_refresh_pending = 1)")
        elif status:
            where.append("status = ?")
            params.append(status)
        where_sql = f"WHERE {' AND '.join(where)}"

        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM accounts {where_sql}",
                    params,
                ).fetchone()[0]
            )
            rows = connection.execute(
                f"""
                SELECT * FROM accounts
                {where_sql}
                ORDER BY created_at DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                [*params, page_size, (page - 1) * page_size],
            ).fetchall()
        return {
            "items": [self._public_account(row) for row in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    def dashboard_stats(self, owner_id: int) -> dict[str, int]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE
                        WHEN status = 'active'
                          AND last_mail_error IS NULL
                          AND full_refresh_pending = 0 THEN 1
                        ELSE 0
                    END) AS active,
                    SUM(CASE
                        WHEN status IN ('pending', 'error')
                          OR full_refresh_pending = 1
                          OR (status = 'active' AND last_mail_error IS NOT NULL) THEN 1
                        ELSE 0
                    END) AS pending,
                    SUM(CASE WHEN status = 'invalid' THEN 1 ELSE 0 END) AS invalid
                FROM accounts
                WHERE owner_id = ?
                """,
                (owner_id,),
            ).fetchone()
        return {
            "total": int(row["total"] or 0),
            "active": int(row["active"] or 0),
            "pending": int(row["pending"] or 0),
            "invalid": int(row["invalid"] or 0),
        }

    def get_account(
        self,
        account_id: int,
        owner_id: int | None = None,
    ) -> dict[str, Any] | None:
        query = "SELECT * FROM accounts WHERE id = ?"
        params: tuple[Any, ...] = (account_id,)
        if owner_id is not None:
            query += " AND owner_id = ?"
            params = (account_id, owner_id)
        with self._connect() as connection:
            row = connection.execute(query, params).fetchone()
        if not row:
            return None
        account = dict(row)
        account["password"] = self.vault.decrypt(row["password_cipher"])
        account["refresh_token"] = self.vault.decrypt(row["refresh_token_cipher"])
        account["access_token"] = self.vault.decrypt(row["access_token_cipher"])
        return account

    @staticmethod
    def _public_message(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "uid": row["uid"],
            "message_id": row["message_id"],
            "subject": row["subject"],
            "sender_name": row["sender_name"],
            "sender_address": row["sender_address"],
            "received_at": row["received_at"],
            "body": row["body"],
        }

    def archive_mail_messages(
        self,
        owner_id: int,
        account_id: int,
        messages: Iterable[dict[str, Any]],
        staging: bool = False,
    ) -> int:
        now = int(time.time())
        count = 0
        with self._write_lock, self._connect() as connection:
            for message in messages:
                uid = str(message.get("uid") or "").strip()
                if not uid:
                    continue
                values = (
                    str(message.get("message_id") or ""),
                    str(message.get("subject") or "无主题"),
                    str(message.get("sender_name") or ""),
                    str(message.get("sender_address") or ""),
                    message.get("received_at"),
                    str(message.get("body") or ""),
                    now,
                    now,
                )
                if staging:
                    connection.execute(
                        """
                        INSERT INTO mail_sync_messages(
                            account_id, uid, message_id, subject, sender_name,
                            sender_address, received_at, body, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(account_id, uid) DO UPDATE SET
                            message_id = excluded.message_id,
                            subject = excluded.subject,
                            sender_name = excluded.sender_name,
                            sender_address = excluded.sender_address,
                            received_at = excluded.received_at,
                            body = excluded.body,
                            updated_at = excluded.updated_at
                        """,
                        (account_id, uid, *values),
                    )
                    connection.execute(
                        "DELETE FROM mail_sync_recipients WHERE account_id = ? AND uid = ?",
                        (account_id, uid),
                    )
                else:
                    connection.execute(
                        """
                        INSERT INTO mail_messages(
                            owner_id, account_id, uid, message_id, subject,
                            sender_name, sender_address, received_at, body,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(account_id, uid) DO UPDATE SET
                            owner_id = excluded.owner_id,
                            message_id = excluded.message_id,
                            subject = excluded.subject,
                            sender_name = excluded.sender_name,
                            sender_address = excluded.sender_address,
                            received_at = excluded.received_at,
                            body = excluded.body,
                            updated_at = excluded.updated_at
                        """,
                        (owner_id, account_id, uid, *values),
                    )
                    message_row = connection.execute(
                        "SELECT id FROM mail_messages WHERE account_id = ? AND uid = ?",
                        (account_id, uid),
                    ).fetchone()
                    message_id = int(message_row["id"])
                    connection.execute(
                        "DELETE FROM mail_recipients WHERE mail_message_id = ?",
                        (message_id,),
                    )

                for recipient in message.get("recipients") or []:
                    if not isinstance(recipient, dict):
                        continue
                    email_address = str(recipient.get("email") or "").strip().lower()
                    recipient_type = str(recipient.get("recipient_type") or "").strip()
                    if not email_address or recipient_type not in {
                        "to",
                        "cc",
                        "bcc",
                        "envelope",
                    }:
                        continue
                    if staging:
                        connection.execute(
                            """
                            INSERT OR IGNORE INTO mail_sync_recipients(
                                account_id, uid, email, recipient_type
                            ) VALUES (?, ?, ?, ?)
                            """,
                            (account_id, uid, email_address, recipient_type),
                        )
                    else:
                        connection.execute(
                            """
                            INSERT OR IGNORE INTO mail_recipients(
                                mail_message_id, email, recipient_type
                            ) VALUES (?, ?, ?)
                            """,
                            (message_id, email_address, recipient_type),
                        )
                count += 1
        return count

    def list_archived_messages(
        self,
        owner_id: int,
        account_id: int,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        offset = (page - 1) * page_size
        with self._connect() as connection:
            total = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM mail_messages
                    WHERE owner_id = ? AND account_id = ?
                    """,
                    (owner_id, account_id),
                ).fetchone()[0]
            )
            rows = connection.execute(
                """
                SELECT * FROM mail_messages
                WHERE owner_id = ? AND account_id = ?
                ORDER BY received_at DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                (owner_id, account_id, page_size, offset),
            ).fetchall()
        return {
            "items": [self._public_message(row) for row in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    def get_archived_message(
        self,
        owner_id: int,
        account_id: int,
        uid: str,
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM mail_messages
                WHERE owner_id = ? AND account_id = ? AND uid = ?
                """,
                (owner_id, account_id, uid),
            ).fetchone()
        return self._public_message(row) if row else None

    def due_archive_account_ids(self, interval_seconds: int) -> list[int]:
        now = int(time.time())
        cutoff = now - interval_seconds
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id FROM accounts
                WHERE status IN ('active', 'pending', 'error')
                  AND (
                      status != 'error'
                      OR access_expires_at > ?
                      OR next_refresh_at IS NULL
                      OR next_refresh_at <= ?
                  )
                  AND (
                      last_archive_sync_at IS NULL
                      OR last_archive_sync_at <= ?
                      OR EXISTS (
                          SELECT 1 FROM mail_sync_state
                          WHERE mail_sync_state.account_id = accounts.id
                      )
                  )
                ORDER BY COALESCE(last_archive_sync_at, 0), id
                """,
                (now + 120, now, cutoff),
            ).fetchall()
        return [int(row["id"]) for row in rows]

    def mark_mail_archive_synced(self, account_id: int, timestamp: int | None = None) -> None:
        value = timestamp or int(time.time())
        with self._write_lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE accounts
                SET status = CASE WHEN status = 'invalid' THEN status ELSE 'active' END,
                    last_archive_sync_at = ?, last_mail_at = ?,
                    last_error = CASE WHEN status = 'invalid' THEN last_error ELSE NULL END,
                    last_mail_error = NULL,
                    last_error_code = CASE WHEN status = 'invalid' THEN last_error_code ELSE NULL END,
                    last_error_source = CASE WHEN status = 'invalid' THEN last_error_source ELSE NULL END,
                    last_error_at = CASE WHEN status = 'invalid' THEN last_error_at ELSE NULL END,
                    updated_at = ?
                WHERE id = ?
                """,
                (value, value, int(time.time()), account_id),
            )

    def get_mail_archive_cursor(self, account_id: int) -> dict[str, Any]:
        with self._connect() as connection:
            staging = connection.execute(
                """
                SELECT uid_validity, last_synced_uid
                FROM mail_sync_state WHERE account_id = ?
                """,
                (account_id,),
            ).fetchone()
            if staging:
                return {
                    "uid_validity": str(staging["uid_validity"]),
                    "last_synced_uid": int(staging["last_synced_uid"]),
                    "rebuilding": True,
                }
            account = connection.execute(
                """
                SELECT imap_uid_validity, last_synced_uid
                FROM accounts WHERE id = ?
                """,
                (account_id,),
            ).fetchone()
        if not account:
            raise ValueError("邮箱不存在")
        return {
            "uid_validity": str(account["imap_uid_validity"] or ""),
            "last_synced_uid": int(account["last_synced_uid"] or 0),
            "rebuilding": False,
        }

    def begin_mail_archive_rebuild(self, account_id: int, uid_validity: str) -> None:
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            connection.execute(
                "DELETE FROM mail_sync_messages WHERE account_id = ?",
                (account_id,),
            )
            connection.execute(
                """
                INSERT INTO mail_sync_state(
                    account_id, uid_validity, last_synced_uid, started_at, updated_at
                ) VALUES (?, ?, 0, ?, ?)
                ON CONFLICT(account_id) DO UPDATE SET
                    uid_validity = excluded.uid_validity,
                    last_synced_uid = 0,
                    started_at = excluded.started_at,
                    updated_at = excluded.updated_at
                """,
                (account_id, uid_validity, now, now),
            )

    def update_mail_archive_cursor(
        self,
        account_id: int,
        uid_validity: str,
        last_synced_uid: int,
        rebuilding: bool = False,
    ) -> None:
        with self._write_lock, self._connect() as connection:
            if rebuilding:
                connection.execute(
                    """
                    UPDATE mail_sync_state
                    SET last_synced_uid = ?, updated_at = ?
                    WHERE account_id = ? AND uid_validity = ?
                    """,
                    (last_synced_uid, int(time.time()), account_id, uid_validity),
                )
            else:
                connection.execute(
                    """
                    UPDATE accounts
                    SET imap_uid_validity = ?, last_synced_uid = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (uid_validity, last_synced_uid, int(time.time()), account_id),
                )

    def complete_mail_archive_rebuild(
        self,
        account_id: int,
        uid_validity: str,
        last_synced_uid: int,
        timestamp: int,
    ) -> None:
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            state = connection.execute(
                "SELECT uid_validity FROM mail_sync_state WHERE account_id = ?",
                (account_id,),
            ).fetchone()
            if not state or str(state["uid_validity"]) != uid_validity:
                raise RuntimeError("邮件暂存状态已变化")

            # 新快照完整后再替换旧归档，读取方在事务提交前始终看到旧数据。
            connection.execute(
                "DELETE FROM mail_messages WHERE account_id = ?",
                (account_id,),
            )
            connection.execute(
                """
                INSERT INTO mail_messages(
                    owner_id, account_id, uid, message_id, subject,
                    sender_name, sender_address, received_at, body,
                    created_at, updated_at
                )
                SELECT
                    accounts.owner_id, staged.account_id, staged.uid,
                    staged.message_id, staged.subject, staged.sender_name,
                    staged.sender_address, staged.received_at, staged.body,
                    staged.created_at, staged.updated_at
                FROM mail_sync_messages AS staged
                JOIN accounts ON accounts.id = staged.account_id
                WHERE staged.account_id = ?
                """,
                (account_id,),
            )
            connection.execute(
                """
                INSERT INTO mail_recipients(mail_message_id, email, recipient_type)
                SELECT messages.id, staged.email, staged.recipient_type
                FROM mail_sync_recipients AS staged
                JOIN mail_messages AS messages
                    ON messages.account_id = staged.account_id
                    AND messages.uid = staged.uid
                WHERE staged.account_id = ?
                """,
                (account_id,),
            )
            connection.execute(
                """
                UPDATE accounts
                SET status = CASE WHEN status = 'invalid' THEN status ELSE 'active' END,
                    imap_uid_validity = ?, last_synced_uid = ?,
                    last_archive_sync_at = ?, last_mail_at = ?,
                    last_error = CASE WHEN status = 'invalid' THEN last_error ELSE NULL END,
                    last_mail_error = NULL,
                    last_error_code = CASE WHEN status = 'invalid' THEN last_error_code ELSE NULL END,
                    last_error_source = CASE WHEN status = 'invalid' THEN last_error_source ELSE NULL END,
                    last_error_at = CASE WHEN status = 'invalid' THEN last_error_at ELSE NULL END,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    uid_validity,
                    last_synced_uid,
                    timestamp,
                    timestamp,
                    now,
                    account_id,
                ),
            )
            connection.execute(
                "DELETE FROM mail_sync_messages WHERE account_id = ?",
                (account_id,),
            )
            connection.execute(
                "DELETE FROM mail_sync_state WHERE account_id = ?",
                (account_id,),
            )

    def prune_mail_archive(self, account_id: int, max_messages: int) -> int:
        with self._write_lock, self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM mail_messages
                WHERE id IN (
                    SELECT id FROM mail_messages
                    WHERE account_id = ?
                    ORDER BY CAST(uid AS INTEGER) DESC, id DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (account_id, max_messages),
            )
        return int(cursor.rowcount)

    def prune_mail_archives_batch(
        self,
        max_messages: int,
        batch_size: int = 500,
    ) -> int:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id FROM (
                    SELECT
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY account_id
                            ORDER BY CAST(uid AS INTEGER) DESC, id DESC
                        ) AS position
                    FROM mail_messages
                )
                WHERE position > ?
                LIMIT ?
                """,
                (max_messages, batch_size),
            ).fetchall()
        ids = [int(row["id"]) for row in rows]
        if not ids:
            return 0
        placeholders = ",".join("?" for _ in ids)
        with self._write_lock, self._connect() as connection:
            cursor = connection.execute(
                f"DELETE FROM mail_messages WHERE id IN ({placeholders})",
                ids,
            )
            return int(cursor.rowcount)

    def list_mail_targets(self, owner_id: int) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    mail_targets.*,
                    accounts.email AS account_email,
                    COUNT(DISTINCT mail_messages.id) AS message_count
                FROM mail_targets
                JOIN accounts ON accounts.id = mail_targets.account_id
                LEFT JOIN mail_recipients
                    ON mail_recipients.email = mail_targets.email
                LEFT JOIN mail_messages
                    ON mail_messages.id = mail_recipients.mail_message_id
                    AND mail_messages.account_id = mail_targets.account_id
                WHERE mail_targets.owner_id = ?
                GROUP BY mail_targets.id
                ORDER BY mail_targets.created_at DESC, mail_targets.id DESC
                """,
                (owner_id,),
            ).fetchall()
            tag_rows = connection.execute(
                """
                SELECT mail_target_tags.target_id, mail_tags.name
                FROM mail_target_tags
                JOIN mail_tags ON mail_tags.id = mail_target_tags.tag_id
                JOIN mail_targets ON mail_targets.id = mail_target_tags.target_id
                WHERE mail_targets.owner_id = ?
                ORDER BY mail_tags.name COLLATE NOCASE
                """,
                (owner_id,),
            ).fetchall()
        tags_by_target: dict[int, list[str]] = {}
        for tag_row in tag_rows:
            tags_by_target.setdefault(int(tag_row["target_id"]), []).append(
                str(tag_row["name"])
            )
        return [
            {
                "id": int(row["id"]),
                "account_id": int(row["account_id"]),
                "account_email": row["account_email"],
                "email": row["email"],
                "enabled": bool(row["enabled"]),
                "message_count": int(row["message_count"] or 0),
                "tags": tags_by_target.get(int(row["id"]), []),
                "created_at": int(row["created_at"]),
                "updated_at": int(row["updated_at"]),
            }
            for row in rows
        ]

    def create_mail_target(
        self,
        owner_id: int,
        account_id: int,
        email_address: str,
    ) -> dict[str, Any]:
        normalized_email = email_address.strip().lower()
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            account = connection.execute(
                "SELECT email FROM accounts WHERE id = ? AND owner_id = ?",
                (account_id, owner_id),
            ).fetchone()
            if not account:
                raise ValueError("邮箱不存在")
            existing = connection.execute(
                """
                SELECT * FROM mail_targets
                WHERE owner_id = ? AND account_id = ? AND email = ? COLLATE NOCASE
                """,
                (owner_id, account_id, normalized_email),
            ).fetchone()
            if existing:
                return {
                    "id": int(existing["id"]),
                    "account_id": account_id,
                    "account_email": account["email"],
                    "email": existing["email"],
                    "enabled": bool(existing["enabled"]),
                    "created_at": int(existing["created_at"]),
                    "updated_at": int(existing["updated_at"]),
                }
            cursor = connection.execute(
                """
                INSERT INTO mail_targets(
                    owner_id, account_id, email, enabled, created_at, updated_at
                ) VALUES (?, ?, ?, 1, ?, ?)
                """,
                (owner_id, account_id, normalized_email, now, now),
            )
        return {
            "id": int(cursor.lastrowid),
            "account_id": account_id,
            "account_email": account["email"],
            "email": normalized_email,
            "enabled": True,
            "created_at": now,
            "updated_at": now,
        }

    def set_mail_target_tags(
        self,
        owner_id: int,
        target_id: int,
        tags: Iterable[str],
    ) -> list[str]:
        normalized_tags: list[str] = []
        seen: set[str] = set()
        for raw_tag in tags:
            tag = str(raw_tag).strip()
            key = tag.casefold()
            if not tag or key in seen:
                continue
            if len(tag) > 30:
                raise ValueError("标签不能超过 30 个字符")
            seen.add(key)
            normalized_tags.append(tag)

        with self._write_lock, self._connect() as connection:
            target = connection.execute(
                "SELECT id FROM mail_targets WHERE id = ? AND owner_id = ?",
                (target_id, owner_id),
            ).fetchone()
            if not target:
                raise ValueError("别名不存在")
            connection.execute(
                "DELETE FROM mail_target_tags WHERE target_id = ?",
                (target_id,),
            )
            for tag in normalized_tags:
                row = connection.execute(
                    "SELECT id FROM mail_tags WHERE owner_id = ? AND name = ? COLLATE NOCASE",
                    (owner_id, tag),
                ).fetchone()
                if row:
                    tag_id = int(row["id"])
                else:
                    cursor = connection.execute(
                        """
                        INSERT INTO mail_tags(owner_id, name, created_at)
                        VALUES (?, ?, ?)
                        """,
                        (owner_id, tag, int(time.time())),
                    )
                    tag_id = int(cursor.lastrowid)
                connection.execute(
                    "INSERT INTO mail_target_tags(target_id, tag_id) VALUES (?, ?)",
                    (target_id, tag_id),
                )
        return normalized_tags

    def create_oauth_device_flow(
        self,
        owner_id: int,
        email_address: str,
        client_id: str,
        tenant: str,
        device_code: str,
        user_code: str,
        verification_uri: str,
        verification_uri_complete: str | None,
        expires_in: int,
        interval_seconds: int,
    ) -> dict[str, Any]:
        now = int(time.time())
        flow_id = str(uuid.uuid4())
        expires_at = now + max(60, expires_in)
        with self._write_lock, self._connect() as connection:
            connection.execute(
                "DELETE FROM oauth_device_flows WHERE expires_at < ?",
                (now - 86400,),
            )
            connection.execute(
                """
                INSERT INTO oauth_device_flows(
                    id, owner_id, email, client_id, tenant, device_code_cipher,
                    verification_uri, verification_uri_complete, user_code,
                    expires_at, interval_seconds, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    flow_id,
                    owner_id,
                    email_address,
                    client_id,
                    tenant,
                    self.vault.encrypt(device_code),
                    verification_uri,
                    verification_uri_complete,
                    user_code,
                    expires_at,
                    max(1, interval_seconds),
                    now,
                    now,
                ),
            )
        return {
            "id": flow_id,
            "email": email_address,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_uri_complete,
            "user_code": user_code,
            "expires_at": expires_at,
            "interval_seconds": max(1, interval_seconds),
        }

    def get_oauth_device_flow(
        self,
        owner_id: int,
        flow_id: str,
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM oauth_device_flows
                WHERE id = ? AND owner_id = ?
                """,
                (flow_id, owner_id),
            ).fetchone()
        if not row:
            return None
        flow = dict(row)
        flow["device_code"] = self.vault.decrypt(row["device_code_cipher"])
        return flow

    def finish_oauth_device_flow(
        self,
        owner_id: int,
        flow_id: str,
        status: str,
        account_id: int | None = None,
        error: str | None = None,
    ) -> bool:
        with self._write_lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE oauth_device_flows
                SET status = ?, account_id = ?, last_error = ?, device_code_cipher = NULL,
                    updated_at = ?
                WHERE id = ? AND owner_id = ?
                """,
                (status, account_id, (error or "")[:600] or None, int(time.time()), flow_id, owner_id),
            )
        return cursor.rowcount > 0

    def set_mail_target_enabled(
        self,
        owner_id: int,
        target_id: int,
        enabled: bool,
    ) -> bool:
        with self._write_lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE mail_targets
                SET enabled = ?, updated_at = ?
                WHERE id = ? AND owner_id = ?
                """,
                (1 if enabled else 0, int(time.time()), target_id, owner_id),
            )
        return cursor.rowcount > 0

    def delete_mail_target(self, owner_id: int, target_id: int) -> bool:
        with self._write_lock, self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM mail_targets WHERE id = ? AND owner_id = ?",
                (target_id, owner_id),
            )
        return cursor.rowcount > 0

    def get_or_create_target_share_link(
        self,
        owner_id: int,
        target_id: int,
    ) -> dict[str, Any]:
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            target = connection.execute(
                """
                SELECT mail_targets.*, accounts.email AS account_email
                FROM mail_targets
                JOIN accounts ON accounts.id = mail_targets.account_id
                WHERE mail_targets.id = ? AND mail_targets.owner_id = ?
                """,
                (target_id, owner_id),
            ).fetchone()
            if not target:
                raise ValueError("别名不存在")
            existing = connection.execute(
                """
                SELECT * FROM target_share_links
                WHERE owner_id = ? AND target_id = ?
                """,
                (owner_id, target_id),
            ).fetchone()
            if existing and self._link_is_active(existing, now):
                return {
                    "id": int(existing["id"]),
                    "target_id": target_id,
                    "email": target["email"],
                    "account_email": target["account_email"],
                    "token": existing["token"],
                    "created_at": int(existing["created_at"]),
                    "updated_at": int(existing["updated_at"]),
                    "last_access_at": existing["last_access_at"],
                    "expires_at": existing["expires_at"],
                    "revoked_at": existing["revoked_at"],
                }
            token = str(uuid.uuid4())
            if existing:
                connection.execute(
                    """
                    UPDATE target_share_links
                    SET token = ?, expires_at = NULL, revoked_at = NULL,
                        last_access_at = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (token, now, int(existing["id"])),
                )
                link_id = int(existing["id"])
            else:
                cursor = connection.execute(
                    """
                    INSERT INTO target_share_links(
                        owner_id, target_id, token, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (owner_id, target_id, token, now, now),
                )
                link_id = int(cursor.lastrowid)
        return {
            "id": link_id,
            "target_id": target_id,
            "email": target["email"],
            "account_email": target["account_email"],
            "token": token,
            "created_at": now,
            "updated_at": now,
            "last_access_at": None,
            "expires_at": None,
            "revoked_at": None,
        }

    def list_target_archived_messages(
        self,
        owner_id: int,
        target_id: int,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        offset = (page - 1) * page_size
        with self._connect() as connection:
            target = connection.execute(
                """
                SELECT * FROM mail_targets
                WHERE id = ? AND owner_id = ?
                """,
                (target_id, owner_id),
            ).fetchone()
            if not target:
                return {"items": [], "total": 0, "page": page, "page_size": page_size}
            params = (owner_id, int(target["account_id"]), target["email"])
            total = int(
                connection.execute(
                    """
                    SELECT COUNT(DISTINCT mail_messages.id)
                    FROM mail_messages
                    JOIN mail_recipients
                        ON mail_recipients.mail_message_id = mail_messages.id
                    WHERE mail_messages.owner_id = ?
                      AND mail_messages.account_id = ?
                      AND mail_recipients.email = ? COLLATE NOCASE
                    """,
                    params,
                ).fetchone()[0]
            )
            rows = connection.execute(
                """
                SELECT DISTINCT mail_messages.*
                FROM mail_messages
                JOIN mail_recipients
                    ON mail_recipients.mail_message_id = mail_messages.id
                WHERE mail_messages.owner_id = ?
                  AND mail_messages.account_id = ?
                  AND mail_recipients.email = ? COLLATE NOCASE
                ORDER BY mail_messages.received_at DESC, mail_messages.id DESC
                LIMIT ? OFFSET ?
                """,
                (*params, page_size, offset),
            ).fetchall()
        return {
            "items": [self._public_message(row) for row in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    def get_or_create_share_link(
        self,
        owner_id: int,
        account_id: int,
    ) -> dict[str, Any]:
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            existing = connection.execute(
                """
                SELECT share_links.*, accounts.email
                FROM share_links
                JOIN accounts ON accounts.id = share_links.account_id
                WHERE share_links.owner_id = ? AND share_links.account_id = ?
                """,
                (owner_id, account_id),
            ).fetchone()
            if existing and self._link_is_active(existing, now):
                return dict(existing)

            account = connection.execute(
                "SELECT email FROM accounts WHERE owner_id = ? AND id = ?",
                (owner_id, account_id),
            ).fetchone()
            if not account:
                raise ValueError("邮箱不存在")

            # 共享链接使用随机 UUID 作为入口，不暴露内部账号 ID。
            token = str(uuid.uuid4())
            if existing:
                connection.execute(
                    """
                    UPDATE share_links
                    SET token = ?, expires_at = NULL, revoked_at = NULL,
                        last_access_at = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (token, now, int(existing["id"])),
                )
                link_id = int(existing["id"])
            else:
                cursor = connection.execute(
                    """
                    INSERT INTO share_links(
                        owner_id, account_id, token, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (owner_id, account_id, token, now, now),
                )
                link_id = int(cursor.lastrowid)
            return {
                "id": link_id,
                "owner_id": owner_id,
                "account_id": account_id,
                "email": account["email"],
                "token": token,
                "created_at": now,
                "updated_at": now,
                "last_access_at": None,
                "expires_at": None,
                "revoked_at": None,
            }

    def get_shared_mailbox(self, token: str) -> dict[str, Any] | None:
        now = int(time.time())
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    accounts.*,
                    target_share_links.token,
                    target_share_links.id AS share_id,
                    mail_targets.id AS target_id,
                    mail_targets.email AS target_email
                FROM target_share_links
                JOIN mail_targets ON mail_targets.id = target_share_links.target_id
                JOIN accounts ON accounts.id = mail_targets.account_id
                JOIN users ON users.id = accounts.owner_id AND users.enabled = 1
                WHERE target_share_links.token = ?
                  AND mail_targets.enabled = 1
                  AND target_share_links.revoked_at IS NULL
                  AND (
                      target_share_links.expires_at IS NULL
                      OR target_share_links.expires_at > ?
                  )
                """,
                (token, now),
            ).fetchone()
            if not row:
                row = connection.execute(
                    """
                    SELECT
                        accounts.*,
                        share_links.token,
                        share_links.id AS share_id,
                        NULL AS target_id,
                        NULL AS target_email
                    FROM share_links
                    JOIN accounts ON accounts.id = share_links.account_id
                    JOIN users ON users.id = accounts.owner_id AND users.enabled = 1
                    WHERE share_links.token = ?
                      AND share_links.revoked_at IS NULL
                      AND (
                          share_links.expires_at IS NULL
                          OR share_links.expires_at > ?
                      )
                    """,
                    (token, now),
                ).fetchone()
        if not row:
            return None
        account = dict(row)
        account["shared_email"] = account["target_email"] or account["email"]
        account["password"] = self.vault.decrypt(row["password_cipher"])
        account["refresh_token"] = self.vault.decrypt(row["refresh_token_cipher"])
        account["access_token"] = self.vault.decrypt(row["access_token_cipher"])
        return account

    def get_shared_account(self, token: str) -> dict[str, Any] | None:
        return self.get_shared_mailbox(token)

    def mark_share_access(self, token: str) -> None:
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            connection.execute(
                "UPDATE share_links SET last_access_at = ?, updated_at = ? WHERE token = ?",
                (now, now, token),
            )
            connection.execute(
                "UPDATE target_share_links SET last_access_at = ?, updated_at = ? WHERE token = ?",
                (now, now, token),
            )

    def update_share_link_expiry(
        self,
        owner_id: int,
        token: str,
        expires_at: int | None,
    ) -> bool:
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE share_links
                SET expires_at = ?, updated_at = ?
                WHERE owner_id = ? AND token = ? AND revoked_at IS NULL
                """,
                (expires_at, now, owner_id, token),
            )
            if cursor.rowcount > 0:
                return True
            cursor = connection.execute(
                """
                UPDATE target_share_links
                SET expires_at = ?, updated_at = ?
                WHERE owner_id = ? AND token = ? AND revoked_at IS NULL
                """,
                (expires_at, now, owner_id, token),
            )
        return cursor.rowcount > 0

    def revoke_share_link(self, owner_id: int, token: str) -> bool:
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE share_links
                SET revoked_at = ?, updated_at = ?
                WHERE owner_id = ? AND token = ? AND revoked_at IS NULL
                """,
                (now, now, owner_id, token),
            )
            if cursor.rowcount > 0:
                return True
            cursor = connection.execute(
                """
                UPDATE target_share_links
                SET revoked_at = ?, updated_at = ?
                WHERE owner_id = ? AND token = ? AND revoked_at IS NULL
                """,
                (now, now, owner_id, token),
            )
        return cursor.rowcount > 0

    def create_captcha_challenge(
        self,
        challenge_id: str,
        share_token: str,
        answer_digest: str,
        ttl_seconds: int,
    ) -> None:
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            connection.execute(
                "DELETE FROM captcha_challenges WHERE expires_at <= ?",
                (now,),
            )
            connection.execute(
                """
                INSERT INTO captcha_challenges(
                    id, share_token, answer_digest, attempts, expires_at, created_at
                ) VALUES (?, ?, ?, 0, ?, ?)
                """,
                (challenge_id, share_token, answer_digest, now + ttl_seconds, now),
            )

    def consume_captcha_challenge(
        self,
        challenge_id: str,
        share_token: str,
        answer_digest: str,
        max_attempts: int = 5,
    ) -> bool:
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT * FROM captcha_challenges
                WHERE id = ? AND share_token = ?
                """,
                (challenge_id, share_token),
            ).fetchone()
            if not row or int(row["expires_at"]) <= now or int(row["attempts"]) >= max_attempts:
                connection.execute(
                    "DELETE FROM captcha_challenges WHERE id = ?",
                    (challenge_id,),
                )
                return False
            if hmac.compare_digest(str(row["answer_digest"]), answer_digest):
                connection.execute(
                    "DELETE FROM captcha_challenges WHERE id = ?",
                    (challenge_id,),
                )
                return True
            connection.execute(
                """
                UPDATE captcha_challenges
                SET attempts = attempts + 1
                WHERE id = ?
                """,
                (challenge_id,),
            )
            return False

    @staticmethod
    def _refresh_job_response(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        error_row = connection.execute(
            """
            SELECT error FROM refresh_job_items
            WHERE job_id = ? AND error IS NOT NULL
            ORDER BY id DESC LIMIT 1
            """,
            (row["id"],),
        ).fetchone()
        return {
            "id": row["id"],
            "mode": row["mode"],
            "total": int(row["total"]),
            "completed": int(row["completed"]),
            "succeeded": int(row["succeeded"]),
            "failed": int(row["failed"]),
            "done": row["status"] == "completed",
            "error": str(error_row["error"]) if error_row else "",
        }

    def create_refresh_job(
        self,
        owner_id: int,
        account_ids: Iterable[int],
        mode: str,
        public_token: str | None = None,
    ) -> dict[str, Any]:
        if mode not in {"full", "mail"}:
            raise ValueError("刷新模式无效")
        ids = list(dict.fromkeys(int(account_id) for account_id in account_ids))
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM refresh_jobs WHERE completed_at IS NOT NULL AND completed_at < ?",
                (now - 7 * 86400,),
            )

            if ids:
                placeholders = ",".join("?" for _ in ids)
                valid_rows = connection.execute(
                    f"""
                    SELECT id FROM accounts
                    WHERE owner_id = ? AND provider = 'outlook'
                      AND id IN ({placeholders})
                    """,
                    [owner_id, *ids],
                ).fetchall()
                valid_ids = {int(row["id"]) for row in valid_rows}
                ids = [account_id for account_id in ids if account_id in valid_ids]

            active_by_account: dict[int, sqlite3.Row] = {}
            if ids:
                placeholders = ",".join("?" for _ in ids)
                active_rows = connection.execute(
                    f"""
                    SELECT refresh_jobs.*, refresh_job_items.account_id AS active_account_id
                    FROM refresh_jobs
                    JOIN refresh_job_items
                        ON refresh_job_items.job_id = refresh_jobs.id
                    WHERE refresh_jobs.owner_id = ?
                      AND refresh_jobs.status IN ('queued', 'running')
                      AND refresh_job_items.status IN ('queued', 'running')
                      AND refresh_job_items.account_id IN ({placeholders})
                    ORDER BY refresh_jobs.created_at DESC
                    """,
                    [owner_id, *ids],
                ).fetchall()
                for row in active_rows:
                    active_by_account.setdefault(int(row["active_account_id"]), row)

            if public_token and len(ids) != 1:
                raise ValueError("公开链接一次只能刷新一个邮箱")
            if public_token and ids and ids[0] in active_by_account:
                existing = active_by_account[ids[0]]
                if existing["mode"] == "mail" and existing["public_token"] == public_token:
                    return self._refresh_job_response(connection, existing)
                raise ValueError("邮箱正在刷新，请稍后重试")
            if not public_token and len(ids) == 1 and ids[0] in active_by_account:
                existing = active_by_account[ids[0]]
                if mode == "full" and existing["mode"] == "mail":
                    raise ValueError("邮箱正在同步邮件，请完成后再执行完整校验")
                return self._refresh_job_response(connection, existing)
            if not public_token and active_by_account:
                raise ValueError("部分邮箱已有刷新任务，请完成后再重试")
            if not ids:
                return {
                    "id": "",
                    "mode": mode,
                    "total": 0,
                    "completed": 0,
                    "succeeded": 0,
                    "failed": 0,
                    "done": True,
                    "error": "",
                }

            active_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM refresh_job_items
                    JOIN refresh_jobs ON refresh_jobs.id = refresh_job_items.job_id
                    WHERE refresh_jobs.owner_id = ?
                      AND refresh_jobs.status IN ('queued', 'running')
                      AND refresh_job_items.status IN ('queued', 'running')
                    """,
                    (owner_id,),
                ).fetchone()[0]
            )
            if active_count + len(ids) > MAX_ACTIVE_REFRESH_ITEMS_PER_OWNER:
                raise ValueError("刷新任务过多，请等待当前任务完成后重试")

            job_id = uuid.uuid4().hex
            connection.execute(
                """
                INSERT INTO refresh_jobs(
                    id, owner_id, mode, public_token, status, total,
                    completed, succeeded, failed, created_at, updated_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?, ?)
                """,
                (
                    job_id,
                    owner_id,
                    mode,
                    public_token,
                    "queued",
                    len(ids),
                    now,
                    now,
                    None,
                ),
            )
            connection.executemany(
                """
                INSERT INTO refresh_job_items(job_id, account_id, status)
                VALUES (?, ?, 'queued')
                """,
                [(job_id, account_id) for account_id in ids],
            )
            if mode == "full" and ids:
                placeholders = ",".join("?" for _ in ids)
                connection.execute(
                    f"""
                    UPDATE accounts
                    SET full_refresh_pending = 1,
                        last_error = CASE
                            WHEN status = 'invalid' THEN last_error ELSE NULL
                        END,
                        last_mail_error = CASE
                            WHEN status = 'invalid' THEN last_mail_error ELSE NULL
                        END,
                        last_error_code = CASE
                            WHEN status = 'invalid' THEN last_error_code ELSE NULL
                        END,
                        last_error_source = CASE
                            WHEN status = 'invalid' THEN last_error_source ELSE NULL
                        END,
                        last_error_at = CASE
                            WHEN status = 'invalid' THEN last_error_at ELSE NULL
                        END,
                        updated_at = ?
                    WHERE owner_id = ? AND id IN ({placeholders})
                    """,
                    [now, owner_id, *ids],
                )
            row = connection.execute(
                "SELECT * FROM refresh_jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
            return self._refresh_job_response(connection, row)

    def get_refresh_job(self, owner_id: int, job_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM refresh_jobs WHERE id = ? AND owner_id = ?",
                (job_id, owner_id),
            ).fetchone()
            return self._refresh_job_response(connection, row) if row else None

    def get_public_refresh_job(
        self,
        public_token: str,
        job_id: str,
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM refresh_jobs
                WHERE id = ? AND public_token = ? AND mode = 'mail'
                """,
                (job_id, public_token),
            ).fetchone()
            return self._refresh_job_response(connection, row) if row else None

    def public_refresh_retry_after(
        self,
        account_id: int,
        cooldown_seconds: int,
    ) -> int:
        now = int(time.time())
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT MAX(refresh_jobs.completed_at) AS completed_at
                FROM refresh_jobs
                JOIN refresh_job_items
                    ON refresh_job_items.job_id = refresh_jobs.id
                WHERE refresh_jobs.public_token IS NOT NULL
                  AND refresh_jobs.mode = 'mail'
                  AND refresh_jobs.status = 'completed'
                  AND refresh_job_items.account_id = ?
                """,
                (account_id,),
            ).fetchone()
        completed_at = int(row["completed_at"] or 0)
        return max(0, cooldown_seconds - (now - completed_at))

    def requeue_running_refresh_items(self) -> None:
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE refresh_job_items
                SET status = 'queued', claimed_at = NULL
                WHERE status = 'running'
                """
            )
            connection.execute(
                """
                UPDATE refresh_jobs
                SET status = 'queued', updated_at = ?
                WHERE status = 'running'
                """,
                (now,),
            )

    def claim_refresh_job_item(self, lease_seconds: int = 600) -> dict[str, Any] | None:
        now = int(time.time())
        with self._connect() as connection:
            pending = connection.execute(
                """
                SELECT 1 FROM refresh_job_items
                JOIN refresh_jobs ON refresh_jobs.id = refresh_job_items.job_id
                WHERE refresh_jobs.status IN ('queued', 'running')
                  AND (
                      refresh_job_items.status = 'queued'
                      OR (
                          refresh_job_items.status = 'running'
                          AND refresh_job_items.claimed_at < ?
                      )
                  )
                LIMIT 1
                """,
                (now - lease_seconds,),
            ).fetchone()
        if not pending:
            return None
        with self._write_lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                UPDATE refresh_job_items
                SET status = 'queued', claimed_at = NULL
                WHERE status = 'running' AND claimed_at < ?
                """,
                (now - lease_seconds,),
            )
            row = connection.execute(
                """
                SELECT
                    refresh_job_items.id,
                    refresh_job_items.job_id,
                    refresh_job_items.account_id,
                    refresh_jobs.owner_id,
                    refresh_jobs.mode
                FROM refresh_job_items
                JOIN refresh_jobs ON refresh_jobs.id = refresh_job_items.job_id
                WHERE refresh_job_items.status = 'queued'
                  AND refresh_jobs.status IN ('queued', 'running')
                  AND (
                      refresh_job_items.account_id IS NULL
                      OR NOT EXISTS (
                          SELECT 1 FROM refresh_job_items AS running_item
                          WHERE running_item.account_id = refresh_job_items.account_id
                            AND running_item.status = 'running'
                      )
                  )
                ORDER BY refresh_job_items.id
                LIMIT 1
                """
            ).fetchone()
            if not row:
                return None
            cursor = connection.execute(
                """
                UPDATE refresh_job_items
                SET status = 'running', claimed_at = ?
                WHERE id = ? AND status = 'queued'
                """,
                (now, int(row["id"])),
            )
            if cursor.rowcount == 0:
                return None
            connection.execute(
                """
                UPDATE refresh_jobs
                SET status = 'running', updated_at = ?
                WHERE id = ? AND status = 'queued'
                """,
                (now, row["job_id"]),
            )
            return dict(row)

    def complete_refresh_job_item(
        self,
        item_id: int,
        succeeded: bool,
        error: str = "",
    ) -> None:
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = connection.execute(
                "SELECT job_id FROM refresh_job_items WHERE id = ? AND status = 'running'",
                (item_id,),
            ).fetchone()
            if not item:
                return
            connection.execute(
                """
                UPDATE refresh_job_items
                SET status = ?, error = ?, completed_at = ?
                WHERE id = ?
                """,
                ("succeeded" if succeeded else "failed", error[:600] or None, now, item_id),
            )
            job = connection.execute(
                "SELECT completed, total FROM refresh_jobs WHERE id = ?",
                (item["job_id"],),
            ).fetchone()
            completed = int(job["completed"]) + 1
            done = completed >= int(job["total"])
            connection.execute(
                """
                UPDATE refresh_jobs
                SET completed = ?,
                    succeeded = succeeded + ?,
                    failed = failed + ?,
                    status = ?, updated_at = ?, completed_at = ?
                WHERE id = ?
                """,
                (
                    completed,
                    1 if succeeded else 0,
                    0 if succeeded else 1,
                    "completed" if done else "running",
                    now,
                    now if done else None,
                    item["job_id"],
                ),
            )

    def renew_refresh_job_item(self, item_id: int) -> None:
        with self._write_lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE refresh_job_items
                SET claimed_at = ?
                WHERE id = ? AND status = 'running'
                """,
                (int(time.time()), item_id),
            )

    def refresh_job_status(self) -> dict[str, int]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END) AS queued,
                    SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running
                FROM refresh_job_items
                """
            ).fetchone()
        return {
            "queued": int(row["queued"] or 0),
            "running": int(row["running"] or 0),
        }

    def existing_ids(
        self,
        owner_id: int,
        account_ids: Iterable[int] | None = None,
    ) -> list[int]:
        ids = [int(account_id) for account_id in account_ids or []]
        with self._connect() as connection:
            if ids:
                placeholders = ",".join("?" for _ in ids)
                rows = connection.execute(
                    f"SELECT id FROM accounts WHERE owner_id = ? AND id IN ({placeholders})",
                    [owner_id, *ids],
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT id FROM accounts WHERE owner_id = ?",
                    (owner_id,),
                ).fetchall()
        return [int(row["id"]) for row in rows]

    def due_account_ids(self, limit: int = 500) -> list[int]:
        now = int(time.time())
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id FROM accounts
                WHERE next_refresh_at IS NOT NULL
                  AND next_refresh_at <= ?
                  AND status != 'invalid'
                  AND provider = 'outlook'
                ORDER BY next_refresh_at ASC
                LIMIT ?
                """,
                (now, limit),
            ).fetchall()
        return [int(row["id"]) for row in rows]

    def refreshable_ids(
        self,
        owner_id: int,
        account_ids: Iterable[int] | None = None,
        search: str = "",
        status: str = "",
    ) -> list[int]:
        ids = [int(account_id) for account_id in account_ids or []]
        where = ["owner_id = ?", "provider = 'outlook'"]
        params: list[Any] = [owner_id]
        if ids:
            placeholders = ",".join("?" for _ in ids)
            where.append(f"id IN ({placeholders})")
            params.extend(ids)
        else:
            if search:
                where.append("email LIKE ?")
                params.append(f"%{search}%")
            if status == "active":
                where.append(
                    "status = 'active' AND last_mail_error IS NULL AND full_refresh_pending = 0"
                )
            elif status == "error":
                where.append(
                    "(status = 'error' OR last_mail_error IS NOT NULL) AND full_refresh_pending = 0"
                )
            elif status == "pending":
                where.append("(status = 'pending' OR full_refresh_pending = 1)")
            elif status:
                where.append("status = ?")
                params.append(status)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT id FROM accounts WHERE {' AND '.join(where)}",
                params,
            ).fetchall()
        return [int(row["id"]) for row in rows]

    def mark_full_refresh_pending(self, account_ids: Iterable[int]) -> None:
        ids = list(dict.fromkeys(int(account_id) for account_id in account_ids))
        if not ids:
            return
        now = int(time.time())
        placeholders = ",".join("?" for _ in ids)
        with self._write_lock, self._connect() as connection:
            connection.execute(
                f"""
                UPDATE accounts
                SET full_refresh_pending = 1,
                    last_error = CASE
                        WHEN status = 'invalid' THEN last_error ELSE NULL
                    END,
                    last_mail_error = CASE
                        WHEN status = 'invalid' THEN last_mail_error ELSE NULL
                    END,
                    last_error_code = CASE
                        WHEN status = 'invalid' THEN last_error_code ELSE NULL
                    END,
                    last_error_source = CASE
                        WHEN status = 'invalid' THEN last_error_source ELSE NULL
                    END,
                    last_error_at = CASE
                        WHEN status = 'invalid' THEN last_error_at ELSE NULL
                    END,
                    updated_at = ?
                WHERE id IN ({placeholders})
                """,
                [now, *ids],
            )

    def mark_full_refresh_succeeded(self, account_id: int) -> None:
        with self._write_lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE accounts
                SET status = CASE WHEN status = 'invalid' THEN status ELSE 'active' END,
                    full_refresh_pending = 0,
                    last_error = CASE WHEN status = 'invalid' THEN last_error ELSE NULL END,
                    last_mail_error = NULL,
                    last_error_code = CASE WHEN status = 'invalid' THEN last_error_code ELSE NULL END,
                    last_error_source = CASE WHEN status = 'invalid' THEN last_error_source ELSE NULL END,
                    last_error_at = CASE WHEN status = 'invalid' THEN last_error_at ELSE NULL END,
                    updated_at = ?
                WHERE id = ?
                """,
                (int(time.time()), account_id),
            )

    def mark_full_refresh_failure(
        self,
        account_id: int,
        message: str,
        mail_error: bool = False,
        permanent: bool = False,
        code: str = "refresh_error",
        source: str = "system",
    ) -> None:
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE accounts
                SET status = ?, full_refresh_pending = 0,
                    last_error = ?,
                    last_mail_error = ?, last_error_code = ?,
                    last_error_source = ?, last_error_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    "invalid" if permanent else "error",
                    message[:600],
                    message[:600] if mail_error else None,
                    code[:100],
                    source[:30],
                    now,
                    now,
                    account_id,
                ),
            )

    def update_tokens(
        self,
        account_id: int,
        access_token: str,
        access_expires_at: int,
        refresh_token: str | None,
        refreshed_at: int,
        next_refresh_at: int,
    ) -> None:
        with self._write_lock, self._connect() as connection:
            if refresh_token:
                connection.execute(
                    """
                    UPDATE accounts
                    SET access_token_cipher = ?, access_expires_at = ?,
                        refresh_token_cipher = ?, status = 'active',
                        last_refresh_at = ?, next_refresh_at = ?, last_error = NULL,
                        last_error_code = CASE WHEN last_mail_error IS NULL THEN NULL ELSE last_error_code END,
                        last_error_source = CASE WHEN last_mail_error IS NULL THEN NULL ELSE last_error_source END,
                        last_error_at = CASE WHEN last_mail_error IS NULL THEN NULL ELSE last_error_at END,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        self.vault.encrypt(access_token),
                        access_expires_at,
                        self.vault.encrypt(refresh_token),
                        refreshed_at,
                        next_refresh_at,
                        refreshed_at,
                        account_id,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE accounts
                    SET access_token_cipher = ?, access_expires_at = ?,
                        status = 'active', last_refresh_at = ?, next_refresh_at = ?,
                        last_error = NULL,
                        last_error_code = CASE WHEN last_mail_error IS NULL THEN NULL ELSE last_error_code END,
                        last_error_source = CASE WHEN last_mail_error IS NULL THEN NULL ELSE last_error_source END,
                        last_error_at = CASE WHEN last_mail_error IS NULL THEN NULL ELSE last_error_at END,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        self.vault.encrypt(access_token),
                        access_expires_at,
                        refreshed_at,
                        next_refresh_at,
                        refreshed_at,
                        account_id,
                    ),
                )

    def mark_refresh_failure(
        self,
        account_id: int,
        status: str,
        message: str,
        next_refresh_at: int | None,
        code: str = "token_error",
        source: str = "token",
    ) -> None:
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE accounts
                SET status = ?, last_error = ?, next_refresh_at = ?,
                    last_error_code = CASE WHEN last_mail_error IS NULL THEN ? ELSE last_error_code END,
                    last_error_source = CASE WHEN last_mail_error IS NULL THEN ? ELSE last_error_source END,
                    last_error_at = CASE WHEN last_mail_error IS NULL THEN ? ELSE last_error_at END,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    status,
                    message[:600],
                    next_refresh_at,
                    code[:100],
                    source[:30],
                    now,
                    now,
                    account_id,
                ),
            )

    def add_refresh_log(
        self,
        account_id: int,
        owner_id: int,
        email: str,
        outcome: str,
        message: str,
    ) -> None:
        with self._write_lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO refresh_logs(
                    account_id, owner_id, email, outcome, message, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    account_id,
                    owner_id,
                    email,
                    outcome,
                    message[:600],
                    int(time.time()),
                ),
            )
            connection.execute(
                """
                DELETE FROM refresh_logs
                WHERE id NOT IN (
                    SELECT id FROM refresh_logs ORDER BY id DESC LIMIT 10000
                )
                """
            )

    def list_refresh_logs(
        self,
        owner_id: int,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        with self._connect() as connection:
            total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM refresh_logs WHERE owner_id = ?",
                    (owner_id,),
                ).fetchone()[0]
            )
            rows = connection.execute(
                """
                SELECT id, account_id, email, outcome, message, created_at
                FROM refresh_logs
                WHERE owner_id = ?
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (owner_id, page_size, (page - 1) * page_size),
            ).fetchall()
        return {
            "items": [dict(row) for row in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    def delete_accounts(self, owner_id: int, account_ids: list[int]) -> int:
        if not account_ids:
            return 0
        placeholders = ",".join("?" for _ in account_ids)
        with self._write_lock, self._connect() as connection:
            cursor = connection.execute(
                f"DELETE FROM accounts WHERE owner_id = ? AND id IN ({placeholders})",
                [owner_id, *account_ids],
            )
        return int(cursor.rowcount)

    def export_accounts(
        self,
        owner_id: int,
        account_ids: list[int] | None = None,
    ) -> list[str]:
        ids = account_ids or []
        with self._connect() as connection:
            if ids:
                placeholders = ",".join("?" for _ in ids)
                rows = connection.execute(
                    f"""
                    SELECT provider, email, icloud_alias, password_cipher, client_id, refresh_token_cipher
                    FROM accounts
                    WHERE owner_id = ? AND id IN ({placeholders})
                    ORDER BY id
                    """,
                    [owner_id, *ids],
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT provider, email, icloud_alias, password_cipher, client_id, refresh_token_cipher
                    FROM accounts
                    WHERE owner_id = ?
                    ORDER BY id
                    """,
                    (owner_id,),
                ).fetchall()
        lines: list[str] = []
        for row in rows:
            lines.append(
                "----".join(
                    (
                        row["email"],
                        self.vault.decrypt(row["password_cipher"]),
                        row["client_id"],
                        self.vault.decrypt(row["refresh_token_cipher"]),
                    )
                )
            )
        return lines

    def update_last_mail(self, account_id: int, timestamp: int | None = None) -> None:
        value = timestamp or int(time.time())
        with self._write_lock, self._connect() as connection:
            connection.execute(
                "UPDATE accounts SET last_mail_at = ?, updated_at = ? WHERE id = ?",
                (value, int(time.time()), account_id),
            )

    def set_mail_error(
        self,
        account_id: int,
        message: str,
        code: str = "imap_error",
        source: str = "imap",
    ) -> None:
        now = int(time.time())
        with self._write_lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE accounts
                SET last_error = ?, last_mail_error = ?, last_error_code = ?,
                    last_error_source = ?, last_error_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    message[:600],
                    message[:600],
                    code[:100],
                    source[:30],
                    now,
                    now,
                    account_id,
                ),
            )

    def get_settings(self) -> dict[str, Any]:
        with self._connect() as connection:
            rows = connection.execute("SELECT key, value FROM settings").fetchall()
        values = {row["key"]: row["value"] for row in rows}
        return {
            "tenant": values.get("tenant", DEFAULT_SETTINGS["tenant"]),
            "refresh_interval_days": int(
                values.get(
                    "refresh_interval_days",
                    DEFAULT_SETTINGS["refresh_interval_days"],
                )
            ),
            "mail_page_size": int(
                values.get("mail_page_size", DEFAULT_SETTINGS["mail_page_size"])
            ),
        }

    def update_settings(
        self,
        tenant: str,
        refresh_interval_days: int,
        mail_page_size: int,
    ) -> None:
        values = {
            "tenant": tenant,
            "refresh_interval_days": str(refresh_interval_days),
            "mail_page_size": str(mail_page_size),
        }
        with self._write_lock, self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO settings(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                values.items(),
            )
