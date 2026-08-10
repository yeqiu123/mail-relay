from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _required(name: str) -> str:
    value = (os.getenv(name) or "").strip()
    if not value:
        raise RuntimeError(f"缺少必需环境变量：{name}")
    return value


@dataclass(frozen=True)
class AppConfig:
    data_dir: Path
    database_path: Path
    encryption_key: str
    session_secret: str
    admin_username: str
    admin_password: str
    cookie_secure: bool
    imap_host: str
    imap_port: int
    token_scope: str
    refresh_workers: int
    scheduler_seconds: int
    mail_sync_interval_seconds: int
    mail_fetch_max_bytes: int
    mail_archive_max_messages: int
    public_share_origin: str

    @classmethod
    def from_env(cls) -> "AppConfig":
        data_dir = Path(os.getenv("DATA_DIR", "/data")).resolve()
        return cls(
            data_dir=data_dir,
            database_path=data_dir / "mail-relay.db",
            encryption_key=_required("APP_ENCRYPTION_KEY"),
            session_secret=_required("APP_SESSION_SECRET"),
            admin_username=os.getenv("APP_ADMIN_USERNAME", "admin").strip() or "admin",
            admin_password=_required("APP_ADMIN_PASSWORD"),
            cookie_secure=os.getenv("APP_COOKIE_SECURE", "true").lower() in {"1", "true", "yes"},
            imap_host=os.getenv("IMAP_HOST", "outlook.office365.com").strip(),
            imap_port=int(os.getenv("IMAP_PORT", "993")),
            token_scope=os.getenv(
                "MICROSOFT_SCOPE",
                "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
            ).strip(),
            refresh_workers=max(1, min(8, int(os.getenv("REFRESH_WORKERS", "3")))),
            scheduler_seconds=max(60, int(os.getenv("SCHEDULER_SECONDS", "300"))),
            mail_sync_interval_seconds=max(
                60, int(os.getenv("MAIL_SYNC_INTERVAL_SECONDS", "300"))
            ),
            mail_fetch_max_bytes=max(
                262_144,
                min(20_971_520, int(os.getenv("MAIL_FETCH_MAX_BYTES", "5242880"))),
            ),
            mail_archive_max_messages=max(
                100,
                min(20_000, int(os.getenv("MAIL_ARCHIVE_MAX_MESSAGES", "5000"))),
            ),
            public_share_origin=os.getenv(
                "PUBLIC_SHARE_ORIGIN",
                "https://temporary.yeqiu.loc.cc",
            ).strip().rstrip("/"),
        )


config = AppConfig.from_env()
