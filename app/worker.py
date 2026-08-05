from __future__ import annotations

import asyncio
import signal

from .config import config
from .imap_client import OutlookMailbox
from .microsoft import (
    FullRefreshCoordinator,
    MailArchiveCoordinator,
    MicrosoftTokenService,
    RefreshCoordinator,
)
from .security import Vault
from .store import Store


async def run_worker() -> None:
    """独立任务进程，统一负责令牌刷新和 Outlook 邮件归档。"""
    vault = Vault(config.encryption_key)
    store = Store(config.database_path, vault)
    token_service = MicrosoftTokenService(store, config)
    archive_coordinator = MailArchiveCoordinator(
        store,
        token_service,
        OutlookMailbox(config.imap_host, config.imap_port),
        config.refresh_workers,
        config.scheduler_seconds,
        config.mail_sync_interval_seconds,
    )
    token_coordinator = RefreshCoordinator(
        store,
        token_service,
        config.refresh_workers,
        config.scheduler_seconds,
    )
    job_coordinator = FullRefreshCoordinator(
        store,
        token_service,
        archive_coordinator,
        config.refresh_workers,
    )
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signal_value in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signal_value, stop_event.set)

    await token_coordinator.start()
    await archive_coordinator.start()
    await job_coordinator.start()
    try:
        await stop_event.wait()
    finally:
        await job_coordinator.stop()
        await archive_coordinator.stop()
        await token_coordinator.stop()
        await token_service.close()


if __name__ == "__main__":
    asyncio.run(run_worker())
