from __future__ import annotations

import asyncio
import signal

from .config import config
from .imap_client import OutlookMailbox
from .microsoft import MailArchiveCoordinator, MicrosoftTokenService
from .security import Vault
from .store import Store


async def run_worker() -> None:
    """独立归档进程，只负责把 Outlook 邮件同步到本地缓存。"""
    vault = Vault(config.encryption_key)
    store = Store(config.database_path, vault)
    token_service = MicrosoftTokenService(store, config)
    coordinator = MailArchiveCoordinator(
        store,
        token_service,
        OutlookMailbox(config.imap_host, config.imap_port),
        config.refresh_workers,
        config.scheduler_seconds,
        config.mail_sync_interval_seconds,
    )
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signal_value in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signal_value, stop_event.set)

    store.initialize(config.admin_username, config.admin_password)
    await coordinator.start()
    try:
        await stop_event.wait()
    finally:
        await coordinator.stop()
        await token_service.close()


if __name__ == "__main__":
    asyncio.run(run_worker())
