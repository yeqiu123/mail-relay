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


async def _heartbeat(store: Store) -> None:
    while True:
        store.touch_service_heartbeat("worker")
        await asyncio.sleep(10)


async def run_worker() -> None:
    """独立任务进程，统一负责令牌刷新和 Outlook 邮件归档。"""
    vault = Vault(config.encryption_key)
    store = Store(config.database_path, vault)
    token_service = MicrosoftTokenService(store, config)
    archive_coordinator = MailArchiveCoordinator(
        store,
        token_service,
        OutlookMailbox(
            config.imap_host,
            config.imap_port,
            config.mail_fetch_max_bytes,
        ),
        config.refresh_workers,
        config.scheduler_seconds,
        config.mail_sync_interval_seconds,
        config.mail_archive_max_messages,
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

    # 先启动心跳，归档清理采用小批次，避免启动阶段长事务导致健康检查误判。
    heartbeat_task = asyncio.create_task(_heartbeat(store), name="worker-heartbeat")
    await asyncio.sleep(0)
    await token_coordinator.start()
    await archive_coordinator.start()
    await job_coordinator.start()
    await asyncio.to_thread(
        store.prune_mail_archives_batch,
        config.mail_archive_max_messages,
    )
    stop_task = asyncio.create_task(stop_event.wait(), name="worker-stop")
    try:
        supervised = [
            *token_coordinator.tasks,
            *archive_coordinator.tasks,
            *job_coordinator.tasks,
            heartbeat_task,
        ]
        done, _ = await asyncio.wait(
            [stop_task, *supervised],
            return_when=asyncio.FIRST_COMPLETED,
        )
        if stop_task not in done:
            failed_task = next(iter(done))
            if failed_task.cancelled():
                raise RuntimeError(f"后台任务意外停止：{failed_task.get_name()}")
            error = failed_task.exception()
            if error:
                raise error
            raise RuntimeError(f"后台任务意外退出：{failed_task.get_name()}")
    finally:
        stop_task.cancel()
        heartbeat_task.cancel()
        await asyncio.gather(stop_task, heartbeat_task, return_exceptions=True)
        await job_coordinator.stop()
        await archive_coordinator.stop()
        await token_coordinator.stop()
        await token_service.close()


if __name__ == "__main__":
    asyncio.run(run_worker())
