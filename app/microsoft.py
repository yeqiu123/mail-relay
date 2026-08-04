from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from .config import AppConfig
from .store import Store


class TokenRefreshError(RuntimeError):
    def __init__(self, code: str, description: str, permanent: bool) -> None:
        super().__init__(description)
        self.code = code
        self.description = description
        self.permanent = permanent


class MicrosoftTokenService:
    def __init__(self, store: Store, config: AppConfig) -> None:
        self.store = store
        self.config = config
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=15.0),
            follow_redirects=False,
            trust_env=False,
        )
        self._locks: dict[int, asyncio.Lock] = {}

    async def close(self) -> None:
        await self._client.aclose()

    def _lock_for(self, account_id: int) -> asyncio.Lock:
        lock = self._locks.get(account_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[account_id] = lock
        return lock

    async def refresh_account(self, account_id: int) -> dict[str, Any]:
        async with self._lock_for(account_id):
            account = self.store.get_account(account_id)
            if not account:
                raise TokenRefreshError("not_found", "邮箱不存在", True)

            now = int(time.time())
            # 刚刷新成功的令牌直接复用，避免手动重复操作触发 Microsoft 请求循环限制。
            if (
                account["access_token"]
                and account["access_expires_at"]
                and int(account["access_expires_at"]) > now + 120
                and account["last_refresh_at"]
                and now - int(account["last_refresh_at"]) < 15 * 60
            ):
                return {
                    "access_token": str(account["access_token"]),
                    "access_expires_at": int(account["access_expires_at"]),
                    "rotated": False,
                    "skipped": True,
                }

            settings = self.store.get_settings()
            tenant = settings["tenant"]
            endpoint = (
                f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
            )

            try:
                response = await self._client.post(
                    endpoint,
                    data={
                        "client_id": account["client_id"],
                        "grant_type": "refresh_token",
                        "refresh_token": account["refresh_token"],
                        "scope": self.config.token_scope,
                    },
                    headers={"Accept": "application/json"},
                )
            except httpx.HTTPError as exc:
                description = f"Microsoft 连接失败：{exc.__class__.__name__}"
                self._record_failure(account, "network_error", description, False)
                raise TokenRefreshError("network_error", description, False) from exc

            try:
                payload = response.json()
            except ValueError:
                payload = {}

            if response.status_code >= 400:
                code = str(payload.get("error") or f"http_{response.status_code}")
                description = str(
                    payload.get("error_description")
                    or payload.get("error")
                    or f"Microsoft 返回 HTTP {response.status_code}"
                )
                description = " ".join(description.split())[:600]
                permanent = code in {
                    "invalid_grant",
                    "interaction_required",
                    "invalid_client",
                    "unauthorized_client",
                }
                if code == "invalid_grant" and "AADSTS50196" in description:
                    permanent = False
                self._record_failure(account, code, description, permanent)
                raise TokenRefreshError(code, description, permanent)

            access_token = str(payload.get("access_token") or "")
            if not access_token:
                description = "Microsoft 响应中缺少 access_token"
                self._record_failure(account, "invalid_response", description, False)
                raise TokenRefreshError("invalid_response", description, False)

            now = int(time.time())
            expires_in = max(300, int(payload.get("expires_in") or 3600))
            next_refresh_at = now + int(settings["refresh_interval_days"]) * 86400
            new_refresh_token = str(payload.get("refresh_token") or "") or None
            self.store.update_tokens(
                account_id=account_id,
                access_token=access_token,
                access_expires_at=now + expires_in,
                refresh_token=new_refresh_token,
                refreshed_at=now,
                next_refresh_at=next_refresh_at,
            )
            self.store.add_refresh_log(
                account_id,
                int(account["owner_id"]),
                account["email"],
                "success",
                "令牌刷新成功",
            )
            return {
                "access_token": access_token,
                "access_expires_at": now + expires_in,
                "rotated": bool(new_refresh_token),
            }

    def _record_failure(
        self,
        account: dict[str, Any],
        code: str,
        description: str,
        permanent: bool,
    ) -> None:
        now = int(time.time())
        retry_at = None if permanent else now + 30 * 60
        has_valid_access = bool(
            account["access_token"]
            and account["access_expires_at"]
            and int(account["access_expires_at"]) > now + 120
        )
        status = "invalid" if permanent else ("active" if has_valid_access else "error")
        message = f"{code}: {description}"
        self.store.mark_refresh_failure(
            account["id"],
            status,
            message,
            retry_at,
        )
        self.store.add_refresh_log(
            account["id"],
            int(account["owner_id"]),
            account["email"],
            "invalid" if permanent else "error",
            message,
        )

    async def get_access_token(self, account_id: int) -> str:
        account = self.store.get_account(account_id)
        if not account:
            raise TokenRefreshError("not_found", "邮箱不存在", True)

        if (
            account["access_token"]
            and account["access_expires_at"]
            and int(account["access_expires_at"]) > int(time.time()) + 120
        ):
            return str(account["access_token"])

        refreshed = await self.refresh_account(account_id)
        return str(refreshed["access_token"])


class RefreshCoordinator:
    """单进程刷新队列，避免同一令牌被多个任务并发轮换。"""

    def __init__(
        self,
        store: Store,
        token_service: MicrosoftTokenService,
        worker_count: int,
        scheduler_seconds: int,
    ) -> None:
        self.store = store
        self.token_service = token_service
        self.worker_count = worker_count
        self.scheduler_seconds = scheduler_seconds
        self.queue: asyncio.Queue[int] = asyncio.Queue()
        self._queued_ids: set[int] = set()
        self._queued_lock = asyncio.Lock()
        self._tasks: list[asyncio.Task[Any]] = []

    async def start(self) -> None:
        self._tasks = [
            asyncio.create_task(self._worker(index), name=f"refresh-worker-{index}")
            for index in range(self.worker_count)
        ]
        self._tasks.append(
            asyncio.create_task(self._scheduler(), name="refresh-scheduler")
        )
        await self.enqueue(self.store.due_account_ids())

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    async def enqueue(self, account_ids: list[int]) -> int:
        queued = 0
        async with self._queued_lock:
            for account_id in account_ids:
                if account_id in self._queued_ids:
                    continue
                self._queued_ids.add(account_id)
                self.queue.put_nowait(account_id)
                queued += 1
        return queued

    async def _worker(self, index: int) -> None:
        del index
        while True:
            account_id = await self.queue.get()
            try:
                await self.token_service.refresh_account(account_id)
            except TokenRefreshError:
                pass
            except Exception as exc:
                account = self.store.get_account(account_id)
                if account:
                    message = f"internal_error: {exc.__class__.__name__}"
                    self.store.mark_refresh_failure(
                        account_id,
                        "error",
                        message,
                        int(time.time()) + 3600,
                    )
                    self.store.add_refresh_log(
                        account_id,
                        int(account["owner_id"]),
                        account["email"],
                        "error",
                        message,
                    )
            finally:
                async with self._queued_lock:
                    self._queued_ids.discard(account_id)
                self.queue.task_done()

    async def _scheduler(self) -> None:
        while True:
            await asyncio.sleep(self.scheduler_seconds)
            await self.enqueue(self.store.due_account_ids())

    def status(self) -> dict[str, int]:
        return {
            "queued": self.queue.qsize(),
            "workers": self.worker_count,
        }
