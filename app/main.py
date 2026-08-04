from __future__ import annotations

import asyncio
import re
import secrets
import string
import time
from contextlib import asynccontextmanager
from html import escape
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import parse_qs, urlsplit

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

from .config import config
from .imap_client import MailboxError, OutlookMailbox
from .microsoft import MicrosoftTokenService, RefreshCoordinator, TokenRefreshError
from .security import Vault
from .store import Store


STATIC_DIR = Path(__file__).parent / "static"
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
TENANT_PATTERN = re.compile(r"^[A-Za-z0-9.-]{1,100}$")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]{3,50}$")
TOKEN_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
VALID_STATUSES = {"active", "pending", "error", "invalid"}
PUBLIC_MAIL_PAGE_SIZE = 1
CAPTCHA_TTL_SECONDS = 10 * 60
PUBLIC_SHARE_HOST = (urlsplit(config.public_share_origin).hostname or "").lower()

vault = Vault(config.encryption_key)
store = Store(config.database_path, vault)
token_service = MicrosoftTokenService(store, config)
refresh_coordinator = RefreshCoordinator(
    store,
    token_service,
    config.refresh_workers,
    config.scheduler_seconds,
)
mailbox = OutlookMailbox(config.imap_host, config.imap_port)


@asynccontextmanager
async def lifespan(_: FastAPI):
    store.initialize(config.admin_username, config.admin_password)
    await refresh_coordinator.start()
    try:
        yield
    finally:
        await refresh_coordinator.stop()
        await token_service.close()


app = FastAPI(
    title="Mail Relay",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.add_middleware(
    SessionMiddleware,
    secret_key=config.session_secret,
    session_cookie="mail_relay_session",
    max_age=12 * 60 * 60,
    same_site="strict",
    https_only=config.cookie_secure,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class LoginPayload(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=500)


class ImportPayload(BaseModel):
    content: str = Field(min_length=1, max_length=10_000_000)


class AccountIdsPayload(BaseModel):
    ids: list[int] = Field(default_factory=list, max_length=5000)


class ShareLinkPayload(BaseModel):
    account_id: int = Field(ge=1)


class SettingsPayload(BaseModel):
    tenant: str = Field(min_length=1, max_length=100)
    refresh_interval_days: int = Field(ge=1, le=30)
    mail_page_size: int = Field(ge=10, le=100)


class UserCreatePayload(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=200)


class UserPasswordPayload(BaseModel):
    password: str = Field(min_length=8, max_length=200)


class UserStatusPayload(BaseModel):
    enabled: bool


def require_user(request: Request) -> dict[str, Any]:
    user_id = request.session.get("user_id")
    if not isinstance(user_id, int):
        raise HTTPException(status_code=401, detail="请先登录")
    user = store.get_user(user_id)
    if not user or not user["enabled"]:
        request.session.clear()
        raise HTTPException(status_code=401, detail="账号已退出或停用")
    return user


CurrentUser = Annotated[dict[str, Any], Depends(require_user)]


def require_admin(user: CurrentUser) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="仅管理员可执行此操作")
    return user


AdminUser = Annotated[dict[str, Any], Depends(require_admin)]


def normalized_username(value: str) -> str:
    username = value.strip()
    if not USERNAME_PATTERN.match(username):
        raise HTTPException(status_code=422, detail="用户名格式无效")
    return username


def parse_import(content: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    errors: list[str] = []
    unique_records: dict[str, dict[str, str]] = {}

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        parts = [part.strip() for part in line.split("----", 3)]

        if len(parts) != 4 or any(not part for part in parts):
            errors.append(f"第 {line_number} 行不是 Outlook 四段格式（email----password----client_id----refresh_token）")
            continue

        email_address, password, client_id, refresh_token = parts
        if not EMAIL_PATTERN.match(email_address):
            errors.append(f"第 {line_number} 行邮箱格式无效")
            continue

        unique_records[f"outlook:{email_address.lower()}"] = {
            "provider": "outlook",
            "email": email_address,
            "password": password,
            "client_id": client_id,
            "refresh_token": refresh_token,
        }

    if errors:
        detail = "；".join(errors[:10])
        if len(errors) > 10:
            detail += f"；另有 {len(errors) - 10} 行错误"
        raise HTTPException(status_code=422, detail=detail)
    if not unique_records:
        raise HTTPException(status_code=422, detail="没有可导入的邮箱数据")

    records.extend(unique_records.values())
    return records


def public_shell(title: str, body: str, *, wide: bool = False, status: str = "共享收件箱") -> str:
    width_class = "wide" if wide else "narrow"
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <link rel="stylesheet" href="/static/public-mail.css?v=20260804-mmp">
  <title>{escape(title)}</title>
</head>
<body>
  <div class="page-shell {width_class}">
    <header class="site-header">
      <div class="brand">
        <div class="brand-mark" aria-hidden="true">
          <svg width="23" height="23" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="5" width="18" height="14" rx="3"/><path d="m4 7 8 5 8-5"/></svg>
        </div>
        <div class="brand-copy">
          <p class="brand-title">隐私邮件查看</p>
          <p class="brand-subtitle">受保护的邮件正文入口</p>
        </div>
      </div>
      <span class="status-chip">{escape(status)}</span>
    </header>
    {body}
  </div>
</body>
</html>"""


def public_error_page(title: str, message: str) -> str:
    body = f"""
    <main class="auth-layout">
      <section class="glass-panel auth-card">
        <div class="auth-heading">
          <div class="auth-icon" aria-hidden="true">!</div>
          <p class="eyebrow">Access failed</p>
          <h1>{escape(title)}</h1>
          <p class="lead">{escape(message)}</p>
        </div>
      </section>
    </main>
    """
    return public_shell(title, body, status="无法访问")


def public_not_found() -> HTMLResponse:
    return HTMLResponse(
        public_error_page("链接不存在", "这个共享链接不存在或对应邮箱已删除。"),
        status_code=404,
        headers={"Cache-Control": "no-store"},
    )


def is_public_host(request: Request) -> bool:
    host = (request.headers.get("host") or "").split(":", 1)[0].lower()
    return host in {PUBLIC_SHARE_HOST, "127.0.0.1", "localhost"}


def verified_key(token: str) -> str:
    return f"public_verified:{token}"


def captcha_key(token: str) -> str:
    return f"public_captcha:{token}"


def is_verified(request: Request, token: str) -> bool:
    verified_at = request.session.get(verified_key(token))
    return isinstance(verified_at, int) and verified_at > int(time.time()) - 12 * 60 * 60


def render_captcha_page(token: str, error: str = "") -> str:
    error_html = f'<p class="alert" role="alert">{escape(error)}</p>' if error else ""
    body = f"""
    <main class="auth-layout">
      <section class="glass-panel auth-card captcha-card">
        <div class="auth-heading">
          <div class="auth-icon" aria-hidden="true">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><path d="M12 14v3"/></svg>
          </div>
          <p class="eyebrow">Access verification</p>
          <h1>验证后查看邮件</h1>
          <p class="lead">请输入图片中的 4 位字母或数字，验证成功后即可查看对应正文。</p>
        </div>
        {error_html}
        <div class="captcha-box">
          <img src="/{escape(token)}/captcha.svg?ts={int(time.time())}" alt="验证码" width="180" height="60">
          <p class="muted small">验证码有效期有限，请按图片准确输入。</p>
        </div>
        <form class="form-stack" method="post" action="/{escape(token)}/verify" autocomplete="off">
          <label class="field" for="answer">
            <span>验证码</span>
            <input class="input captcha-input" id="answer" name="answer" maxlength="4" minlength="4" inputmode="text" autocomplete="off" required autofocus>
          </label>
          <button class="btn btn-primary btn-block" type="submit">继续查看</button>
        </form>
        <p class="page-note">此链接仅用于查看对应隐私邮箱的匹配邮件。</p>
      </section>
    </main>
    """
    return public_shell("邮件访问验证", body, status="安全验证")


def captcha_svg(answer: str) -> str:
    # 轻量 SVG 验证码，答案保存在签名会话 Cookie 中。
    chars = []
    for index, char in enumerate(answer):
        x = 46 + index * 24 + secrets.randbelow(5)
        y = 38 + secrets.randbelow(8)
        rotate = secrets.randbelow(28) - 14
        chars.append(
            f'<text x="{x}" y="{y}" transform="rotate({rotate} {x} {y})">{escape(char)}</text>'
        )
    lines = []
    for _ in range(5):
        x1 = 16 + secrets.randbelow(35)
        y1 = 13 + secrets.randbelow(36)
        x2 = 128 + secrets.randbelow(35)
        y2 = 13 + secrets.randbelow(36)
        lines.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}"/>')
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="180" height="60" viewBox="0 0 180 60">
  <rect width="180" height="60" rx="9" fill="#f8fafc"/>
  <g stroke="#94a3b8" stroke-width="1.4" opacity="0.62">{''.join(lines)}</g>
  <g fill="#1e293b" font-family="Georgia, serif" font-size="28" font-weight="700" letter-spacing="2">{''.join(chars)}</g>
</svg>"""


def render_public_mail_page(
    token: str,
    email_address: str,
    result: dict[str, Any],
) -> str:
    items = result["items"]
    cards: list[str] = []
    for message in items:
        sender = message["sender_name"] or message["sender_address"] or "未知发件人"
        if message["sender_address"] and message["sender_address"] not in sender:
            sender = f"{sender} <{message['sender_address']}>"
        cards.append(
            f"""
          <article class="mail-card">
            <div class="mail-card-label">{escape(formatTimeForHtml(message["received_at"]))}</div>
            <h2>{escape(message["subject"] or "无主题")}</h2>
            <p class="mail-meta">发件人：{escape(sender)}</p>
            <pre class="mail-body">{escape(message["body"] or "（无可显示的文本正文）")}</pre>
          </article>
            """
        )

    if not cards:
        cards.append(
            """
          <section class="glass-panel empty-state">
            <div class="empty-icon" aria-hidden="true">0</div>
            <h2>暂无邮件</h2>
            <p>当前页没有可显示的邮件。</p>
          </section>
            """
        )

    refresh_url = f"/{escape(token)}?refresh={int(time.time())}"
    body = f"""
    <main class="public-content">
      <section class="section-heading">
        <div>
          <p class="eyebrow">Inbox view</p>
          <h1>最新邮件</h1>
          <p class="lead">这里仅显示该共享邮箱最新收到的一封邮件。</p>
        </div>
        <div class="section-actions">
          <span class="matched-mailbox">邮箱 <strong>{escape(email_address)}</strong></span>
          <a class="btn btn-primary" href="{refresh_url}">刷新新邮件</a>
        </div>
      </section>
      <section class="mail-list">
        {"".join(cards)}
      </section>
    </main>
    """
    return public_shell(f"{email_address} - 邮件查看", body, wide=True)


def formatTimeForHtml(timestamp: Any) -> str:
    if not timestamp:
        return "未知时间"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(timestamp)))


@app.get("/admin")
@app.get("/admin/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/m/{token}/view")
async def legacy_public_mail_view(token: str) -> Response:
    if not TOKEN_PATTERN.match(token) or not store.get_shared_account(token):
        return public_not_found()
    return RedirectResponse(f"{config.public_share_origin}/{token}", status_code=302)


@app.get("/{token}/captcha.svg")
async def public_captcha(token: str, request: Request) -> Response:
    if not TOKEN_PATTERN.match(token) or not is_public_host(request) or not store.get_shared_account(token):
        return Response("not found", status_code=404)
    alphabet = string.ascii_uppercase + string.digits
    answer = "".join(secrets.choice(alphabet) for _ in range(4))
    request.session[captcha_key(token)] = {
        "answer": answer.lower(),
        "created_at": int(time.time()),
    }
    return Response(
        captcha_svg(answer),
        media_type="image/svg+xml",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/{token}/verify")
async def verify_public_mail(token: str, request: Request) -> Response:
    if not TOKEN_PATTERN.match(token) or not is_public_host(request) or not store.get_shared_account(token):
        return public_not_found()

    body = (await request.body()).decode("utf-8", errors="ignore")
    answer = (parse_qs(body).get("answer") or [""])[0].strip().lower()
    captcha = request.session.get(captcha_key(token))
    created_at = int(captcha.get("created_at", 0)) if isinstance(captcha, dict) else 0
    expected = str(captcha.get("answer", "")) if isinstance(captcha, dict) else ""
    if not answer or answer != expected or created_at < int(time.time()) - CAPTCHA_TTL_SECONDS:
        return HTMLResponse(
            render_captcha_page(token, "验证码错误或已过期，请重新输入。"),
            status_code=400,
            headers={"Cache-Control": "no-store"},
        )

    request.session.pop(captcha_key(token), None)
    request.session[verified_key(token)] = int(time.time())
    return RedirectResponse(f"/{token}", status_code=303)


@app.get("/{token}", name="public_mail_view")
async def public_mail_view(
    token: str,
    request: Request,
) -> HTMLResponse:
    if not TOKEN_PATTERN.match(token) or not is_public_host(request):
        return public_not_found()

    account = store.get_shared_account(token)
    if not account:
        return public_not_found()

    if not is_verified(request, token):
        return HTMLResponse(
            render_captcha_page(token),
            headers={"Cache-Control": "no-store"},
        )

    try:
        access_token = await token_service.get_access_token(int(account["id"]))
        result = await asyncio.to_thread(
            mailbox.list_messages_page,
            account["email"],
            access_token,
            1,
            PUBLIC_MAIL_PAGE_SIZE,
        )
    except TokenRefreshError as exc:
        return HTMLResponse(
            public_error_page("暂时无法读取邮件", exc.description),
            status_code=502,
            headers={"Cache-Control": "no-store"},
        )
    except MailboxError as exc:
        store.set_mail_error(int(account["id"]), str(exc))
        return HTMLResponse(
            public_error_page("暂时无法读取邮件", str(exc)),
            status_code=502,
            headers={"Cache-Control": "no-store"},
        )

    now = int(time.time())
    store.mark_share_access(token)
    store.update_last_mail(int(account["id"]), now)
    return HTMLResponse(
        render_public_mail_page(token, account["email"], result),
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/session")
async def session_state(request: Request) -> dict[str, str | bool]:
    user_id = request.session.get("user_id")
    user = store.get_user(user_id) if isinstance(user_id, int) else None
    if not user or not user["enabled"]:
        request.session.clear()
        return {"authenticated": False, "username": "", "role": ""}
    return {
        "authenticated": True,
        "username": str(user["username"]),
        "role": str(user["role"]),
    }


@app.post("/api/login")
async def login(payload: LoginPayload, request: Request) -> dict[str, str]:
    user = store.authenticate_user(payload.username.strip(), payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="用户名或密码错误")

    request.session.clear()
    request.session["user_id"] = int(user["id"])
    return {"username": str(user["username"]), "role": str(user["role"])}


@app.post("/api/logout")
async def logout(request: Request) -> dict[str, bool]:
    request.session.clear()
    return {"ok": True}


@app.get("/api/dashboard")
async def dashboard(user: CurrentUser) -> dict[str, object]:
    return {
        "accounts": store.dashboard_stats(int(user["id"])),
        "service": refresh_coordinator.status(),
    }


@app.get("/api/accounts")
async def list_accounts(
    user: CurrentUser,
    search: str = Query(default="", max_length=200),
    status: str = Query(default="", max_length=20),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=10, le=100),
) -> dict[str, object]:
    normalized_status = status.strip().lower()
    if normalized_status and normalized_status not in VALID_STATUSES:
        raise HTTPException(status_code=422, detail="状态筛选值无效")
    return store.list_accounts(
        owner_id=int(user["id"]),
        search=search.strip(),
        status=normalized_status,
        page=page,
        page_size=page_size,
    )


@app.post("/api/accounts/import")
async def import_accounts(
    payload: ImportPayload,
    user: CurrentUser,
) -> dict[str, int]:
    result = store.import_accounts(int(user["id"]), parse_import(payload.content))
    queued = await refresh_coordinator.enqueue(
        store.refreshable_ids(int(user["id"]), result["account_ids"])
    )
    return {
        "imported": int(result["imported"]),
        "updated": int(result["updated"]),
        "queued": queued,
    }


@app.post("/api/accounts/refresh")
async def refresh_accounts(
    payload: AccountIdsPayload,
    user: CurrentUser,
) -> dict[str, int]:
    account_ids = store.refreshable_ids(int(user["id"]), payload.ids or None)
    queued = await refresh_coordinator.enqueue(account_ids)
    return {"matched": len(account_ids), "queued": queued}


@app.delete("/api/accounts")
async def delete_accounts(
    payload: AccountIdsPayload,
    user: CurrentUser,
) -> dict[str, int]:
    if not payload.ids:
        raise HTTPException(status_code=422, detail="请选择要删除的邮箱")
    return {"deleted": store.delete_accounts(int(user["id"]), payload.ids)}


@app.get("/api/accounts/export")
async def export_accounts(
    user: CurrentUser,
    ids: str = Query(default="", max_length=50000),
) -> Response:
    account_ids: list[int] | None = None
    if ids.strip():
        try:
            account_ids = [int(item) for item in ids.split(",") if item.strip()]
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="导出邮箱 ID 无效") from exc

    lines = store.export_accounts(int(user["id"]), account_ids)
    content = "\n".join(lines)
    if content:
        content += "\n"
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="outlook-accounts.txt"',
            "Cache-Control": "no-store",
        },
    )


@app.post("/api/accounts/share")
async def create_share_link(
    payload: ShareLinkPayload,
    user: CurrentUser,
) -> dict[str, str]:
    try:
        link = store.get_or_create_share_link(int(user["id"]), payload.account_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "email": str(link["email"]),
        "token": str(link["token"]),
        "path": f"/{link['token']}",
        "url": f"{config.public_share_origin}/{link['token']}",
    }


@app.get("/api/accounts/{account_id}/messages")
async def list_messages(account_id: int, user: CurrentUser) -> dict[str, object]:
    account = store.get_account(account_id, int(user["id"]))
    if not account:
        raise HTTPException(status_code=404, detail="邮箱不存在")

    try:
        limit = int(store.get_settings()["mail_page_size"])
        access_token = await token_service.get_access_token(account_id)
        messages = await asyncio.to_thread(
            mailbox.list_messages,
            account["email"],
            access_token,
            limit,
        )
    except TokenRefreshError as exc:
        raise HTTPException(status_code=502, detail=exc.description) from exc
    except MailboxError as exc:
        store.set_mail_error(account_id, str(exc))
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    last_mail_at = int(time.time())
    store.update_last_mail(account_id, last_mail_at)
    return {"email": account["email"], "items": messages, "last_mail_at": last_mail_at}


@app.get("/api/accounts/{account_id}/messages/{uid}")
async def get_message(
    account_id: int,
    uid: str,
    user: CurrentUser,
) -> dict[str, object]:
    account = store.get_account(account_id, int(user["id"]))
    if not account:
        raise HTTPException(status_code=404, detail="邮箱不存在")

    try:
        access_token = await token_service.get_access_token(account_id)
        message = await asyncio.to_thread(
            mailbox.get_message,
            account["email"],
            access_token,
            uid,
        )
    except TokenRefreshError as exc:
        raise HTTPException(status_code=502, detail=exc.description) from exc
    except MailboxError as exc:
        store.set_mail_error(account_id, str(exc))
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return message


@app.get("/api/refresh-logs")
async def refresh_logs(
    user: CurrentUser,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=30, ge=10, le=100),
) -> dict[str, object]:
    return store.list_refresh_logs(int(user["id"]), page, page_size)


@app.get("/api/settings")
async def get_settings(_: AdminUser) -> dict[str, object]:
    return store.get_settings()


@app.put("/api/settings")
async def update_settings(
    payload: SettingsPayload,
    _: AdminUser,
) -> dict[str, object]:
    tenant = payload.tenant.strip()
    if not TENANT_PATTERN.match(tenant):
        raise HTTPException(status_code=422, detail="租户值格式无效")
    store.update_settings(
        tenant=tenant,
        refresh_interval_days=payload.refresh_interval_days,
        mail_page_size=payload.mail_page_size,
    )
    return store.get_settings()


@app.get("/api/users")
async def list_users(_: AdminUser) -> dict[str, object]:
    return {"items": store.list_users()}


@app.post("/api/users")
async def create_user(
    payload: UserCreatePayload,
    _: AdminUser,
) -> dict[str, object]:
    try:
        user = store.create_user(
            normalized_username(payload.username),
            payload.password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return user


@app.put("/api/users/{user_id}/password")
async def reset_user_password(
    user_id: int,
    payload: UserPasswordPayload,
    _: AdminUser,
) -> dict[str, bool]:
    target = store.get_user(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="用户不存在")
    if target["role"] == "admin":
        raise HTTPException(status_code=422, detail="管理员密码由服务器环境变量管理")
    return {"updated": store.reset_user_password(user_id, payload.password)}


@app.patch("/api/users/{user_id}")
async def update_user_status(
    user_id: int,
    payload: UserStatusPayload,
    _: AdminUser,
) -> dict[str, bool]:
    target = store.get_user(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="用户不存在")
    if target["role"] == "admin":
        raise HTTPException(status_code=422, detail="不能停用管理员")
    return {"updated": store.set_user_enabled(user_id, payload.enabled)}


@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, _: AdminUser) -> dict[str, bool]:
    target = store.get_user(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="用户不存在")
    if target["role"] == "admin":
        raise HTTPException(status_code=422, detail="不能删除管理员")
    return {"deleted": store.delete_user(user_id)}


@app.exception_handler(404)
async def not_found(request: Request, _: Exception) -> Response:
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "接口不存在"}, status_code=404)
    if request.url.path == "/admin" or request.url.path.startswith("/admin/"):
        return FileResponse(STATIC_DIR / "index.html")
    return HTMLResponse(
        public_error_page("页面不存在", "请检查共享链接是否完整。"),
        status_code=404,
        headers={"Cache-Control": "no-store"},
    )
