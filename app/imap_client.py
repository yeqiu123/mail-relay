from __future__ import annotations

import email
import imaplib
import re
import ssl
from email.header import decode_header
from email.message import Message
from email.policy import default
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html import unescape
from html.parser import HTMLParser
from typing import Any, Callable


MAX_UID_SEARCH_BLOCKS = 100


class MailboxError(RuntimeError):
    def __init__(self, message: str, authentication_failed: bool = False) -> None:
        super().__init__(message)
        self.authentication_failed = authentication_failed


def _is_authentication_failure(message: str) -> bool:
    """仅将明确的凭据拒绝视为账户授权异常。"""
    value = message.lower()
    if "authenticated but not connected" in value:
        return False
    return any(
        marker in value
        for marker in (
            "authenticate failed",
            "authenticationfailed",
            "authentication failed",
            "invalid credentials",
            "invalid token",
        )
    )


def _decode_header(value: str | None) -> str:
    if not value:
        return ""
    parts: list[str] = []
    for chunk, encoding in decode_header(value):
        if isinstance(chunk, bytes):
            for charset in (encoding, "utf-8", "gb18030", "latin-1"):
                if not charset:
                    continue
                try:
                    parts.append(chunk.decode(charset))
                    break
                except (LookupError, UnicodeDecodeError):
                    continue
            else:
                parts.append(chunk.decode("utf-8", errors="replace"))
        else:
            parts.append(chunk)
    return "".join(parts).strip()


def _parse_date(value: str | None) -> int | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
        return int(parsed.timestamp())
    except (TypeError, ValueError, OverflowError):
        return None


def _message_bytes(data: list[Any]) -> bytes:
    chunks = [
        item[1]
        for item in data
        if isinstance(item, tuple)
        and len(item) >= 2
        and isinstance(item[1], (bytes, bytearray))
    ]
    if not chunks:
        raise MailboxError("Microsoft IMAP 未返回有效邮件内容")
    return b"".join(chunks)


def _message_size(data: list[Any]) -> int | None:
    for item in data:
        if not isinstance(item, tuple) or not item:
            continue
        metadata = item[0]
        if not isinstance(metadata, (bytes, bytearray)):
            continue
        match = re.search(rb"RFC822\.SIZE\s+(\d+)", metadata)
        if match:
            return int(match.group(1))
    return None


def _mailbox_count(data: list[Any]) -> int:
    if not data or not isinstance(data[0], (bytes, bytearray)):
        return 0
    try:
        return max(0, int(data[0]))
    except ValueError:
        return 0


def _response_number(connection: imaplib.IMAP4_SSL, name: str) -> int:
    _, data = connection.response(name)
    value = (data or [b""])[-1]
    try:
        return int(value)
    except (TypeError, ValueError):
        raise MailboxError(f"无法读取 INBOX {name}") from None


def _recent_uids_after(
    connection: imaplib.IMAP4_SSL,
    after_uid: int,
    limit: int,
) -> list[int]:
    lower = max(1, after_uid + 1)
    upper = _response_number(connection, "UIDNEXT") - 1
    if upper < lower:
        return []

    block_size = max(100, limit)
    uids: set[int] = set()
    for _ in range(MAX_UID_SEARCH_BLOCKS):
        start = max(lower, upper - block_size + 1)
        status, data = connection.uid("search", None, "UID", f"{start}:{upper}")
        if status != "OK":
            raise MailboxError("无法搜索 INBOX 邮件")
        for chunk in data or []:
            if isinstance(chunk, (bytes, bytearray)):
                uids.update(int(value) for value in chunk.split() if value.isdigit())
        upper = start - 1
        if len(uids) >= limit or upper < lower:
            break
    else:
        raise MailboxError("INBOX UID 范围过大，已停止本次同步")

    return sorted(uids)[-limit:]


def _sequence_uids(
    connection: imaplib.IMAP4_SSL,
    start: int,
    end: int,
) -> list[int]:
    if start > end:
        return []
    status, data = connection.fetch(f"{start}:{end}", "(UID)")
    if status != "OK":
        raise MailboxError("无法读取 INBOX UID 列表")
    uids: set[int] = set()
    for item in data or []:
        parts = item if isinstance(item, tuple) else (item,)
        for part in parts:
            if not isinstance(part, (bytes, bytearray)):
                continue
            match = re.search(rb"\bUID\s+(\d+)", part)
            if match:
                uids.add(int(match.group(1)))
    return sorted(uids)


def _compact_text(value: str) -> str:
    """统一邮件换行并移除 HTML 模板产生的纯空白行。"""
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    lines: list[str] = []
    for raw_line in value.split("\n"):
        line = re.sub(r"[ \t\u00a0\u200b\ufeff]+", " ", raw_line).strip()
        if line:
            lines.append(line)
    return "\n".join(lines)


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if tag in {"script", "style", "noscript"}:
            self._skip_depth += 1
        elif tag in {"br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4"}:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1
        elif tag in {"p", "div", "li", "tr"}:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self._parts.append(data)

    def text(self) -> str:
        return _compact_text(unescape("".join(self._parts)))


def _part_text(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset)
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


def _body_text(message: Message) -> str:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    parts = message.walk() if message.is_multipart() else [message]

    for part in parts:
        content_type = part.get_content_type()
        disposition = (part.get("Content-Disposition") or "").lower()
        if "attachment" in disposition:
            continue
        if content_type == "text/plain":
            plain_parts.append(_part_text(part))
        elif content_type == "text/html":
            html_parts.append(_part_text(part))

    if plain_parts:
        return _compact_text(
            "\n".join(part for part in plain_parts if part.strip())
        )[:200000]

    extractor = _HTMLTextExtractor()
    extractor.feed("\n".join(html_parts))
    return extractor.text()[:200000]


def _recipients(message: Message) -> list[dict[str, str]]:
    recipients: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    recipient_headers = {
        "to": ("To",),
        "cc": ("Cc",),
        "bcc": ("Bcc",),
        "envelope": (
            "Delivered-To",
            "X-Original-To",
            "Envelope-To",
            "X-Envelope-To",
            "X-MS-Exchange-Organization-OriginalEnvelopeRecipient",
            "X-MS-Exchange-Organization-OriginalEnvelopeRecipients",
        ),
    }
    for recipient_type, headers in recipient_headers.items():
        values = [
            str(value)
            for header in headers
            for value in message.get_all(header, [])
        ]
        if recipient_type == "envelope":
            values = [
                re.sub(r"(?i)\bSMTP:", "", value).replace(";", ",").strip(" ,")
                for value in values
            ]
        for _, address in getaddresses(values):
            email_address = address.strip().lower()
            key = (email_address, recipient_type)
            if not email_address or key in seen:
                continue
            seen.add(key)
            recipients.append(
                {"email": email_address, "recipient_type": recipient_type}
            )
    return recipients


class OutlookMailbox:
    def __init__(self, host: str, port: int, max_message_bytes: int) -> None:
        self.host = host
        self.port = port
        self.max_message_bytes = max_message_bytes

    def _fetch_message(
        self,
        connection: imaplib.IMAP4_SSL,
        uid: str,
    ) -> dict[str, Any]:
        status, payload = connection.uid(
            "fetch",
            uid.encode(),
            f"(RFC822.SIZE BODY.PEEK[]<0.{self.max_message_bytes}>)",
        )
        if status != "OK":
            raise MailboxError(f"无法读取邮件 UID {uid}")

        parsed = email.message_from_bytes(_message_bytes(payload), policy=default)
        sender_name, sender_address = parseaddr(_decode_header(parsed.get("From")))
        body = _body_text(parsed)
        source_size = _message_size(payload)
        if source_size and source_size > self.max_message_bytes:
            marker = f"\n\n[邮件超过 {self.max_message_bytes} 字节，正文仅保留已读取部分]"
            body = body[: max(0, 200_000 - len(marker))] + marker
        return {
            "uid": uid,
            "subject": _decode_header(parsed.get("Subject")) or "无主题",
            "sender_name": _decode_header(sender_name) or sender_address,
            "sender_address": sender_address,
            "received_at": _parse_date(parsed.get("Date")),
            "message_id": str(parsed.get("Message-ID") or ""),
            "body": body,
            "recipients": _recipients(parsed),
        }

    def _connect(self, email_address: str, access_token: str) -> imaplib.IMAP4_SSL:
        try:
            connection = imaplib.IMAP4_SSL(
                self.host,
                self.port,
                ssl_context=ssl.create_default_context(),
                timeout=30,
            )
            auth_string = (
                f"user={email_address}\x01auth=Bearer {access_token}\x01\x01"
            ).encode("utf-8")
            connection.authenticate("XOAUTH2", lambda _: auth_string)
            return connection
        except imaplib.IMAP4.error as exc:
            detail = str(exc)
            raise MailboxError(
                f"IMAP XOAUTH2 认证失败：{detail}",
                _is_authentication_failure(detail),
            ) from exc
        except (OSError, ssl.SSLError) as exc:
            raise MailboxError(f"IMAP 连接失败：{exc}") from exc

    def list_messages(
        self,
        email_address: str,
        access_token: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        connection = self._connect(email_address, access_token)
        try:
            status, selected_data = connection.select("INBOX", readonly=True)
            if status != "OK":
                raise MailboxError("无法打开 INBOX")
            total = _mailbox_count(selected_data)
            if not total:
                return []

            uids = _sequence_uids(connection, max(1, total - limit + 1), total)
            selected = [str(x) for x in sorted(uids, reverse=True)[:limit]]
            messages: list[dict[str, Any]] = []
            for uid in selected:
                messages.append(self._fetch_message(connection, uid))
            return messages
        except imaplib.IMAP4.error as exc:
            raise MailboxError(f"读取收件箱失败：{exc}") from exc
        finally:
            try:
                connection.logout()
            except imaplib.IMAP4.error:
                pass

    def process_messages_after(
        self,
        email_address: str,
        access_token: str,
        expected_uid_validity: str,
        after_uid: int,
        batch_size: int,
        message_limit: int,
        on_batch: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]:
        connection = self._connect(email_address, access_token)
        try:
            status, _ = connection.select("INBOX", readonly=True)
            if status != "OK":
                raise MailboxError("无法打开 INBOX")
            _, validity_data = connection.response("UIDVALIDITY")
            validity_value = (validity_data or [b""])[-1]
            uid_validity = (
                validity_value.decode("ascii", errors="ignore")
                if isinstance(validity_value, bytes)
                else str(validity_value or "")
            ).strip()
            if not uid_validity:
                raise MailboxError("无法读取 INBOX UIDVALIDITY")

            reset = bool(expected_uid_validity and expected_uid_validity != uid_validity)
            cursor = 0 if reset else max(0, after_uid)
            unseen_uids = _recent_uids_after(
                connection,
                cursor,
                max(1, message_limit),
            )
            size = max(1, batch_size)
            offsets = range(0, len(unseen_uids), size) if unseen_uids else [0]
            last_uid = cursor
            for batch_index, offset in enumerate(offsets):
                selected = unseen_uids[offset:offset + size]
                messages: list[dict[str, Any]] = []
                for uid in selected:
                    messages.append(self._fetch_message(connection, str(uid)))
                if selected:
                    last_uid = selected[-1]
                has_more = offset + len(selected) < len(unseen_uids)
                on_batch(
                    {
                        "items": messages,
                        "uid_validity": uid_validity,
                        "reset": reset and batch_index == 0,
                        "last_uid": last_uid,
                        "has_more": has_more,
                    }
                )
            return {"uid_validity": uid_validity, "last_uid": last_uid}
        except imaplib.IMAP4.error as exc:
            raise MailboxError(f"读取收件箱失败：{exc}") from exc
        finally:
            try:
                connection.logout()
            except imaplib.IMAP4.error:
                pass

    def list_messages_page(
        self,
        email_address: str,
        access_token: str,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        connection = self._connect(email_address, access_token)
        try:
            status, selected_data = connection.select("INBOX", readonly=True)
            if status != "OK":
                raise MailboxError("无法打开 INBOX")
            total = _mailbox_count(selected_data)
            if not total:
                return {"items": [], "total": 0, "page": page, "page_size": page_size}

            offset = (page - 1) * page_size
            end = total - offset
            start = max(1, end - page_size + 1)
            uids = _sequence_uids(connection, start, end)
            selected = [str(x) for x in sorted(uids, reverse=True)]
            messages: list[dict[str, Any]] = []
            for uid in selected:
                try:
                    messages.append(self._fetch_message(connection, uid))
                except MailboxError:
                    continue
            return {
                "items": messages,
                "total": total,
                "page": page,
                "page_size": page_size,
            }
        except imaplib.IMAP4.error as exc:
            raise MailboxError(f"读取收件箱失败：{exc}") from exc
        finally:
            try:
                connection.logout()
            except imaplib.IMAP4.error:
                pass

    def get_message(
        self,
        email_address: str,
        access_token: str,
        uid: str,
    ) -> dict[str, Any]:
        if not uid.isdigit():
            raise MailboxError("邮件 UID 无效")

        connection = self._connect(email_address, access_token)
        try:
            status, _ = connection.select("INBOX", readonly=True)
            if status != "OK":
                raise MailboxError("无法打开 INBOX")
            return self._fetch_message(connection, uid)
        except imaplib.IMAP4.error as exc:
            raise MailboxError(f"读取邮件正文失败：{exc}") from exc
        finally:
            try:
                connection.logout()
            except imaplib.IMAP4.error:
                pass
