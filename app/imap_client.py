from __future__ import annotations

import email
import imaplib
import re
import ssl
from email.header import decode_header
from email.message import Message
from email.policy import default
from email.utils import parseaddr, parsedate_to_datetime
from html import unescape
from html.parser import HTMLParser
from typing import Any


class MailboxError(RuntimeError):
    pass


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


class OutlookMailbox:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

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
        except (imaplib.IMAP4.error, OSError, ssl.SSLError) as exc:
            raise MailboxError(f"IMAP XOAUTH2 认证失败：{exc}") from exc

    def list_messages(
        self,
        email_address: str,
        access_token: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        connection = self._connect(email_address, access_token)
        try:
            status, _ = connection.select("INBOX", readonly=True)
            if status != "OK":
                raise MailboxError("无法打开 INBOX")
            status, data = connection.uid("search", None, "ALL")
            if status != "OK" or not data or not data[0]:
                return []

            uids = [int(x) for x in data[0].split()]
            selected = [str(x) for x in sorted(uids, reverse=True)[:limit]]
            messages: list[dict[str, Any]] = []
            for uid in selected:
                status, payload = connection.uid(
                    "fetch",
                    uid.encode(),
                    "(BODY.PEEK[]<0.1048576>)",
                )
                if status != "OK":
                    continue
                parsed = email.message_from_bytes(_message_bytes(payload), policy=default)
                sender_name, sender_address = parseaddr(_decode_header(parsed.get("From")))
                messages.append(
                    {
                        "uid": uid,
                        "subject": _decode_header(parsed.get("Subject")) or "无主题",
                        "sender_name": _decode_header(sender_name) or sender_address,
                        "sender_address": sender_address,
                        "received_at": _parse_date(parsed.get("Date")),
                        "message_id": str(parsed.get("Message-ID") or ""),
                        "body": _body_text(parsed),
                    }
                )
            return messages
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
            status, _ = connection.select("INBOX", readonly=True)
            if status != "OK":
                raise MailboxError("无法打开 INBOX")
            status, data = connection.uid("search", None, "ALL")
            if status != "OK" or not data or not data[0]:
                return {"items": [], "total": 0, "page": page, "page_size": page_size}

            uids = [int(x) for x in data[0].split()]
            offset = (page - 1) * page_size
            selected = [str(x) for x in sorted(uids, reverse=True)[offset:offset + page_size]]
            messages: list[dict[str, Any]] = []
            for uid in selected:
                status, payload = connection.uid(
                    "fetch",
                    uid.encode(),
                    "(BODY.PEEK[]<0.1048576>)",
                )
                if status != "OK":
                    continue
                parsed = email.message_from_bytes(_message_bytes(payload), policy=default)
                sender_name, sender_address = parseaddr(_decode_header(parsed.get("From")))
                messages.append(
                    {
                        "uid": uid,
                        "subject": _decode_header(parsed.get("Subject")) or "无主题",
                        "sender_name": _decode_header(sender_name) or sender_address,
                        "sender_address": sender_address,
                        "received_at": _parse_date(parsed.get("Date")),
                        "message_id": str(parsed.get("Message-ID") or ""),
                        "body": _body_text(parsed),
                    }
                )
            return {
                "items": messages,
                "total": len(uids),
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
            status, payload = connection.uid(
                "fetch",
                uid.encode(),
                "(BODY.PEEK[]<0.1048576>)",
            )
            if status != "OK":
                raise MailboxError("无法读取邮件正文")

            parsed = email.message_from_bytes(_message_bytes(payload), policy=default)
            sender_name, sender_address = parseaddr(_decode_header(parsed.get("From")))
            return {
                "uid": uid,
                "subject": _decode_header(parsed.get("Subject")) or "无主题",
                "sender_name": _decode_header(sender_name) or sender_address,
                "sender_address": sender_address,
                "received_at": _parse_date(parsed.get("Date")),
                "message_id": str(parsed.get("Message-ID") or ""),
                "body": _body_text(parsed),
            }
        except imaplib.IMAP4.error as exc:
            raise MailboxError(f"读取邮件正文失败：{exc}") from exc
        finally:
            try:
                connection.logout()
            except imaplib.IMAP4.error:
                pass
