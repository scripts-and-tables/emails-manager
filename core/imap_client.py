from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable

from imap_tools import AND, MailBox, MailBoxUnencrypted

from .models import EmailAccount

IMAP_TIMEOUT_SECONDS = 15
MAX_PARALLEL = 8


@dataclass
class StatusResult:
    account_id: int
    email_address: str
    ok: bool
    message: str = ""


@dataclass
class EmailHeader:
    account_id: int
    account_email: str
    uid: str
    subject: str
    from_: str
    date: datetime | None
    seen: bool = False


@dataclass
class EmailFull:
    subject: str
    from_: str
    to: list[str] = field(default_factory=list)
    date: datetime | None = None
    html: str = ""
    text: str = ""


def _open_mailbox(account: EmailAccount) -> MailBox:
    """Open and login to the IMAP mailbox. Caller is responsible for closing."""
    mailbox_cls = MailBox if account.imap_port == 993 else MailBoxUnencrypted
    mailbox = mailbox_cls(account.imap_host, port=account.imap_port, timeout=IMAP_TIMEOUT_SECONDS)
    mailbox.login(account.email_address, account.get_password(), initial_folder="INBOX")
    return mailbox


def check_status(account: EmailAccount) -> StatusResult:
    try:
        with _open_mailbox(account):
            return StatusResult(account.id, account.email_address, ok=True, message="Connected")
    except (socket.timeout, TimeoutError):
        return StatusResult(account.id, account.email_address, ok=False, message="Connection timed out")
    except Exception as exc:  # noqa: BLE001 — surface any IMAP failure as a row, not a 500
        return StatusResult(account.id, account.email_address, ok=False, message=str(exc) or exc.__class__.__name__)


def check_status_bulk(accounts: Iterable[EmailAccount]) -> list[StatusResult]:
    accounts = list(accounts)
    if not accounts:
        return []
    results: list[StatusResult] = []
    workers = min(MAX_PARALLEL, len(accounts))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check_status, acc): acc for acc in accounts}
        for fut in as_completed(futures):
            results.append(fut.result())
    by_id = {r.account_id: r for r in results}
    return [by_id[a.id] for a in accounts]


def _coerce_aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def fetch_recent(account: EmailAccount, since: datetime) -> tuple[list[EmailHeader], str | None]:
    """Returns (headers, error_message_or_none)."""
    headers: list[EmailHeader] = []
    try:
        with _open_mailbox(account) as mailbox:
            criteria = AND(date_gte=since.date())
            for msg in mailbox.fetch(
                criteria,
                bulk=True,
                mark_seen=False,
                headers_only=True,
                reverse=True,
            ):
                headers.append(
                    EmailHeader(
                        account_id=account.id,
                        account_email=account.email_address,
                        uid=msg.uid or "",
                        subject=msg.subject or "(no subject)",
                        from_=msg.from_ or "",
                        date=_coerce_aware(msg.date),
                        seen="\\Seen" in (msg.flags or ()),
                    )
                )
    except Exception as exc:  # noqa: BLE001
        return [], str(exc) or exc.__class__.__name__
    return headers, None


def fetch_recent_bulk(
    accounts: Iterable[EmailAccount],
    days: int,
) -> tuple[list[EmailHeader], dict[int, str]]:
    accounts = list(accounts)
    if not accounts:
        return [], {}
    since = datetime.now(timezone.utc) - timedelta(days=days)
    all_headers: list[EmailHeader] = []
    errors: dict[int, str] = {}
    workers = min(MAX_PARALLEL, len(accounts))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_recent, acc, since): acc for acc in accounts}
        for fut in as_completed(futures):
            account = futures[fut]
            headers, err = fut.result()
            if err is not None:
                errors[account.id] = err
            all_headers.extend(headers)
    all_headers.sort(key=lambda h: h.date or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return all_headers, errors


def fetch_body(account: EmailAccount, uid: str) -> EmailFull | None:
    with _open_mailbox(account) as mailbox:
        for msg in mailbox.fetch(AND(uid=uid), mark_seen=False, limit=1):
            return EmailFull(
                subject=msg.subject or "(no subject)",
                from_=msg.from_ or "",
                to=list(msg.to) if msg.to else [],
                date=msg.date,
                html=msg.html or "",
                text=msg.text or "",
            )
    return None
