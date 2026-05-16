from __future__ import annotations

from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

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


SEMANTIC_FOLDER_FLAGS = {
    "sent":   ("\\Sent",),
    "drafts": ("\\Drafts",),
    "spam":   ("\\Junk",),
    "trash":  ("\\Trash",),
}
SEMANTIC_FOLDER_NAMES = {
    "sent":   ["Sent", "[Gmail]/Sent Mail", "Отправленные"],
    "drafts": ["Drafts", "[Gmail]/Drafts", "Черновики"],
    "spam":   ["Spam", "Junk", "[Gmail]/Spam", "Спам"],
    "trash":  ["Trash", "Bin", "[Gmail]/Trash", "Корзина"],
}
ALLOWED_SEMANTIC_FOLDERS = {"inbox", "sent", "drafts", "spam", "trash"}


def _open_mailbox(account: EmailAccount, folder: str = "INBOX") -> MailBox:
    """Open and login to the IMAP mailbox. Caller is responsible for closing.
    `folder` is the literal IMAP folder name (already resolved)."""
    mailbox_cls = MailBox if account.imap_port == 993 else MailBoxUnencrypted
    mailbox = mailbox_cls(account.imap_host, port=account.imap_port, timeout=IMAP_TIMEOUT_SECONDS)
    mailbox.login(account.email_address, account.get_password(), initial_folder=folder)
    return mailbox


def _resolve_folder(mailbox, semantic: str) -> str:
    """Map a semantic folder name (one of inbox/sent/drafts/spam/trash) to the
    actual folder name on this server. Tries SPECIAL-USE flags first, falls
    back to common names."""
    semantic = (semantic or "inbox").lower()
    if semantic == "inbox":
        return "INBOX"
    flags_wanted = SEMANTIC_FOLDER_FLAGS.get(semantic, ())
    name_fallbacks = SEMANTIC_FOLDER_NAMES.get(semantic, [])
    try:
        folders = list(mailbox.folder.list())
    except Exception:  # noqa: BLE001
        return "INBOX"
    for f in folders:
        f_flags = getattr(f, "flags", ()) or ()
        if any(flag in f_flags for flag in flags_wanted):
            return f.name
    folder_names = {f.name: f for f in folders}
    for candidate in name_fallbacks:
        if candidate in folder_names:
            return candidate
    return "INBOX"


def _open_with_semantic_folder(account: EmailAccount, semantic: str) -> tuple[MailBox, str]:
    """Open mailbox at INBOX, resolve the semantic folder, switch to it.
    Returns (mailbox, resolved_folder_name)."""
    mailbox = _open_mailbox(account, folder="INBOX")
    if (semantic or "inbox").lower() == "inbox":
        return mailbox, "INBOX"
    real = _resolve_folder(mailbox, semantic)
    if real != "INBOX":
        try:
            mailbox.folder.set(real)
        except Exception:  # noqa: BLE001
            pass
    return mailbox, real


def check_status(account: EmailAccount) -> StatusResult:
    try:
        with _open_mailbox(account):
            return StatusResult(account.id, account.email_address, ok=True, message="Connected")
    except TimeoutError:
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
        return value.replace(tzinfo=UTC)
    return value


def fetch_recent(
    account: EmailAccount,
    since: datetime,
    folder: str = "inbox",
) -> tuple[list[EmailHeader], str | None]:
    """Returns (headers, error_message_or_none). `folder` is a semantic name."""
    headers: list[EmailHeader] = []
    try:
        with _open_with_semantic_folder(account, folder)[0] as mailbox:
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
    folder: str = "inbox",
) -> tuple[list[EmailHeader], dict[int, str]]:
    accounts = list(accounts)
    if not accounts:
        return [], {}
    since = datetime.now(UTC) - timedelta(days=days)
    all_headers: list[EmailHeader] = []
    errors: dict[int, str] = {}
    workers = min(MAX_PARALLEL, len(accounts))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_recent, acc, since, folder): acc for acc in accounts}
        for fut in as_completed(futures):
            account = futures[fut]
            headers, err = fut.result()
            if err is not None:
                errors[account.id] = err
            all_headers.extend(headers)
    all_headers.sort(key=lambda h: h.date or datetime.min.replace(tzinfo=UTC), reverse=True)
    return all_headers, errors


def fetch_body(account: EmailAccount, uid: str, folder: str = "inbox") -> EmailFull | None:
    with _open_with_semantic_folder(account, folder)[0] as mailbox:
        for msg in mailbox.fetch(AND(uid=uid), mark_seen=True, limit=1):
            return EmailFull(
                subject=msg.subject or "(no subject)",
                from_=msg.from_ or "",
                to=list(msg.to) if msg.to else [],
                date=msg.date,
                html=msg.html or "",
                text=msg.text or "",
            )
    return None


def fetch_window(
    account: EmailAccount,
    *,
    since: datetime,
    folder: str = "inbox",
    with_bodies: bool = True,
    limit: int = 100,
) -> tuple[list[Any], bool, str | None]:
    """API-shaped fetcher: messages with date >= `since`, newest first.

    Returns (messages, truncated, error). `messages` are raw
    `imap_tools.MailMessage` objects so the serializer can read all fields
    (`to_values`, `headers`, `attachments`, `text`, `html`, `flags`).

    IMAP's date filter is date-granular only — we additionally filter in
    Python by `since` to get minute-level precision, so a `minutes=15`
    request doesn't return everything from earlier today.
    """
    messages: list[Any] = []
    truncated = False
    try:
        with _open_with_semantic_folder(account, folder)[0] as mailbox:
            criteria = AND(date_gte=since.date())
            count = 0
            for msg in mailbox.fetch(
                criteria,
                bulk=True,
                mark_seen=False,
                headers_only=not with_bodies,
                reverse=True,
            ):
                msg_date = _coerce_aware(msg.date)
                if msg_date is not None and msg_date < since:
                    # IMAP gave us today's older messages; skip the ones outside our window.
                    continue
                messages.append(msg)
                count += 1
                if count >= limit:
                    # Peek one more to set truncated flag. Without doing this
                    # we don't know whether the server had more to give.
                    truncated = True
                    break
    except Exception as exc:  # noqa: BLE001
        return [], False, str(exc) or exc.__class__.__name__
    return messages, truncated, None


_TRASH_NAMES = ("Trash", "trash", "Корзина", "INBOX/Trash", "[Gmail]/Trash", "[Gmail]/Корзина")


def _find_trash_folder(mailbox) -> str | None:
    """Look up the destination folder for "deleted" messages.
    Prefer SPECIAL-USE \\Trash flag; fall back to common names."""
    try:
        folders = list(mailbox.folder.list())
    except Exception:  # noqa: BLE001
        return None
    for f in folders:
        flags = getattr(f, "flags", ()) or ()
        if "\\Trash" in flags or r"\Trash" in flags:
            return f.name
    folder_names = {f.name: f for f in folders}
    for candidate in _TRASH_NAMES:
        if candidate in folder_names:
            return candidate
    return None


def mark_unseen(account: EmailAccount, uid: str, folder: str = "inbox") -> None:
    with _open_with_semantic_folder(account, folder)[0] as mailbox:
        mailbox.flag([uid], ["\\Seen"], False)


def delete_message(account: EmailAccount, uid: str, folder: str = "inbox") -> None:
    """Move the message to the account's Trash folder if available;
    otherwise mark it \\Deleted and expunge.
    `folder` is the semantic folder the message currently lives in."""
    with _open_with_semantic_folder(account, folder)[0] as mailbox:
        trash = _find_trash_folder(mailbox)
        if trash and trash != "INBOX" and trash != mailbox.folder.get():
            mailbox.move([uid], trash)
        else:
            mailbox.delete([uid])
