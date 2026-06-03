"""Attach mail.ru aliases to existing accounts.

Aliases share their parent account's IMAP connection and password, so this
command only links addresses — it never touches credentials. It's idempotent:
re-running skips aliases that are already attached, so it's safe to run again
after adding more.

Input is one or more `alias  parent` pairs, supplied either inline:

    python manage.py attach_aliases --account riveracazanova@mail.ru \\
        cyril.lukin@mail.ru gennady.lukin11@mail.ru

or as a whitespace/CSV-separated file (use - for stdin), one pair per line:

    python manage.py attach_aliases --file aliases.tsv

    # aliases.tsv
    cyril.lukin@mail.ru     riveracazanova@mail.ru
    gennady.lukin11@mail.ru riveracazanova@mail.ru

Pass --dry-run to validate and preview without writing anything.
"""

from __future__ import annotations

import sys

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from core.models import EmailAccount, EmailAlias


class Command(BaseCommand):
    help = "Attach aliases to existing email accounts (idempotent)."

    def add_arguments(self, parser):
        parser.add_argument(
            "aliases",
            nargs="*",
            help="Alias addresses to attach to --account (inline mode).",
        )
        parser.add_argument(
            "--account",
            dest="account",
            help="Parent account address for the inline alias list.",
        )
        parser.add_argument(
            "--file",
            dest="file",
            help="Path to a file of 'alias parent' pairs (use - for stdin).",
        )
        parser.add_argument(
            "--owner",
            dest="owner",
            help="Username to disambiguate when several users own the same address.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Validate and preview without writing.",
        )

    def handle(self, *args, **opts):
        pairs = self._collect_pairs(opts)
        if not pairs:
            raise CommandError(
                "No alias pairs given. Use --account EMAIL alias... or --file PATH."
            )

        dry_run = opts["dry_run"]
        owner = opts.get("owner")
        added = skipped = failed = 0

        # One transaction for the whole run so a mid-list failure doesn't leave
        # a half-attached account. --dry-run rolls back unconditionally.
        try:
            with transaction.atomic():
                for alias_addr, parent_addr in pairs:
                    account = self._resolve_account(parent_addr, owner)
                    result = self._attach_one(account, alias_addr, dry_run)
                    if result == "added":
                        added += 1
                        self.stdout.write(self.style.SUCCESS(f"  + {alias_addr}  ->  {parent_addr}"))
                    elif result == "skipped":
                        skipped += 1
                        self.stdout.write(f"  = {alias_addr}  (already attached)")
                if dry_run:
                    transaction.set_rollback(True)
        except _AliasError as exc:
            # Surface validation failures as a clean command error (whole run
            # already rolled back by the atomic block).
            raise CommandError(str(exc)) from exc

        verb = "Would attach" if dry_run else "Attached"
        self.stdout.write(
            self.style.MIGRATE_HEADING(
                f"\n{verb} {added} alias(es); {skipped} already present; {failed} failed."
            )
        )
        if dry_run:
            self.stdout.write("Dry run - no changes were saved.")

    # --- helpers -----------------------------------------------------------

    def _collect_pairs(self, opts) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []

        if opts.get("file"):
            pairs.extend(self._read_file(opts["file"]))

        if opts.get("aliases"):
            if not opts.get("account"):
                raise CommandError("Inline aliases require --account EMAIL.")
            parent = opts["account"].strip()
            pairs.extend((a.strip(), parent) for a in opts["aliases"] if a.strip())
        elif opts.get("account") and not opts.get("file"):
            raise CommandError("--account given but no alias addresses listed.")

        # De-dupe identical pairs while preserving order.
        seen: set[tuple[str, str]] = set()
        unique: list[tuple[str, str]] = []
        for alias_addr, parent in pairs:
            key = (alias_addr.lower(), parent.lower())
            if key not in seen:
                seen.add(key)
                unique.append((alias_addr, parent))
        return unique

    def _read_file(self, path: str) -> list[tuple[str, str]]:
        stream = sys.stdin if path == "-" else open(path, encoding="utf-8")
        try:
            out: list[tuple[str, str]] = []
            for line_num, raw in enumerate(stream, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.replace(",", " ").split()
                if len(parts) != 2:
                    raise CommandError(
                        f"{path}:{line_num}: expected 'alias parent', got: {raw.rstrip()!r}"
                    )
                out.append((parts[0], parts[1]))
            return out
        finally:
            if stream is not sys.stdin:
                stream.close()

    def _resolve_account(self, parent_addr: str, owner: str | None) -> EmailAccount:
        qs = EmailAccount.objects.filter(email_address__iexact=parent_addr)
        if owner:
            qs = qs.filter(owner__username=owner)
        matches = list(qs)
        if not matches:
            who = f" for owner {owner!r}" if owner else ""
            raise CommandError(f"No account {parent_addr!r}{who} found.")
        if len(matches) > 1:
            raise CommandError(
                f"{parent_addr!r} is owned by several users; pass --owner to choose."
            )
        return matches[0]

    def _attach_one(self, account: EmailAccount, alias_addr: str, dry_run: bool) -> str:
        # Idempotency: an alias already on this account is a skip, not an error.
        if account.aliases.filter(email_address__iexact=alias_addr).exists():
            return "skipped"
        alias = EmailAlias(account=account, email_address=alias_addr)
        try:
            alias.full_clean()
        except ValidationError as exc:
            msgs = "; ".join(m for errs in exc.message_dict.values() for m in errs)
            raise _AliasError(f"{alias_addr} -> {account.email_address}: {msgs}") from exc
        if not dry_run:
            alias.save()
        return "added"


class _AliasError(Exception):
    """Internal: a validation failure that should abort the whole run."""
