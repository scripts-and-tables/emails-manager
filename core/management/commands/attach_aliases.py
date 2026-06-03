"""Attach mail.ru aliases to existing accounts.

Aliases share their parent account's IMAP connection and password, so this
command only links addresses — it never touches credentials. It's idempotent:
re-running skips aliases that are already attached, so it's safe to run again.

Input is one or more `alias  parent` pairs, supplied either inline:

    python manage.py attach_aliases --account riveracazanova@mail.ru \\
        cyril.lukin@mail.ru gennady.lukin11@mail.ru

or as a whitespace/CSV-separated file (use - for stdin), one pair per line —
the first token is the alias, the last is the parent:

    python manage.py attach_aliases --file aliases.tsv --skip-missing

    # aliases.tsv
    cyril.lukin@mail.ru     riveracazanova@mail.ru
    gennady.lukin11@mail.ru riveracazanova@mail.ru

Pass --dry-run to preview without writing. Pass --skip-missing for a best-effort
bulk load: rows whose parent account isn't in the database (or that would
collide with an existing address) are skipped and reported instead of aborting.
Lines containing a bare DELETED marker are ignored.

All existing state is read in a handful of queries up front and new rows are
written with a single bulk_create, so even large files load in one round-trip
rather than several per row.
"""

from __future__ import annotations

import sys

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from core.models import EmailAccount, EmailAlias


class Command(BaseCommand):
    help = "Attach aliases to existing email accounts (idempotent, batched)."

    def add_arguments(self, parser):
        parser.add_argument("aliases", nargs="*", help="Aliases to attach to --account.")
        parser.add_argument("--account", dest="account", help="Parent account for inline aliases.")
        parser.add_argument("--file", dest="file", help="File of 'alias parent' pairs (- for stdin).")
        parser.add_argument("--owner", dest="owner", help="Username to disambiguate shared addresses.")
        parser.add_argument(
            "--skip-missing",
            action="store_true",
            help="Best-effort: skip rows with no parent account / that would collide.",
        )
        parser.add_argument("--dry-run", action="store_true", help="Preview without writing.")

    def handle(self, *args, **opts):
        pairs = self._collect_pairs(opts)
        if not pairs:
            raise CommandError("No alias pairs given. Use --account EMAIL alias... or --file PATH.")

        dry_run = opts["dry_run"]
        skip_missing = opts["skip_missing"]
        owner = opts.get("owner")

        # --- Preload existing state (a few queries, not one-per-row). ---
        acc_qs = EmailAccount.objects.all()
        if owner:
            acc_qs = acc_qs.filter(owner__username=owner)
        accounts = list(acc_qs)

        by_email: dict[str, list[EmailAccount]] = {}
        owner_primaries: dict[int, set[str]] = {}
        for acc in accounts:
            em = acc.email_address.lower()
            by_email.setdefault(em, []).append(acc)
            owner_primaries.setdefault(acc.owner_id, set()).add(em)

        present: set[tuple[int, str]] = set()  # (account_id, lower(alias))
        owner_aliases: dict[int, set[str]] = {}
        for al in EmailAlias.objects.values("account_id", "email_address", "account__owner_id"):
            em = al["email_address"].lower()
            present.add((al["account_id"], em))
            owner_aliases.setdefault(al["account__owner_id"], set()).add(em)

        # --- Classify every pair in memory. ---
        to_create: list[EmailAlias] = []
        added: list[tuple[str, str]] = []
        already_present = 0
        skipped_missing: list[tuple[str, str]] = []
        skipped_invalid: list[tuple[str, str, str]] = []

        for alias_addr, parent_addr in pairs:
            accs = by_email.get(parent_addr.lower())
            if not accs:
                if skip_missing:
                    skipped_missing.append((alias_addr, parent_addr))
                    continue
                raise CommandError(f"No account {parent_addr!r} found (use --skip-missing to skip).")
            if len(accs) > 1:
                raise CommandError(
                    f"{parent_addr!r} is owned by several users; pass --owner to choose."
                )
            acc = accs[0]
            oid = acc.owner_id
            em = alias_addr.lower()

            if (acc.id, em) in present:
                already_present += 1
                continue
            reason = None
            if em in owner_primaries.get(oid, ()):
                reason = "already one of your connected accounts"
            elif em in owner_aliases.get(oid, ()):
                reason = "already attached to one of your accounts"
            if reason is not None:
                if skip_missing:
                    skipped_invalid.append((alias_addr, parent_addr, reason))
                    continue
                raise CommandError(f"{alias_addr} -> {parent_addr}: {reason}")

            to_create.append(EmailAlias(account=acc, email_address=alias_addr))
            present.add((acc.id, em))
            owner_aliases.setdefault(oid, set()).add(em)
            added.append((alias_addr, parent_addr))

        # --- Write (one bulk insert) unless dry-run. ---
        if to_create and not dry_run:
            with transaction.atomic():
                EmailAlias.objects.bulk_create(to_create, batch_size=500)

        # --- Report. ---
        for alias_addr, parent_addr in added:
            self.stdout.write(self.style.SUCCESS(f"  + {alias_addr}  ->  {parent_addr}"))
        for alias_addr, parent_addr in skipped_missing:
            self.stdout.write(self.style.WARNING(f"  ? {alias_addr}  (no account for {parent_addr})"))
        for alias_addr, parent_addr, reason in skipped_invalid:
            self.stdout.write(self.style.WARNING(f"  ! {alias_addr} -> {parent_addr}: {reason}"))

        verb = "Would attach" if dry_run else "Attached"
        self.stdout.write(
            self.style.MIGRATE_HEADING(
                f"\n{verb} {len(added)} alias(es); {already_present} already present; "
                f"{len(skipped_missing)} missing parent; {len(skipped_invalid)} invalid."
            )
        )
        if dry_run:
            self.stdout.write("Dry run - no changes were saved.")

    # --- input parsing -----------------------------------------------------

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
                if any(p.upper() == "DELETED" for p in parts):
                    continue  # source-flagged as deleted
                if len(parts) < 2:
                    raise CommandError(
                        f"{path}:{line_num}: expected 'alias parent', got: {raw.rstrip()!r}"
                    )
                # First token is the alias, last is the parent account.
                out.append((parts[0], parts[-1]))
            return out
        finally:
            if stream is not sys.stdin:
                stream.close()
