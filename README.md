<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/img/hero-dark.svg">
  <img src="docs/assets/img/hero-light.svg" alt="Mails Manager App — One dashboard for every mailbox." width="100%">
</picture>

<br>

[![CI](https://github.com/scripts-and-tables/emails-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/scripts-and-tables/emails-manager/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/scripts-and-tables/emails-manager?color=blue)](LICENSE)
[![Python 3.13](https://img.shields.io/badge/python-3.13-3776ab?logo=python&logoColor=white)](https://www.python.org/)
[![Django 5.1+](https://img.shields.io/badge/django-5.1%2B-092e20?logo=django&logoColor=white)](https://www.djangoproject.com/)
[![Code style: Ruff](https://img.shields.io/badge/code%20style-ruff-d7ff64?logo=ruff&logoColor=000)](https://github.com/astral-sh/ruff)

**[Project site](https://scripts-and-tables.github.io/emails-manager/)** &nbsp;·&nbsp;
**[Documentation](https://scripts-and-tables.github.io/emails-manager/guide.html)** &nbsp;·&nbsp;
**[Screenshots](https://scripts-and-tables.github.io/emails-manager/screenshots.html)** &nbsp;·&nbsp;
**[Live app](https://m-m.up.railway.app)**

</div>

---

## What it is

A Django web app for connecting and managing multiple IMAP email accounts from a single dashboard. Portal passwords are hashed with Django's salted PBKDF2-SHA256, IMAP passwords are encrypted at rest with Fernet, authentication uses email-based OTP, and 2FA is on by default.

> **Showcase / portfolio project.** Built solo as an exercise in shipping a small but production-shaped Django application end-to-end — auth, transactional email, encrypted credential storage, security headers, and a Postgres-or-SQLite deploy story.

## Highlights

- **Email-verified signup** — new accounts confirm via a signed link before activation.
- **Login by email OTP** — one-time code delivered via Resend; 5-attempt lock and TTL on each code.
- **2FA on by default** — toggleable per user from the profile page; password reset over a standard Django token flow.
- **Multi-account IMAP** — add accounts one at a time or bulk-import via a small CSV.
- **Per-account actions** — live IMAP connection test, enable / disable, rotate password, edit, delete.
- **Live inbox** — list, read, mark unread, delete messages directly against the IMAP server via [`imap-tools`](https://github.com/ikvk/imap_tools).
- **Encrypted credential storage** — IMAP passwords stored as Fernet ciphertext via a separate `FIELD_ENCRYPTION_KEY`, never in plaintext or in logs.
- **Production-shaped settings** — HSTS preloaded, secure / HttpOnly / SameSite cookies, hardened response headers, WhiteNoise statics, Postgres via `DATABASE_URL` with SQLite fallback for local dev.

→ More depth on the [project site](https://scripts-and-tables.github.io/emails-manager/features.html).

## Screenshots

A walk-through gallery lives on the [project site](https://scripts-and-tables.github.io/emails-manager/screenshots.html). Source PNGs sit under [`docs/assets/screenshots/`](docs/assets/screenshots/README.md).

## Tech stack

| Layer | Pick |
| --- | --- |
| **Backend** | Django 5.1+, Python 3.13 |
| **IMAP client** | [`imap-tools`](https://github.com/ikvk/imap_tools) |
| **Crypto** | [`cryptography`](https://cryptography.io/) (Fernet) for at-rest password encryption |
| **Outbound email** | [Resend](https://resend.com) API |
| **2FA** | `django-otp` + `qrcode` |
| **Database** | PostgreSQL in production (`dj-database-url` + `psycopg`), SQLite locally |
| **Static files** | [WhiteNoise](http://whitenoise.evans.io/) |
| **Config** | `python-decouple` |
| **WSGI** | Gunicorn |
| **Lint / format** | [Ruff](https://github.com/astral-sh/ruff) |

## Quick start

```bash
git clone https://github.com/scripts-and-tables/emails-manager.git
cd emails-manager

python -m venv .venv
.venv\Scripts\activate            # Windows
# source .venv/bin/activate       # macOS / Linux

pip install -r requirements.txt

copy .env.example .env            # Windows
# cp .env.example .env            # macOS / Linux
```

Edit `.env` and fill in at least:

- `SECRET_KEY` — any long random string.
- `FIELD_ENCRYPTION_KEY` — generate with:
  ```bash
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  ```
- `RESEND_API_KEY` — from [resend.com/api-keys](https://resend.com/api-keys), if you want signup / login emails to actually send.
- `RESEND_FROM_EMAIL` — a sender on a domain you've verified in Resend.

Then:

```bash
python manage.py migrate
python manage.py runserver
```

App runs at <http://127.0.0.1:8000>.

→ Full self-hosting guide on the [project site](https://scripts-and-tables.github.io/emails-manager/self-hosting.html).

## Environment variables

| Variable | Required | Notes |
| --- | --- | --- |
| `SECRET_KEY` | yes | Django secret. Long random string. |
| `DEBUG` | no | Defaults to `False`. Set `True` locally. |
| `ALLOWED_HOSTS` | no | Comma-separated. Defaults to `localhost,127.0.0.1`. |
| `CSRF_TRUSTED_ORIGINS` | no | Comma-separated origins for CSRF. |
| `FIELD_ENCRYPTION_KEY` | yes | Fernet key for IMAP password encryption. Rotating invalidates all stored passwords. |
| `RESEND_API_KEY` | yes (for email) | Without this, OTP and verification emails won't send. |
| `RESEND_FROM_EMAIL` | yes (for email) | Must use a verified domain in Resend. RFC 5322 format. |
| `DATABASE_URL` | no | Postgres URL. Falls back to SQLite if unset. |

## Documentation

Full documentation lives on the [project site](https://scripts-and-tables.github.io/emails-manager/):

| Page | What's there |
| --- | --- |
| [Overview](https://scripts-and-tables.github.io/emails-manager/) | What it is, who it's for, tech stack at a glance |
| [Features](https://scripts-and-tables.github.io/emails-manager/features.html) | Ten feature deep-dives with implementation notes |
| [Screenshots](https://scripts-and-tables.github.io/emails-manager/screenshots.html) | Walk-through gallery of the app |
| [Guide](https://scripts-and-tables.github.io/emails-manager/guide.html) | Setup, the Mail.ru aliases trick, 2FA, inbox |
| [Self-hosting](https://scripts-and-tables.github.io/emails-manager/self-hosting.html) | Env vars, deploy notes, CI overview |
| [Security](https://scripts-and-tables.github.io/emails-manager/security.html) | Credentials, hardening, threat model, vuln reporting |

## Project layout

```
emailsmanager/   # Django project (settings, root urls, wsgi)
core/            # Single app — models, views, urls, templates, encryption, middleware
docs/            # GitHub Pages source — public project site
requirements.txt
.env.example
manage.py
```

## Contributing

This is a personal portfolio project, but PRs and issues are welcome. CI runs Ruff + Django tests on every PR; please keep both green.

## License

[MIT](LICENSE) — do what you want with it; no warranty of any kind.
