# Mails Manager App

A Django web app for connecting and managing multiple IMAP email accounts from a single dashboard. Passwords are encrypted at rest with Fernet, authentication uses email-based OTP, and 2FA is on by default.

> Showcase / portfolio project. Built solo as an exercise in shipping a small but production-shaped Django application end-to-end — auth, transactional email, encrypted credential storage, security headers, and a Postgres-or-SQLite deploy story.

## Live demo & project site

- **Live app**: _coming soon_ — fill in the deployed URL here
- **Project site**: <https://scripts-and-tables.github.io/emails-manager/> — overview, features, screenshots, public Guide, [self-hosting](https://scripts-and-tables.github.io/emails-manager/self-hosting.html), [security](https://scripts-and-tables.github.io/emails-manager/security.html)
- **Source**: this repo

## Features

- **Email-verified signup** — new accounts confirm via a signed link before activation.
- **Login by email OTP** — one-time code delivered via Resend; 5-attempt lock and TTL on each code.
- **2FA toggle** — on by default per user, controllable from the profile page.
- **Password reset** — standard Django token flow over email.
- **Multi-account IMAP linking** — add one account at a time or bulk-add several at once.
- **Per-account actions** — test connection, enable/disable, rotate password, edit, delete.
- **Inbox view** — list, read, mark unread, delete messages directly against the live IMAP server (`imap-tools`).
- **Encrypted credential storage** — IMAP passwords stored as Fernet ciphertext via a separate `FIELD_ENCRYPTION_KEY`, never in plaintext.
- **Production-shaped settings** — HSTS, secure cookies, CSP-adjacent headers, WhiteNoise static serving, Postgres via `DATABASE_URL`, SQLite fallback locally.

## Tech stack

- **Backend**: Django 5.1+, Python
- **IMAP client**: `imap-tools`
- **Crypto**: `cryptography` (Fernet) for at-rest password encryption
- **Outbound email**: [Resend](https://resend.com) API
- **2FA**: `django-otp` + `qrcode`
- **Database**: PostgreSQL in production (via `dj-database-url` + `psycopg`), SQLite locally
- **Static files**: WhiteNoise
- **Config**: `python-decouple`
- **WSGI**: Gunicorn

## Screenshots

A walk-through gallery lives on the [project site](https://scripts-and-tables.github.io/emails-manager/screenshots.html). PNG sources sit under [`docs/assets/screenshots/`](docs/assets/screenshots/README.md).

## Local setup

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
- `RESEND_API_KEY` — from [resend.com/api-keys](https://resend.com/api-keys), if you want signup/login emails to actually send.
- `RESEND_FROM_EMAIL` — a sender on a domain you've verified in Resend.

Then:

```bash
python manage.py migrate
python manage.py runserver
```

App runs at <http://127.0.0.1:8000>.

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

## Project layout

```
emailsmanager/   # Django project (settings, root urls, wsgi)
core/            # Single app — models, views, urls, templates, encryption, middleware
requirements.txt
.env.example
manage.py
```

## License

MIT — see [LICENSE](LICENSE).
