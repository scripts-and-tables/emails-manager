# Promo images — first batch

Twelve hand-authored SVG promos, each `1200×1200` (LinkedIn feed square). All share the same brand tokens as `docs/assets/img/hero-light.svg`: blue gradient `#005FF9 → #0099FF`, system fonts, Bootstrap-ish chip styling.

| # | File | Use it for |
|---|---|---|
| 1 | `01-launch-announcement.svg` | "Now live" / launch post |
| 2 | `02-feature-encrypted.svg` | Feature spotlight — Fernet-encrypted credentials |
| 3 | `03-feature-2fa.svg` | Feature spotlight — email OTP 2FA |
| 4 | `04-feature-imap.svg` | Feature spotlight — live IMAP |
| 5 | `05-feature-unified-inbox.svg` | Feature spotlight — one inbox |
| 6 | `06-tech-stack.svg` | "What it's built with" / portfolio post |
| 7 | `07-security-first.svg` | Dark variant — production-shaped security checklist |
| 8 | `08-open-source.svg` | "Read the code" / GitHub-driven post |
| 9 | `09-live-on-railway.svg` | "git push → production" deploy log post |
| 10 | `10-built-end-to-end.svg` | Portfolio framing — auth, IMAP, security, deploy scope |
| 11 | `11-problem-solution.svg` | Problem/solution: 3 mailboxes → one dashboard |
| 12 | `12-hero-square.svg` | Square recut of the landing hero, generic use |
| 13 | `13-built-with-claude.svg` | "Shipped with Claude" — paired-coding angle, terminal transcript |
| 14 | `14-2fa-methods.svg` | 2FA comparison — SMS vs TOTP vs Email-OTP vs Passkeys |
| 15 | `15-why-2fa.svg` | Stat-driven 2FA post — 99% / 81% / 5s |
| 16 | `16-threat-model.svg` | "If your DB leaks tomorrow…" plaintext vs Fernet side-by-side |
| 17 | `17-why-fernet.svg` | Crypto explainer — don't roll your own, what Fernet gives you |
| 18 | `18-railway-vs.svg` | Railway vs Heroku/Vercel/Fly/Render comparison table |
| 19 | `19-git-push-pipeline.svg` | git push → live in 50s, six-step timeline |
| 20 | `20-commit-log.svg` | Real `git log --oneline -10` as portfolio panel |

## Export to PNG for LinkedIn

LinkedIn rejects SVG uploads, so export to PNG before posting:

- **Quickest (Windows):** open the `.svg` in Microsoft Edge, right-click → *Save as…* → pick PNG; or take a screenshot at full size. SVGs are vector — they'll stay crisp at any export size.
- **Figma:** drag the file in, set frame to 1200×1200, *Export → PNG @1x*.
- **CLI (Inkscape):** `inkscape 01-launch-announcement.svg --export-type=png --export-width=1200`
- **CLI (ImageMagick):** `magick convert -density 300 -background none 01-launch-announcement.svg -resize 1200x1200 01-launch-announcement.png`

## Editing notes

- Keep the 1200×1200 viewBox. Don't change the gradient stops — every file uses the same `#005FF9 → #0099FF`.
- Body type is system-stack only — `-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif`. Don't introduce Google Fonts; that breaks GitHub's inline SVG preview.
- Status dot palette: `#005FF9` info · `#198754` ok · `#6f42c1` purple · `#d63384` pink · `#dc3545` danger · `#fd7e14` orange. Stick to these so the set stays coherent.
- Files 7 and 9 are the dark-theme variants. The rest are light theme.
