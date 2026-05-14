# Promo demo — record a LinkedIn clip

Self-contained animated demo of the Mails Manager App flow. Walks through five scenes on a 24-second loop:

1. Sign in (0–5 s)
2. Two-factor code (5–10 s)
3. Add account (10–14 s)
4. Account status (14–18 s)
5. Unified inbox (18–24 s)

## How to record

1. Open `demo.html` in Chrome or Edge — full-screen recommended (F11).
2. Press `C` to hide the progress bar and recording-hint overlay for a clean capture.
3. Open Windows Game Bar: <kbd>Win</kbd>+<kbd>G</kbd>.
4. In the Game Bar Capture widget, hit Record. Let one full loop play (~24 s), then stop.
5. The clip lands in `Videos/Captures/`. Trim the first/last second in Photos or Clipchamp so the loop seam isn't visible.

## Aspect ratios

- Default (1080×1080) — LinkedIn feed (1:1 looks best in-stream).
- Append `?v=portrait` to the URL for a 9:16 layout — LinkedIn Stories / Reels / TikTok.

## Keyboard

| Key | Action |
| --- | --- |
| `C` | Toggle the progress bar & hint overlay (toggle off before recording) |
| `H` | Toggle just the hint card |

## Why a CSS demo instead of a real screen-cap

CSS animation is deterministic and stable. A real screen-cap of the live app would need a logged-in seeded account with three IMAP mailboxes plus working test inbox data — too brittle for a 24-s loop. This page gives a hand-tuned, on-brand walkthrough with the exact gradients / typography / phone frame used on the landing page.

## This folder is gitignored

`promo/` is in `.gitignore`, so nothing in here ships to the repo. Edit freely.
