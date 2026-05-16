# Landscape promo images — opinion-piece batch

Five landscape SVGs at **1200×630** (Open Graph / LinkedIn link card / Twitter card / blog hero — universal social-card format, not the LinkedIn feed square).

Each one pairs with a LinkedIn post angle. Pick one image, paste the matching headline as the post copy lead, write 3–6 lines underneath, drop the link to `https://m-m.up.railway.app`.

## Posts + matching images

### 1. `21-real-engineering.svg`
**Title:** Side projects deserve real engineering.
**Hook:** No users yet — but I built it like there are a thousand. Here's the production-shaped checklist I followed even though nobody's logging in: Email-OTP 2FA, Fernet at rest, CSP nonces, HSTS, 30 tests, AuthEvent audit log, live on Railway. The point isn't the users you have — it's the muscle you build for the next thing.

### 2. `22-tests-on-side-project.svg`
**Title:** 30 tests for a side project sounds insane. Here's what they actually bought me.
**Hook:** Confidence to refactor at midnight. Confidence to upgrade Django without praying. A green CI badge that means something. Tests on a side project aren't about catching bugs that don't exist yet — they're a forcing function for designs you don't regret. ~4 seconds to run the whole suite. Cheap insurance.

### 3. `23-pairing-with-claude.svg`
**Title:** What pairing with Claude on a real Django app actually looks like.
**Hook:** Not vibes. Real diffs, security review, 30 tests, a deploy log. Claude wrote the django-otp wiring, then I asked it to OWASP-review its own work. It added CSP nonces and tightened cookies before I shipped. 12 commits. 0 regressions. The new pair-programming isn't AI doing your job — it's AI shortening the loop between "what if I tried…" and "shipped."

### 4. `24-plaintext-when-not-if.svg`
**Title:** Plaintext passwords in your DB are a "when not if" problem.
**Hook:** If you're storing third-party credentials — IMAP, API keys, anything — and they're not encrypted, you have a security incident waiting. The fix is two lines with Fernet. The key lives in `os.environ`, not the database. After: a DB dump leaks email addresses (low value) and opaque ciphertext blobs (useless). Design for the bad day.

### 5. `25-underrated-stack.svg`
**Title:** The most underrated stack of 2026 is also the most boring.
**Hook:** Django + Postgres + Railway. No edge functions. No yaml priesthood. No framework-of-the-month. `git push` ships in 50 seconds. Postgres is a single click. Django is still the best web framework for someone who wants to build a thing instead of build infrastructure to build a thing. Boring tech compounds.

## Format notes

- **1200×630** is the Open Graph / Twitter Card / LinkedIn link-card standard. Works as a blog hero, an OG meta image, and as a LinkedIn post image when shared via URL.
- For LinkedIn *feed* posts (image upload, not link share), the 1:1 squares in the parent folder still look better in-stream.
- Same brand tokens as the rest of the set — gradient `#005FF9 → #0099FF`, system fonts.

## Export to PNG

Same as the parent folder: open in Edge → Save as PNG. Or `inkscape file.svg --export-type=png --export-width=1200`.
