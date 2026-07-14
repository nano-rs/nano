# Handoff: Sign-in screen (mock 8a in `nano Desktop.dc.html`)

## Overview
The sign-in window for the nano desktop app (Tauri, macOS-first). SSO-first auth with a Touch ID fast path for trusted devices. This is a **high-fidelity HTML design reference** — recreate it in the app's real frontend stack; do not ship the HTML.

Note: the bundled `nano Desktop.dc.html` references the logo at `uploads/nano_white-228054b8.png` in the original project; in this bundle the logo files are at `assets/nano_white.png` (for dark backgrounds) and `assets/nano_pink.png` (dark wordmark + pink dot, for light backgrounds).

## Window
- Frameless, centered, fixed 1040×660, radius 16px, not resizable. Desktop behind shows through.
- Surface: `rgba(26,29,36,0.92)` + `backdrop-filter: blur(44px) saturate(1.5)` (Tauri: transparent window + vibrancy).
- Border `1px solid rgba(255,255,255,0.10)`; shadow `0 40px 100px rgba(0,0,0,0.65)`.
- Two columns: brand panel 480px fixed, sign-in panel fills the rest.
- Font: system stack (`-apple-system, "SF Pro Text"...`); mono is `ui-monospace, "SF Mono", Menlo`.

## Left — brand panel (480px)
- Background: `linear-gradient(160deg, #0A0D12 0%, #0D1421 55%, #0A1119 100%)`, overflow hidden.
- Accent glow: 560px circle, bottom-left offset (left −140px, bottom −180px), `radial-gradient(closest-side, ACCENT@16%, transparent)`.
- Traffic lights top-left (12px circles, 8px gap, 16px padding): `#FF5F57 #FEBC2E #28C840`. Window is draggable by this panel.
- Vertically centered content, 52px side padding:
  - **Logo**: `assets/nano_white.png` at 168px wide, `drop-shadow(0 0 26px ACCENT@30%)`.
  - Headline, 26px below logo: "The SIEM,\non your desk." — 30px/700, `#F2F4F7`, letter-spacing −0.02em, line-height 1.2.
  - Body, 14px below: "Search 7 days of hot data offline. Let your coding agent work the queue. Everything else stays on the cluster." — 13.5px, `rgba(235,240,246,0.55)`, line-height 1.65, max-width 320px.
- Bottom strip (52px side / 26px bottom padding):
  - Live sparkline: 30 bars, 44px tall, 3px gap, accent color at 55% opacity, radius 1.5px top. Animate subtly (it represents live local ingest).
  - Caption row below (10px gap): mono 10.5px — left "local index · 2.1 GB · ready" `rgba(235,240,246,0.38)`, right "● live" in accent.

## Right — sign-in panel
Vertically centered, 72px side padding.
- Title: "Sign in to nano" — 21px/700 `#F2F4F7`.
- Subtitle (6px below, 12.5px): "deployment: `acme.nano.rs` · change" — deployment host in mono `rgba(235,240,246,0.7)`, "change" is an accent-colored action.
- 28px below, SSO buttons (10px gap, full width, radius 9px, 12px vertical padding, 13.5px/600, centered):
  - "Continue with Okta SSO" — filled `#F2F4F7`, ink `#14171C`.
  - "Continue with Google" — ghost: `rgba(255,255,255,0.06)` bg, `1px rgba(255,255,255,0.12)` border, text `rgba(235,240,246,0.85)`.
- Divider (24px margins): hairlines `rgba(255,255,255,0.08)` flanking "or" (11px, `rgba(235,240,246,0.35)`).
- Email input: `rgba(0,0,0,0.28)` bg, `1px rgba(255,255,255,0.12)` border, radius 9px, 12px/14px padding, placeholder "work email…" `rgba(235,240,246,0.35)` 13px.
- Continue button (10px below): accent-soft — bg `ACCENT@16%`, border `ACCENT@32%`, text accent, 13px/600, radius 9px, 11px vertical padding.
- **Touch ID card** (34px below): radius 12px, `rgba(255,255,255,0.025)` bg, `1px rgba(255,255,255,0.09)` border, 14px/16px padding, row layout 14px gap:
  - Glyph: 40px circle, 1.5px solid `ACCENT@55%` border, containing a 24px circle with 1.5px dashed `ACCENT@75%` border. (Placeholder — use the SF Symbol `touchid` on macOS.)
  - Text: "This device is trusted" 13px/600 `#F2F4F7`; below "jk@acme.co · unlock with Touch ID" 11.5px `rgba(235,240,246,0.5)`.
  - Right-aligned "Unlock" action — 12px/600 accent.
- Footnote (22px below, 11px, `rgba(235,240,246,0.35)`, line-height 1.6): "Signing in registers this device's MCP server with your org policy. Local index is encrypted at rest with the device key."

## Tokens
- ACCENT default `#67E3AC` (`ACCENT@N%` = `color-mix(in srgb, ACCENT N%, transparent)`). Alternates: `#5EE7F0 #A78BFA #FFB454 #FF5CA8`.
- Text: `#F2F4F7` primary; `rgba(235,240,246,0.55–0.85)` secondary; `0.35–0.5` tertiary.
- Brand pink (logo dot): `#EC2A80`-ish — sample from the PNG; only appears in the logo itself.

## Behavior
- SSO buttons open the system browser → deep-link back (`nano://auth/callback`).
- Touch ID card appears only when device keychain holds a valid refresh token; "Unlock" triggers LocalAuthentication; success skips straight into the app.
- Deployment "change" swaps the subtitle into an inline host input.
- Buttons/inputs get standard hover (bg +3% white) and focus rings in `ACCENT@40%`.
- Light mode exists app-wide (see main README, mock 6a) — for it, use `assets/nano_pink.png` on a `rgba(248,250,252,0.9)` surface with accent `#0E9464`.
