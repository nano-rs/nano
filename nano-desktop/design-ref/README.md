# Handoff: nano Desktop — native SIEM app (macOS-first, Tauri)

## Overview
Design mocks for a native desktop version of the nano SIEM frontend (macOS-first; Linux/Windows to follow), targeted at a Tauri shell. The desktop app's differentiators over the web app:

1. **Deep AI-agent integration** — the app ships an MCP server (`mcp://nano.local`) so coding agents (Claude Code, Codex, Cursor) can drive investigations; plus an in-app agent side panel and embedded terminal with an MCP call log.
2. **Workspace tabs** — browser-style tabs in the titlebar where each tab is a case/investigation with inner views (Search / Timeline / Assets / Agent notes).
3. **Local data cache** — a 7-day hot index on disk; queries and IOC lookups run offline.
4. **OS-level surfaces** — global-hotkey Quick Search (⌥Space), always-on-top dashboard widgets, menu-bar tray monitor, native notifications, and a system-wide right-click "Search in nano" service for IOCs.

## About the Design Files
The files in this bundle are **design references created in HTML** (`nano Desktop.dc.html` + its `support.js` runtime — open the .dc.html directly in a browser to view). They are prototypes showing intended look and behavior, **not production code to copy directly**. The task is to **recreate these designs in the target codebase's environment** — for a Tauri app that likely means React (or the team's chosen frontend) inside a Tauri window with `titleBarStyle: overlay`/transparent titlebar, plus Tauri APIs for tray, notifications, global shortcuts, and always-on-top windows. If no desktop codebase exists yet, Tauri 2.x + React + Tailwind is the recommended stack.

## Fidelity
**High-fidelity.** Colors, typography, spacing, and copy are intentional; recreate pixel-perfectly using the codebase's component patterns. (Chart data, log lines, and event rows are illustrative sample data.)

## Design language ("net-new desktop-native", distinct from the web app's shadcn kit)
- macOS Tahoe-style **vibrancy/glass**: translucent window surfaces over the desktop wallpaper, `backdrop-filter: blur(44px) saturate(1.5)`.
- **System font**: `-apple-system, "SF Pro Text", "Helvetica Neue", sans-serif`; mono is `ui-monospace, "SF Mono", Menlo, monospace`.
- Accent: **mint `#67E3AC`** (dark mode). The web app's cyan `#5EE7F0` is deliberately NOT used (it exists only as an alternate accent option).
- Roomier radii than the web app: windows 14px, cards/panels 10px, controls 7–9px, chips/pills 20px.

## Design Tokens (dark mode)
Surfaces
- Desktop wallpaper: `linear-gradient(135deg, #0D1118 0%, #131B27 38%, #0F1822 68%, #0A0D12 100%)` + soft radial mint glow top-right `rgba(103,227,172,0.10)`
- Menu bar: `rgba(16,18,24,0.55)` + blur(30px)
- App window: `rgba(26,29,36,0.90)` + blur(44px) saturate(1.5); border `1px rgba(255,255,255,0.10)`; shadow `0 36px 90px rgba(0,0,0,0.6)`; radius 14px
- Sidebar: `rgba(255,255,255,0.028)`; right panels `rgba(255,255,255,0.022)`
- Inset content (tables, charts): `rgba(0,0,0,0.18)`; inputs `rgba(0,0,0,0.28)`
- Terminal drawer: `rgba(0,0,0,0.45)`
- Floating widgets/popovers: `rgba(24,27,33,0.88)`–`rgba(36,39,46,0.96)` + blur(40–50px)

Text
- Primary `#F2F4F7`; secondary `rgba(235,240,246,0.6–0.78)`; tertiary `rgba(235,240,246,0.4–0.55)`; faint `rgba(235,240,246,0.28–0.38)`

Lines
- Hairline `rgba(255,255,255,0.06–0.08)`; stronger `rgba(255,255,255,0.10–0.14)`

Accent & semantic
- Accent (tweakable prop): default `#67E3AC`; options `#5EE7F0`, `#A78BFA`, `#FFB454`, `#FF5CA8`
- Accent soft fills: `color-mix(in srgb, ACCENT 10–16%, transparent)`; borders 22–32%
- Danger `#FF7A76` (soft `rgba(255,122,118,0.14–0.22)`), warn `#FFB454` (`rgba(255,180,84,0.16)`), info `#7FB8FF`, purple (hash/JSON strings) `#E8B4F8`
- Traffic lights: `#FF5F57` / `#FEBC2E` / `#28C840`

Type scale
- Menu bar 12.5px · sidebar 13px · table rows 12.5px (mono for data) · column headers 10.5px/700/0.06em tracking · section labels 10.5–11px/700/0.06–0.08em · panel titles 13–15px/600–700 · KPI numerals 26px/700 mono · terminal 12px mono

Light mode (6a)
- Wallpaper `linear-gradient(135deg, #E7EDF4, #D4DEE9 38%, #DEE6EE 68%, #C9D4E0)`; window `rgba(248,250,252,0.90)`; sidebar `rgba(255,255,255,0.4)`; text `#1A2028` / `rgba(26,32,40,0.55–0.8)`; borders `rgba(20,30,40,0.07–0.14)`
- Accent deepens to `#0E9464` (ink on accent = white); danger `#C93F38`; warn `#B26A00`
- Terminal drawer stays dark (`#14171C`) in light mode. Appearance should follow System Settings.

## Screens / Views
All app-window mocks share: 30px macOS menu bar; 1540×930 window; 44px titlebar containing traffic lights + workspace tabs + right-side status; 200px sidebar (EXPLORE: Search, Dashboards, Detections+badge, Cases, Sources; AGENT: Sessions with pulsing dot, MCP tools); optional bottom terminal drawer with tabs Terminal / MCP log / Query history and a right-aligned `claude-code connected · mcp://nano.local` status.

### 1a — Main window (Search)
- **Tab models** (tweakable): `workspace` (default — tabs are cases with severity chips, inner tab row Search/Timeline/Assets/Agent notes), `browser` (tabs are queries, mono labels), `split` (two side-by-side query panes A/B with histograms for comparison).
- Query bar: mono NPL text, accent-colored field names, ghost italic AI suggestion (`| rare user, src_ip — suggested ⇥`); time-range pill; accent "✳ Ask agent ⌘K" button.
- 120px histogram (accent bars, 28 buckets, spike at 4/15); date axis beneath.
- Results table, 6 mono columns: TIME/SOURCE/EVENT/USER/SRC IP/OUTCOME; event names accent, suspicious IPs warn-orange, outcomes color-coded by risk.
- Right: 330px **Agent panel** — pulsing status dot, `claude-code · MCP` badge; user bubble (accent-tinted, radius 11/11/3/11), tool-call card (mono, `⏺ nano.search — 301 events`…), agent reply bubble, two action buttons (accent-filled "Open case draft" / ghost "Show queries"); footer input "Ask, or ⇧⏎ to run autonomously…".
- Terminal drawer: CLI prompt lines (`➜ claude "why did ConsoleLogin spike…"`) + tool-call trace + pulsing block cursor.
- Titlebar right: pill `● local cache · 2.1 GB · offline-ready` (accent, mono) + avatar.
- Sidebar footer card: "Local index / live" with 72% progress bar, "7d hot · queries run offline".

### 1b — Dashboards + always-on-top widgets
- Dashboard window (1180×920): titlebar with "SOC Overview / auto-refresh 10s" + ghost button "＋ Pin panel to desktop"; grid = 4 KPI cards (Open detections 12/+3, MTTA 4m12s/−38%, Events 24h 7.3B, Agent triaged 31/9 auto-closed), ingest EPS bar chart (span 2), 7×4 MITRE heat grid (accent color-mix scale), latest detections list (severity chips), top talkers with mini bars. MCP-log drawer at bottom.
- Three floating **always-on-top widgets** on the desktop (330px wide, radius 13px): Detections list with 📌 pin, Ingest health sparkline `84.2k eps`, Agent status ("triaging CASE-1042", live tool-call lines).

### 1c — Quick Search (⌥Space)
- Dimmed desktop (`rgba(0,0,0,0.35)` scrim); centered 720px palette (radius 16px, blur 50px).
- Input row: accent ⌕, mono query `203.0.113.42`, pulsing caret, badge "local cache · offline OK".
- Sections: IOC MATCH (accent-tinted row: MALICIOUS chip, IP, "C2 · 14 events across 3 hosts (7d)", `↩ open`), agent action (`⌘↩`), "New investigation tab" (`⌥↩`), RECENT queries. Footer keycap hints.

### 1d — Menu bar tray + notification
- Tray pill in menu bar: nano glyph + live severity counts (red 3 / amber 7, mono).
- Dropdown (380px): "nano · live detections / streaming"; 4 alert rows (severity chip, title, mono source+case meta, age); footer: accent "Open nano", "Triage all with agent", right "Mute 1h".
- Native notification banner (380px): 38px app icon tile (mono "n" on dark), "Critical detection / now", body "Lateral movement: svc-deploy → prod-db-04 via SSH. Agent has started triage.", buttons View (accent) / Snooze (ghost).

### 1e — Right-click IOC anywhere (system service)
- Third-party window (Notes) with an IP text selection highlighted (accent 30% background).
- Native context menu: Copy / Look Up / separator / **accent-filled "n Search in nano ▸"** / Share…; submenu: Quick search (last 24h) [highlighted], Full investigation tab, Ask agent about this IOC, Add to watchlist.
- **Verdict peek popover** (380px, accent-tinted border): SUSPICIOUS chip + IP + "peek · 80ms local"; body "Tor exit node · 27 events in your data (7d)…"; buttons "Open in nano" / "✳ Ask agent".

### 2a — Detections queue
- Filter row: segmented Open·12 / Agent-closed·9 / All; filter pills (crit+high ✕, source, entity); right accent button "✳ Triage all with agent".
- Table: SEV / RULE / ENTITY (mono, warn) / EVENTS / **AGENT VERDICT** (Escalate·0.91 red, Investigating grey, "Benign · signed LOB app" green, agent-closed) / ASSIGNEE ("agent → J. Kim") / AGE. Selected row accent-tinted.
- Right rail (370px): CRIT chip + DET id, title, MITRE technique chips (mono, T1021.004 SSH…), AGENT SUMMARY paragraph with confidence "0.91 — escalate" + tool-call card, TIMELINE (dot-colored events), footer buttons "Open as case tab" / "✳ Continue with agent".

### 2b — Expanded search result
- One table row expanded inline (accent-tinted header row, ▾ chevron). Split body:
  - Left (55%): RAW EVENT — syntax-colored JSON (keys `#7FB8FF`, strings `#E8B4F8`, suspicious values warn/danger, booleans blue); nested keys flattened as dotted paths (`userIdentity.type`).
  - Right (45%): EXTRACTED FIELDS — hoverable rows (key mono grey, value colored, right hint e.g. "27 events · Tor exit", "rare · 1 in 30d"); action chips: **Pivot: src_ip** (accent), Add to case, ✳ Explain this event, Draft detection rule.
- Footer: "27 events · 185.220.101.4" + "⌘↑/⌘↓ walk events with inspector open".

### 3a — Bulk IOC search
- Tab label: "Bulk lookup · vendor-report.pdf" + accent chip "47 IOCs".
- Left rail (350px): "PASTED LIST · auto-parsed", "47 unique · 3 dupes dropped · from clipboard", type-count pills (ip·28 warn / domain·11 blue / sha256·8 purple); the raw list with matched IOCs highlighted (accent 28% bg) + inline hit counts; footer tip about highlight→right-click flow.
- Main: summary "**5 of 47** seen in your data" + "last 30d · 46 hits total · 610ms across 4 sources"; buttons Watchlist all 47 / Export matches / accent "✳ Investigate the 5 matches".
- Matches table: IOC / TYPE / HITS (color = severity) / WHERE / FIRST-LAST SEEN / ACTIVITY 30d sparkline (14 mini bars). Footer note: no-hit IOCs become watchlist candidates that alert on first sighting.

### 4a — MCP tools
- Header: "9 tools exposed · 1,204 calls this week · 0 denied"; copyable install snippet `claude mcp add nano -- nano-desktop mcp serve`.
- Table: TOOL (mono accent) / DESCRIPTION / SCOPE (mono: `read:*` blue, `write:*` amber, `act:response` red) / POLICY (Auto-allow green → Ask each time amber → "Always confirm · 2-person" red for `nano.isolate_host`) / CALLS 7D.
- Tools: nano.search, nano.lookup, nano.timeline, nano.enrich_ip, nano.triage, nano.case, nano.watchlist, nano.rule_draft, nano.isolate_host.
- Sidebar footer: Connected clients (claude-code ●, codex ●, cursor ○).
- Right rail (380px): selected tool (`nano.search`) description, PARAMETERS schema (name blue / type purple / description), RECENT CALLS (client-colored, query preview), buttons Edit policy / Test in terminal.

### 5a — Cases
- Filter row: Open·7 / Mine·3 / Agent-drafted·2 / Closed 30d; "sort: SLA risk"; accent "＋ New case".
- Table: CASE id (mono) / SEV / TITLE / STATUS (Containment red, Investigating amber, "Draft · agent" green) / ASSIGNEE ("J. Kim + agent", "agent → unassigned") / SLA (mono; at-risk red) / UPDATED.
- Right rail: CASE-1042 — "opened 02:31 by agent", title, entity chips (warn-tinted mono), LINKED block (2 detections, 3 saved searches · 41 pinned events, 1 agent session · 12 tool calls), ACTIVITY feed with color-coded actors (agent = accent, humans = blue) and an approval entry ("attached 41 pinned events · approved by JK"), buttons "Open as tab" / "✳ Draft report".
- Terminal drawer: `nano.case` MCP writes with approval trail.

### 6a — Light appearance
Identical layout to 1a with the light token set above. Key rules: terminal stays dark; tabs/inputs become white cards with subtle shadows; accent fills use white ink.

## Interactions & Behavior
- Workspace tabs: click to switch, ⌘T new tab; each tab persists its case context (query, pinned events, agent session). Inner tabs: Search / Timeline / Assets / Agent notes.
- Query bar: AI suggestion ghost text accepted with ⇥; ⌘K focuses agent ask.
- Agent: chat panel streams tool calls as collapsible cards; ⇧⏎ = autonomous run; every `write:*` MCP call respects the per-tool policy (auto-allow / ask each time / 2-person confirm) — approvals surface as native dialogs and are logged in case activity.
- Terminal drawer: real shell; `nano` CLI + MCP log tab mirror all agent traffic live. Toggleable (tweak/menu).
- Quick Search: ⌥Space global shortcut; ↑↓/↩/⌘↩/⌥↩ per footer hints; must work offline via local cache.
- Right-click service: registered as macOS Services entry (Linux: context-menu extension; Windows: shell extension); selection is parsed for IOC type; peek popover returns in <100ms from local index.
- Widgets: spawned from dashboard panels ("Pin panel to desktop"); frameless always-on-top Tauri windows; pin icon unpins.
- Tray: live severity counts; dropdown on click; "Mute 1h" suppresses notifications.
- Notifications: native (macOS UNUserNotification / Tauri notification API) with View/Snooze actions.
- Hovers: table rows `rgba(255,255,255,0.03)` (light: `rgba(20,30,40,0.03)`); field rows in inspector `rgba(255,255,255,0.04)`.
- Pulse animation (status dots, cursors): opacity 1→0.35→1, 2s infinite (cursors 1.2s).

## State Management
- Per-tab: query, time range, view mode, selected row, agent session id, pinned events.
- Global: theme (system-follow), accent choice, terminal-drawer visibility, local-cache sync status, tray alert feed (websocket/stream), MCP server state + per-tool policies, connected clients.
- Offline: queries route to local index when disconnected; sync badge reflects state (`▲ synced`).

## Assets
No image assets. Glyphs are unicode text placeholders (⌕ ▦ ◉ ▤ ⇄ ✳ ⌘ ⏺ ➜ 📌 ) — replace with the product icon set (e.g. SF Symbols on macOS / Lucide cross-platform). The "n" app-icon tiles are placeholders for the real nano app icon. The Apple  glyph in menu bars is environmental (OS chrome), not an asset to ship.

## Files
- `nano Desktop.dc.html` — all 10 mocks on one pannable canvas (badges 1a–6a; newest turns at top). Tweakable props: `tabModel` (browser/split/workspace, default workspace), `showTerminal` (bool), `accent` (5 options).
- `support.js` — runtime required to open the .dc.html in a browser; not part of the design.
