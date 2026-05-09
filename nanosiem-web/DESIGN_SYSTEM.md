# nano Design System - Color & Typography Guide

> Source: Figma "Foundations / Colors & Typography" (Feb 2026)
> This file is the single source of truth for frontend color and typography tokens.
> When building or modifying UI components, use these values.

## Typography

### Font Families

| Role | Family | Replaces |
|---|---|---|
| Sans (UI text) | **Geist** | Inter |
| Mono (code, data) | **Geist Mono** | Roboto Mono |

### Heading (Desktop)

Large display text for page titles and section headers. Line height is a `1.2` multiplier.

**H1 — 56px, letter-spacing: -1px**
| Token | Weight | CSS `font-weight` |
|---|---|---|
| `heading/h1/bold` | Bold | 700 |
| `heading/h1/semibold` | SemiBold | 600 |
| `heading/h1/medium` | Medium | 500 |
| `heading/h1/regular` | Regular | 400 |

**H2 — 40px, letter-spacing: 0**
| Token | Weight | CSS `font-weight` |
|---|---|---|
| `heading/h2/bold` | Bold | 700 |
| `heading/h2/semibold` | SemiBold | 600 |
| `heading/h2/medium` | Medium | 500 |
| `heading/h2/regular` | Regular | 400 |

**H3 — 32px, letter-spacing: 0**
| Token | Weight | CSS `font-weight` |
|---|---|---|
| `heading/h3/bold` | Bold | 700 |
| `heading/h3/semibold` | SemiBold | 600 |
| `heading/h3/medium` | Medium | 500 |
| `heading/h3/regular` | Regular | 400 |

### Title

Smaller headings for cards, dialogs, and sidebar sections. Line height: `1.2` multiplier.

**Lg — 18px, letter-spacing: 0**
| Token | Weight | CSS `font-weight` |
|---|---|---|
| `title/lg/bold` | Bold | 700 |
| `title/lg/semibold` | SemiBold | 600 |
| `title/lg/medium` | Medium | 500 |
| `title/lg/regular` | Regular | 400 |

### Body

Primary readable text. Line height: `1.6` multiplier (except xl which uses fixed 30px).

**Xl — 20px, line-height: 30px, letter-spacing: -0.2px**
| Token | Weight | CSS `font-weight` |
|---|---|---|
| `body/xl/medium` | Medium | 500 |

**Lg — 18px, line-height: 28px, letter-spacing: 0**
| Token | Weight | CSS `font-weight` |
|---|---|---|
| `body/lg/medium` | Medium | 500 |

**Md — 16px, line-height: 1.6 (25.6px), letter-spacing: 0**
| Token | Weight | CSS `font-weight` |
|---|---|---|
| `body/md/bold` | Bold | 700 |
| `body/md/semibold` | SemiBold | 600 |
| `body/md/medium` | Medium | 500 |
| `body/md/regular` | Regular | 400 |

**Sm — 14px, line-height: 1.6 (22.4px), letter-spacing: 0**
| Token | Weight | CSS `font-weight` |
|---|---|---|
| `body/sm/bold` | Bold | 700 |
| `body/sm/semibold` | SemiBold | 600 |
| `body/sm/medium` | Medium | 500 |
| `body/sm/regular` | Regular | 400 |

### Mono-Uppercase

Geist Mono in uppercase — for labels, status badges, field headers. Line height: `1.6` multiplier.

**Xs — 12px, letter-spacing: 6% (0.72px), text-transform: uppercase**
| Token | Weight | CSS `font-weight` |
|---|---|---|
| `mono-uppercase/xs/bold` | Bold | 700 |
| `mono-uppercase/xs/semibold` | SemiBold | 600 |
| `mono-uppercase/xs/medium` | Medium | 500 |
| `mono-uppercase/xs/regular` | Regular | 400 |

### Mono-Lowercase

Geist Mono in normal case — for code, query editors, log data, hex values. Line height: `1.2` multiplier.

**Md — 15px, letter-spacing: 4% (0.6px)**
| Token | Weight | CSS `font-weight` |
|---|---|---|
| `mono-lowercase/md/bold` | Bold | 700 |
| `mono-lowercase/md/semibold` | SemiBold | 600 |
| `mono-lowercase/md/medium` | Medium | 500 |
| `mono-lowercase/md/regular` | Regular | 400 |

**Sm — 13px, letter-spacing: 4% (0.52px)**
| Token | Weight | CSS `font-weight` |
|---|---|---|
| `mono-lowercase/sm/bold` | Bold | 700 |
| `mono-lowercase/sm/semibold` | SemiBold | 600 |
| `mono-lowercase/sm/medium` | Medium | 500 |
| `mono-lowercase/sm/regular` | Regular | 400 |

### Typography Quick Reference

| Context | Recommended Token | Example |
|---|---|---|
| Page title | `heading/h1/medium` | "Search", "Alerts" |
| Section header | `heading/h2/medium` | "Detection Rules" |
| Subsection | `heading/h3/medium` | "Rule Configuration" |
| Card/dialog title | `title/lg/semibold` | Alert detail title |
| Body text | `body/md/regular` | Descriptions, paragraphs |
| Emphasized body | `body/md/semibold` | Inline emphasis, counts |
| Small text | `body/sm/regular` | Timestamps, metadata |
| Field labels | `mono-uppercase/xs/medium` | "SOURCE IP", "SEVERITY" |
| Code / queries | `mono-lowercase/md/regular` | nPL editor, log lines |
| Small code | `mono-lowercase/sm/regular` | Inline code, hashes |

## Neutral Colors

| Token | Hex | RGB | Usage |
|---|---|---|---|
| `neutral-black` | `#0D0D12` | `rgb(13, 13, 18)` | Dark mode app background |
| `neutral-white` | `#FFFFFF` | `rgb(255, 255, 255)` | Text on dark, light mode background |
| `neutral-iron-400` | `#A0A0AB` | `rgb(160, 160, 171)` | Secondary text, labels |
| `neutral-iron-500` | `#70707B` | `rgb(112, 112, 123)` | Muted text, descriptions |
| `neutral-iron-700` | `#3F3F46` | `rgb(63, 63, 70)` | Disabled / very muted text |
| `neutral-gray-500` | `#667085` | `rgb(102, 112, 133)` | Subdued informational text |
| `neutral-gray-700` | `#344054` | `rgb(52, 64, 84)` | Dark text on light surfaces |
| `base-black` | `#000000` | `rgb(0, 0, 0)` | True black |
| `base-white` | `#FFFFFF` | `rgb(255, 255, 255)` | True white |

## Primary Brand Color

Base hue: **`#1C9CF0`** — `rgb(28, 156, 240)`

The primary scale is alpha-based (single hue at varying opacities), designed for dark backgrounds:

| Token | CSS Value | Opacity |
|---|---|---|
| `primary-50` | `rgba(28, 156, 240, 0.05)` | 5% |
| `primary-100` | `rgba(28, 156, 240, 0.10)` | 10% |
| `primary-200` | `rgba(28, 156, 240, 0.20)` | 20% |
| `primary-300` | `rgba(28, 156, 240, 0.30)` | 30% |
| `primary-400` | `rgba(28, 156, 240, 0.40)` | 40% |
| `primary-500` | `rgba(28, 156, 240, 0.50)` | 50% |
| `primary-600` | `rgba(28, 156, 240, 0.60)` | 60% |
| `primary-700` | `rgba(28, 156, 240, 0.70)` | 70% |
| `primary-800` | `rgba(28, 156, 240, 0.80)` | 80% |
| `primary-900` | `rgba(28, 156, 240, 0.90)` | 90% |
| `primary-1000` | `#1C9CF0` | 100% |

### Usage guidance
- **50–100**: Subtle hover backgrounds, tinted surfaces
- **200–300**: Active/selected backgrounds, badges
- **400–500**: Secondary buttons, progress bars
- **600–700**: Prominent UI elements, links
- **800–900**: High-emphasis buttons, focus rings
- **1000**: Full-strength brand accent, primary buttons

## Accent Colors

Supporting colors for badges, labels, status indicators, and chart series:

| Token | Hex | RGB | Typical Use |
|---|---|---|---|
| `accent-purple` | `#C084FC` | `rgb(192, 132, 252)` | AI/meloD features, detection rules |
| `accent-green` | `#4ADE80` | `rgb(74, 222, 128)` | Success, resolved alerts, healthy status |
| `accent-blue` | `#60A5FA` | `rgb(96, 165, 250)` | Informational, links, secondary emphasis |
| `accent-orange` | `#FDBA74` | `rgb(253, 186, 116)` | Warnings, medium-severity alerts |
| `accent-cyan` | `#22D3EE` | `rgb(34, 211, 238)` | Highlights, network-related indicators |
| `accent-yellow` | `#FACC15` | `rgb(250, 204, 21)` | Caution, attention, low-severity alerts |
| `accent-light-blue` | `#93C5FD` | `rgb(147, 197, 253)` | Secondary info, supplementary data |

## Border Colors

Dark-mode border colors with a blue tint (not pure gray):

| Token | Hex | RGB | Usage |
|---|---|---|---|
| `border-primary` | `#0F1B28` | `rgb(15, 27, 40)` | Primary dividers, card borders |
| `border-secondary` | `#182029` | `rgb(24, 32, 41)` | Subtle separators, nested borders |

## Alpha (White) Scale

White at varying opacity levels for layering depth on dark backgrounds:

| Token | CSS Value | Opacity | Usage |
|---|---|---|---|
| `alpha-white-50` | `rgba(255, 255, 255, 0.05)` | 5% | Subtle surface elevation |
| `alpha-white-100` | `rgba(255, 255, 255, 0.10)` | 10% | Card/panel backgrounds, borders |
| `alpha-white-200` | `rgba(255, 255, 255, 0.20)` | 20% | Hover states, active borders |
| `alpha-white-300` | `rgba(255, 255, 255, 0.30)` | 30% | Emphasized borders, dividers |
| `alpha-white-400` | `rgba(255, 255, 255, 0.40)` | 40% | Strong separation |
| `alpha-white-500` | `rgba(255, 255, 255, 0.50)` | 50% | Muted foreground text |
| `alpha-white-600` | `rgba(255, 255, 255, 0.60)` | 60% | Secondary foreground text |
| `alpha-white-700` | `rgba(255, 255, 255, 0.70)` | 70% | Body text on dark backgrounds |
| `alpha-white-800` | `rgba(255, 255, 255, 0.80)` | 80% | Emphasized text |
| `alpha-white-900` | `rgba(255, 255, 255, 0.90)` | 90% | High-contrast text, headings |

## Syntax Highlighting (nPL Query Language)

Map accent colors to syntax roles for dark mode:

| Role | Color | Accent Token |
|---|---|---|
| Keywords | `#C084FC` | `accent-purple` |
| Functions | `#4ADE80` | `accent-green` |
| Strings | `#FDBA74` | `accent-orange` |
| Fields (UDM) | `#3B82F6` | — (between `accent-blue` and `accent-light-blue`) |
| Fields (general) | `#60A5FA` | `accent-blue` |
| Operators | `#22D3EE` | `accent-cyan` |
| Pipe chars | `#FACC15` | `accent-yellow` |
| Numbers | `#93C5FD` | `accent-light-blue` |
| Comments | `#6B7280` | — (neutral gray, no accent mapping) |
| Regex | `#F97316` | — (deeper orange than `accent-orange`) |

## SIEM Severity Mapping

Recommended accent-to-severity mapping for alerts and detection rules:

| Severity | Color Token | Hex |
|---|---|---|
| Critical | `accent-purple` | `#C084FC` |
| High | `accent-orange` | `#FDBA74` |
| Medium | `accent-yellow` | `#FACC15` |
| Low | `accent-cyan` | `#22D3EE` |
| Info | `accent-blue` | `#60A5FA` |
| Resolved | `accent-green` | `#4ADE80` |
