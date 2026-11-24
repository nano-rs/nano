// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-484 — shared helpers for the redesigned rule editor.
// Lifted from design-ref/shadcn/editor-*.jsx and normalized against the real
// DetectionRule shape.

import type { DetectionRule } from '@/lib/api/types';

export type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type ModeKey = 'staging' | 'live' | 'alerting' | 'paused';
export type DisplayModeKey = 'alerting' | 'live' | 'staging' | 'paused';

// Severity → token color. Matches the oklch palette used by the /rules list.
export const SEV_COLOR: Record<SeverityKey, string> = {
  critical: 'oklch(62% 0.22 18)',
  high: 'oklch(72% 0.18 28)',
  medium: 'oklch(80% 0.15 78)',
  low: 'oklch(68% 0.11 215)',
  informational: 'oklch(55% 0.04 250)',
};

// Short label for the sev pill chip in the top strip.
export const SEV_LABEL: Record<SeverityKey, string> = {
  critical: 'CRIT',
  high: 'HIGH',
  medium: 'MED',
  low: 'LOW',
  informational: 'INFO',
};

export function normalizeSeverity(raw: DetectionRule['severity'] | string | undefined): SeverityKey {
  if (!raw) return 'medium';
  const v = String(raw).toLowerCase();
  if (v === 'critical' || v === 'high' || v === 'medium' || v === 'low' || v === 'informational') {
    return v;
  }
  return 'medium';
}

// Map the API mode onto a display key. NAN-5327: `alerting` used to collapse
// to `live`, so the header badge and tree pill read "LIVE" after "Enable
// alerting" while the YAML / meta row said alerting. Live (count only) and
// Alerting (emits alerts) are operationally different and must not share a
// badge.
export function displayMode(mode: string | undefined | null): DisplayModeKey {
  if (mode === 'paused') return 'paused';
  if (mode === 'alerting') return 'alerting';
  if (mode === 'live') return 'live';
  return 'staging';
}

export const MODE_META: Record<DisplayModeKey, { label: string; dotVar: string; tone: string; bg: string }> = {
  // Alerting is the normal production state, not an error: it takes the
  // success tone and Live takes cyan, matching `getModeColor` (lib/ui-colors).
  alerting: {
    label: 'ALERTING',
    dotVar: 'var(--success)',
    tone: 'text-[var(--success)]',
    bg: 'color-mix(in srgb, var(--success) 15%, transparent)',
  },
  live: {
    label: 'LIVE',
    dotVar: 'var(--accent-cyan)',
    tone: 'text-[var(--accent-cyan)]',
    bg: 'color-mix(in srgb, var(--accent-cyan) 15%, transparent)',
  },
  staging: {
    label: 'STAGING',
    dotVar: 'var(--primary)',
    tone: 'text-[var(--primary)]',
    bg: 'color-mix(in srgb, var(--primary) 15%, transparent)',
  },
  paused: {
    label: 'PAUSED',
    dotVar: 'var(--muted-foreground)',
    tone: 'text-muted-foreground',
    bg: 'color-mix(in srgb, var(--foreground) 10%, transparent)',
  },
};

// Cron → human cadence. Covers the common patterns used by rule authors.
// Accepts the 5-field form (`min hour dom mon dow`) and the 6/7-field form the
// scheduler stores (`sec min hour dom mon dow [year]`) — NAN-5316: the API
// writes `*/30 * * * * *` (every 30 s) for auto-switched rules, which the old
// 5-field parse read as "every 30m".
export function cronHuman(expr: string | undefined | null): string {
  if (!expr) return '—';
  const parts = expr.trim().split(/\s+/);
  if (parts.length < 5 || parts.length > 7) return expr;
  const [s, m, h, dom, mo, dow] = parts.length === 5 ? ['0', ...parts] : parts;
  const wild = (p: string) => p === '*' || p === '?';
  const year = parts.length === 7 ? parts[6] : '*';
  if (![dom, mo, dow, year].every(wild)) return expr;

  // Sub-minute cadences: seconds field drives, everything else wildcard.
  if (wild(m) && wild(h)) {
    const sm = s.match(/^(?:\*|0)\/(\d+)$/);
    if (sm) return `every ${sm[1]}s`;
    if (s === '*') return 'every second';
  }
  if (!/^\d+$/.test(s)) return expr;

  if (wild(h)) {
    const mm = m.match(/^(?:\*|0)\/(\d+)$/);
    if (mm) return `every ${mm[1]}m`;
    if (m === '*') return 'every minute';
    if (/^\d+$/.test(m)) return `hourly at :${m.padStart(2, '0')}`;
  }
  if (/^\d+$/.test(m)) {
    const hh = h.match(/^(?:\*|0)\/(\d+)$/);
    if (hh && m === '0') return `every ${hh[1]}h`;
  }
  return expr;
}

// Categorize a rule into a folder. Uses the explicit `folder` field, else
// 'Uncategorized'. NAN-5327: this used to fall back to a MITRE-tactic guess
// (Execution → "Identity"), so the tree disagreed with the meta row / API,
// which both show `folder: null` as Uncategorized.
export function folderOf(rule: Pick<DetectionRule, 'folder'>): string {
  const explicit = (rule.folder || '').trim();
  return explicit || 'Uncategorized';
}

// Display labels for reserved folder ids (the stored value stays the id).
// NAN-5581: hunts' agent detections live in `agent_detections`.
const FOLDER_LABELS: Record<string, string> = { agent_detections: 'Agent detections' };
export function folderLabel(name: string): string {
  return FOLDER_LABELS[name.toLowerCase()] ?? name;
}

// Folder display icon kind — drives the icon in RuleRail.
export type FolderKind = 'network' | 'identity' | 'endpoint' | 'cloud' | 'folder';
export function folderKind(name: string): FolderKind {
  const v = name.toLowerCase();
  if (v === 'identity') return 'identity';
  if (v === 'endpoint') return 'endpoint';
  if (v === 'network') return 'network';
  if (v === 'cloud') return 'cloud';
  return 'folder';
}

// NAN-5773: the rule rail's Active / Archived tabs. Deleting a rule archives
// it (NAN-5672) and the editor loads archived rules too, so every rail count
// goes through this rather than `rules.length`.
export type RailTab = 'active' | 'archived';

export function inRailTab(rule: Pick<DetectionRule, 'archived'>, tab: RailTab): boolean {
  return Boolean(rule.archived) === (tab === 'archived');
}

// The footer's rule total: the rules the selected tab lists (before the name
// filter), never the archived + active union.
export function railTabTotal(rules: ReadonlyArray<Pick<DetectionRule, 'archived'>>, tab: RailTab): number {
  return rules.filter((rule) => inRailTab(rule, tab)).length;
}

// NAN-5773: the folders active (non-archived) rules use, as `folderOf` names
// them. A folder only deleted rules use is not listed or treated as existing.
export function activeFolderNames(rules: ReadonlyArray<Pick<DetectionRule, 'archived' | 'folder'>>): string[] {
  return rules.filter((rule) => inRailTab(rule, 'active')).map((rule) => folderOf(rule));
}

/** One UTC calendar day of rule activity for the Impact & baseline card. */
export interface DailyBucket {
  /** `YYYY-MM-DD` (UTC). */
  date: string;
  count: number;
}

const DAY_MS = 86_400_000;

/**
 * NAN-5842: `/api/rules/stats` returns only the days a rule fired (sparse,
 * keyed by UTC date). Build `days` contiguous, zero-filled UTC buckets ending
 * on `now`'s UTC day, so "last 7d" means the last seven calendar days rather
 * than the last seven days that happened to have matches, and a single match
 * still draws a line (a spike) instead of a lone, clipped point.
 */
export function dailyBuckets(
  stats: ReadonlyArray<{ date: string; match_count?: number | null }> | undefined,
  days: number,
  now: Date = new Date(),
): DailyBucket[] {
  const byDate = new Map<string, number>();
  for (const s of stats ?? []) {
    const key = String(s.date).slice(0, 10);
    byDate.set(key, (byDate.get(key) ?? 0) + (s.match_count || 0));
  }
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const out: DailyBucket[] = [];
  for (let i = days - 1; i >= 0; i -= 1) {
    const date = new Date(today - i * DAY_MS).toISOString().slice(0, 10);
    out.push({ date, count: byDate.get(date) ?? 0 });
  }
  return out;
}
