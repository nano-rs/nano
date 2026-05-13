// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-484 — shared helpers for the redesigned rule editor.
// Lifted from design-ref/shadcn/editor-*.jsx and normalized against the real
// DetectionRule shape.

import type { DetectionRule } from '@/lib/api/types';

export type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type ModeKey = 'staging' | 'live' | 'alerting' | 'paused';
export type DisplayModeKey = 'live' | 'staging' | 'paused';

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

// The design uses live/staging/paused; the API uses staging/live/alerting/paused.
// Map:   staging → staging,   alerting → live,   live → live,   paused → paused.
export function displayMode(mode: string | undefined | null): DisplayModeKey {
  if (mode === 'paused') return 'paused';
  if (mode === 'staging') return 'staging';
  if (mode === 'alerting' || mode === 'live') return 'live';
  return 'staging';
}

export const MODE_META: Record<DisplayModeKey, { label: string; dotVar: string; tone: string }> = {
  live: { label: 'LIVE', dotVar: 'var(--success)', tone: 'text-[var(--success)]' },
  staging: { label: 'STAGING', dotVar: 'var(--primary)', tone: 'text-[var(--primary)]' },
  paused: { label: 'PAUSED', dotVar: 'var(--muted-foreground)', tone: 'text-muted-foreground' },
};

// Cron → human cadence. Covers the common patterns used by rule authors.
export function cronHuman(expr: string | undefined | null): string {
  if (!expr) return '—';
  const parts = expr.trim().split(/\s+/);
  if (parts.length < 5) return expr;
  const [m, h, dom, mo, dow] = parts;
  const starOthers = [h, dom, mo, dow].every((p) => p === '*' || p === '?');
  if (starOthers) {
    const mm = m.match(/^\*\/(\d+)$/);
    if (mm) return `every ${mm[1]}m`;
    if (m === '*') return 'every minute';
    if (/^\d+$/.test(m)) return `at :${m.padStart(2, '0')}`;
  }
  return expr;
}

// Categorize a rule into a folder. Uses the explicit `folder` field first, then
// falls back to its primary MITRE tactic, then to 'Uncategorized'.
export function folderOf(rule: DetectionRule): string {
  const explicit = (rule.folder || '').trim();
  if (explicit) return explicit;
  const tactics = rule.mitre_tactics || [];
  if (tactics.length === 0) return 'Uncategorized';
  const first = tactics[0];
  if (/TA00(01|02|04|06)/.test(first)) return 'Identity';
  if (/TA000[35]/.test(first)) return 'Endpoint';
  if (/TA00(07|08|09|10|11)/.test(first)) return 'Network';
  return 'Cloud';
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
