// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-482 — shared constants + derivation helpers for the rules redesign.
// Lifted from design-ref/shadcn/rules-data.jsx + rules-overview.jsx, normalized
// against the real DetectionRule shape.

import type { DetectionRule } from '@/lib/api/types';

export type BandId = 'firing' | 'active' | 'silent' | 'staging' | 'disabled';
export type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type RuleView = ReturnType<typeof buildRuleView>;

export interface SevMeta {
  color: string;
  label: string;
}

export const SEV_META: Record<SeverityKey, SevMeta> = {
  critical: { color: 'oklch(62% 0.22 18)', label: 'Critical' },
  high: { color: 'oklch(72% 0.18 28)', label: 'High' },
  medium: { color: 'oklch(80% 0.15 78)', label: 'Medium' },
  low: { color: 'oklch(68% 0.11 215)', label: 'Low' },
  info: { color: 'oklch(55% 0.04 250)', label: 'Info' },
};

export interface BandMeta {
  id: BandId;
  label: string;
  hint: string;
  accent: string;
  defaultOpen: boolean;
}

export const BANDS: BandMeta[] = [
  { id: 'firing', label: 'Firing now', hint: 'Matched in the last hour', accent: 'oklch(72% 0.18 28)', defaultOpen: true },
  { id: 'active', label: 'Active', hint: 'Matched in the last 7 days', accent: 'oklch(70% 0.14 160)', defaultOpen: true },
  { id: 'silent', label: 'Silent', hint: 'No matches in 30+ days — tuned well, or broken', accent: 'oklch(80% 0.15 78)', defaultOpen: true },
  { id: 'staging', label: 'Staging', hint: 'Not yet promoted to production', accent: 'var(--primary)', defaultOpen: false },
  { id: 'disabled', label: 'Disabled', hint: 'Inactive', accent: 'var(--muted-foreground)', defaultOpen: false },
];

// MITRE tactic chip labels — match what rule metadata stores.
export const TACTIC_CHIPS = [
  'All tactics',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

function parseUTC(ts?: string): Date | undefined {
  if (!ts) return undefined;
  let s = ts.trim();
  if (!s.includes('Z') && !s.includes('+') && !s.includes('-', 10)) {
    s = s.includes('T') ? `${s}Z` : `${s.replace(' ', 'T')}Z`;
  }
  return new Date(s);
}

function normalizeSeverity(raw: DetectionRule['severity']): SeverityKey {
  if (raw === 'informational') return 'info';
  return raw as SeverityKey;
}

// Classify into visual band. Uses last_match_at against real time — firing = <1h,
// active = <7d, silent = never or >30d. Paused/staging rules get their own bands
// regardless of last match.
export function bandOf(rule: DetectionRule, now: Date = new Date()): BandId {
  if (rule.mode === 'staging') return 'staging';
  if (rule.mode === 'paused') return 'disabled';
  const last = parseUTC(rule.last_match_at);
  if (!last) return 'silent';
  const ageH = (now.getTime() - last.getTime()) / 36e5;
  if (ageH < 1) return 'firing';
  if (ageH < 24 * 7) return 'active';
  if (ageH > 24 * 30) return 'silent';
  return 'active';
}

export function formatLastMatch(d: Date | undefined, now: Date = new Date()): string {
  if (!d) return 'Never';
  const mins = Math.floor((now.getTime() - d.getTime()) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return d.toISOString().slice(0, 10);
}

// Pull the primary MITRE tactic string if present. Rule data stores tactics as
// slugs ("initial-access") or human labels; we accept either and render as label.
export function primaryTactic(rule: DetectionRule): string | undefined {
  const raw = rule.mitre_tactics?.[0];
  if (!raw) return undefined;
  // convert "initial-access" -> "Initial Access"
  if (raw.includes('-') || raw === raw.toLowerCase()) {
    return raw
      .split(/[-_\s]+/)
      .map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w))
      .join(' ');
  }
  return raw;
}

export function primaryTechnique(rule: DetectionRule): string | undefined {
  return rule.mitre_techniques?.[0];
}

// Build the frontend view model the list components consume. Keeps the raw
// DetectionRule on the side so actions that hit the API still work.
export function buildRuleView(rule: DetectionRule, todayCount: number, activity: number[]) {
  return {
    raw: rule,
    id: rule.id,
    name: rule.name,
    severity: normalizeSeverity(rule.severity),
    mode: (rule.detection_mode || 'scheduled') as 'scheduled' | 'real-time',
    detectionStatus: rule.mode,
    lastMatch: parseUTC(rule.last_match_at),
    today: todayCount,
    activity,
    tactic: primaryTactic(rule),
    tech: primaryTechnique(rule),
    author: rule.author || '—',
    query: rule.query,
    matchCount: rule.match_count || 0,
  };
}

// Syntax-highlighter used in the expanded row. Mirrors the mockup's pattern;
// real CodeMirror-driven highlighting is available via CodeViewer for the full
// editor surface, but the sparse inline preview reads better with a compact
// tokenizer.
type HLPart = { type: 'text' | 'str' | 'kw' | 'cmd' | 'num' | 'op'; v: string };

const KEYWORDS = new Set([
  'where', 'by', 'as', 'and', 'or', 'not', 'stats', 'dc', 'count', 'values', 'range',
  'iplocation', 'mvcount', 'source_type', 'status', 'event_id', 'eventType',
  'sort', 'head', 'table', 'timechart', 'eval', 'top', 'rare', 'transaction',
  'tree', 'sequence', 'funnel', 'asset', 'cloud', 'lateral',
]);

export function highlightLogic(t: string): HLPart[] {
  const parts: HLPart[] = [];
  const regex = /("[^"]*"|\|\s*\w+|[a-zA-Z_][a-zA-Z0-9_]*|[=><!]+|\b\d+\b)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(t)) !== null) {
    if (m.index > last) parts.push({ type: 'text', v: t.slice(last, m.index) });
    const tok = m[0];
    if (/^"/.test(tok)) parts.push({ type: 'str', v: tok });
    else if (/^\|/.test(tok)) parts.push({ type: 'cmd', v: tok });
    else if (/^\d+$/.test(tok)) parts.push({ type: 'num', v: tok });
    else if (/^[=><!]+$/.test(tok)) parts.push({ type: 'op', v: tok });
    else if (KEYWORDS.has(tok)) parts.push({ type: 'kw', v: tok });
    else parts.push({ type: 'text', v: tok });
    last = m.index + tok.length;
  }
  if (last < t.length) parts.push({ type: 'text', v: t.slice(last) });
  return parts;
}
