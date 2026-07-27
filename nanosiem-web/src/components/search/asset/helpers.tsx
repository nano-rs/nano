// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';
import type { ReactNode } from 'react';
import { nplQuotedBody } from '@/lib/npl-quote';

// ---------------------------------------------------------------------------
// Risk tone / severity tone
// ---------------------------------------------------------------------------
export type RiskBand = 'critical' | 'high' | 'elevated' | 'medium' | 'low' | 'informational' | 'none';

export interface RiskTone {
  /** Text color class */
  text: string;
  /** Label (dim text) class */
  label: string;
  /** Border class */
  border: string;
  /** Background class */
  bg: string;
  /** Raw color for inline bar fills */
  bar: string;
}

/** Classify a risk score (0-100) into a band. */
export function riskBandForScore(score: number): RiskBand {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'elevated';
  if (score >= 20) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}

export function riskTone(band: RiskBand): RiskTone {
  switch (band) {
    case 'critical':
      return {
        text: 'text-[oklch(62%_0.18_28)]',
        label: 'text-[oklch(62%_0.18_28)]',
        border: 'border-[oklch(62%_0.18_28/0.4)]',
        bg: 'bg-[oklch(62%_0.18_28/0.08)]',
        bar: 'oklch(62% 0.18 28)',
      };
    case 'high':
    case 'elevated':
      return {
        text: 'text-[oklch(72%_0.14_80)]',
        label: 'text-[oklch(72%_0.14_80)]',
        border: 'border-[oklch(72%_0.14_80/0.4)]',
        bg: 'bg-[oklch(72%_0.14_80/0.08)]',
        bar: 'oklch(72% 0.14 80)',
      };
    case 'medium':
      return {
        text: 'text-[oklch(80%_0.10_95)]',
        label: 'text-[oklch(80%_0.10_95)]',
        border: 'border-[oklch(80%_0.10_95/0.4)]',
        bg: 'bg-[oklch(80%_0.10_95/0.08)]',
        bar: 'oklch(80% 0.10 95)',
      };
    default:
      return {
        text: 'text-foreground',
        label: 'text-muted-foreground',
        border: 'border-border',
        bg: 'bg-foreground/5',
        bar: 'var(--primary)',
      };
  }
}

export function sevTone(sev: string): { text: string; bg: string; dot: string } {
  const s = sev.toLowerCase();
  if (s === 'critical')
    return {
      text: 'text-[oklch(62%_0.18_28)]',
      bg: 'bg-[oklch(62%_0.18_28/0.12)]',
      dot: 'oklch(62% 0.18 28)',
    };
  if (s === 'high')
    return {
      text: 'text-[oklch(72%_0.14_80)]',
      bg: 'bg-[oklch(72%_0.14_80/0.12)]',
      dot: 'oklch(72% 0.14 80)',
    };
  if (s === 'medium')
    return {
      text: 'text-[oklch(80%_0.10_95)]',
      bg: 'bg-[oklch(80%_0.10_95/0.12)]',
      dot: 'oklch(80% 0.10 95)',
    };
  return {
    text: 'text-muted-foreground',
    bg: 'bg-foreground/5',
    dot: 'var(--muted-foreground)',
  };
}

// ---------------------------------------------------------------------------
// Pieces shared by IdentityHeader
// ---------------------------------------------------------------------------

export interface FactCellProps {
  k: string;
  v: ReactNode;
  sub?: ReactNode;
  subTone?: 'warn' | 'default';
}

export function FactCell({ k, v, sub, subTone = 'default' }: FactCellProps) {
  return (
    <div className="min-w-0">
      <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70">
        {k}
      </div>
      <div className="text-[12px] text-foreground mt-0.5 truncate">{v}</div>
      {sub !== undefined && sub !== null && sub !== '' && (
        <div
          className={cn(
            'text-[10.5px] mt-0.5 truncate',
            subTone === 'warn' ? 'text-[oklch(72%_0.14_80)]' : 'text-muted-foreground/70'
          )}
        >
          {sub}
        </div>
      )}
    </div>
  );
}

interface RiskGaugeProps {
  score: number;
  band: RiskBand;
  size?: number;
}

export function RiskGauge({ score, band, size = 44 }: RiskGaugeProps) {
  const tone = riskTone(band);
  const r = 18;
  const c = 2 * Math.PI * r;
  const pct = Math.min(100, Math.max(0, score)) / 100;
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg viewBox="0 0 48 48" className="w-full h-full -rotate-90">
        <circle cx="24" cy="24" r={r} fill="none" stroke="var(--border)" strokeWidth="3.5" />
        <circle
          cx="24"
          cy="24"
          r={r}
          fill="none"
          stroke={tone.bar}
          strokeWidth="3.5"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - pct)}
          strokeLinecap="round"
        />
      </svg>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes < 1024 * 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  return `${(bytes / (1024 * 1024 * 1024 * 1024)).toFixed(2)} TB`;
}

export function formatCompact(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1000 * 1000) return `${(n / 1000).toFixed(1)}K`;
  if (n < 1000 * 1000 * 1000) return `${(n / 1_000_000).toFixed(1)}M`;
  return `${(n / 1_000_000_000).toFixed(1)}B`;
}

/**
 * Parse a ClickHouse timestamp string as UTC. ClickHouse emits raw timestamps
 * like `2026-04-20 17:59:35.000000` without a timezone suffix, so JS parses them
 * as local time by default — which shifts them by the user's offset. We always
 * want UTC, so append `Z` when no timezone designator is present.
 */
export function parseAsUTC(value: string | Date | null | undefined): Date | null {
  if (!value) return null;
  if (value instanceof Date) return value;
  if (value.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(value)) {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  const iso = value.replace(' ', 'T') + 'Z';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatTimeRelative(iso: string | null | undefined): string {
  const d = parseAsUTC(iso);
  if (!d) return iso ?? '';
  const diffMs = Date.now() - d.getTime();
  if (diffMs < 0) return d.toISOString().slice(11, 19) + ' UTC';
  const sec = Math.floor(diffMs / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 48) return `${hr}h ago`;
  const days = Math.floor(hr / 24);
  return `${days}d ago`;
}

export function formatTimestampHMS(iso: string | null | undefined): string {
  const d = parseAsUTC(iso);
  if (!d) return iso ?? '';
  return d.toISOString().slice(11, 19) + ' UTC';
}

export function formatDate(iso: string | null | undefined): string {
  const d = parseAsUTC(iso);
  if (!d) return iso ?? '';
  return d.toISOString().slice(0, 10);
}

// ---------------------------------------------------------------------------
// Identity-aware drilldown
//
// Build a filter dict for `handleDrilldown` (in pages/Search.tsx) that scopes
// the resulting search to every known identifier of an asset (ip / hostname /
// user), rather than only the primary identifier the user clicked through to.
//
// IMPORTANT: only the identity values flow through `escDQ` here. Any other
// user/server-provided value that callers want to interpolate must be added as
// a top-level key in the filter dict (which `handleDrilldown` then escapes) —
// do NOT inline it into a `_tableCommand` string, since those are appended
// verbatim. The legacy `components/search/AssetView.tsx:1105` helper does the
// same shape; converge fixes here so both surfaces stay in sync.
// ---------------------------------------------------------------------------

interface AssetIdentityRecordLike {
  ip?: string | null;
  hostname?: string | null;
  user?: string | null;
}

const escDQ = (s: string) => nplQuotedBody(s);

export function buildIdentityClause(
  identities: AssetIdentityRecordLike[] | undefined,
): string | null {
  const ips = new Set<string>();
  const hostnames = new Set<string>();
  const users = new Set<string>();
  for (const id of identities ?? []) {
    const ip = id.ip?.trim();
    const hostname = id.hostname?.trim();
    const user = id.user?.trim();
    if (ip) ips.add(ip);
    if (hostname) hostnames.add(hostname);
    if (user) users.add(user);
  }
  const clauses: string[] = [];
  for (const ip of ips) clauses.push(`src_ip="${escDQ(ip)}"`);
  for (const ip of ips) clauses.push(`dest_ip="${escDQ(ip)}"`);
  for (const h of hostnames) clauses.push(`src_host="${escDQ(h)}"`);
  for (const h of hostnames) clauses.push(`dest_host="${escDQ(h)}"`);
  for (const u of users) clauses.push(`user="${escDQ(u)}"`);
  if (clauses.length === 0) return null;
  return `(${clauses.join(' OR ')})`;
}

/**
 * Compute the [start, end] ISO window for bucket `bucketIdx` of an asset
 * activity timeline. The timeline divides `timeRange` into `bucketCount`
 * equal-width slices; bucket 0 is oldest, bucket `bucketCount - 1` is newest.
 *
 * Returns `null` if the inputs are degenerate (NaN range, zero bucketCount,
 * out-of-range index). Used by `handleTimelineCellClick` in `asset/index.tsx`
 * to pass `_timeRangeOverride` through to `handleDrilldown` (NAN-1050).
 */
export function computeBucketWindow(
  timeRange: { start: string; end: string },
  bucketCount: number,
  bucketIdx: number,
): { start: string; end: string } | null {
  if (bucketCount <= 0) return null;
  if (bucketIdx < 0 || bucketIdx >= bucketCount) return null;
  const startMs = Date.parse(timeRange.start);
  const endMs = Date.parse(timeRange.end);
  if (Number.isNaN(startMs) || Number.isNaN(endMs) || endMs <= startMs) return null;
  const span = (endMs - startMs) / bucketCount;
  const bStart = new Date(startMs + bucketIdx * span);
  const bEnd = new Date(startMs + (bucketIdx + 1) * span);
  return { start: bStart.toISOString(), end: bEnd.toISOString() };
}

/**
 * Merge an asset's identity clause into a drilldown filter dict. If no
 * identities are resolved, falls back to a direct `{primaryField: primaryValue}`
 * match so the drilldown still scopes to this asset.
 */
export function withAssetIdentity(
  filters: Record<string, unknown>,
  identities: AssetIdentityRecordLike[] | undefined,
  primary?: { field: string; value: string } | null,
): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...filters };
  const clause = buildIdentityClause(identities);
  if (clause) {
    merged._identityClause = clause;
  } else if (primary?.field && primary.value) {
    merged[primary.field] = primary.value;
  }
  return merged;
}
