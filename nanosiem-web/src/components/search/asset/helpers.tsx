// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';
import type { ReactNode } from 'react';

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
