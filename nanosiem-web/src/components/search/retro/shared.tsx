// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Retro-hunt shared atoms + helpers (NAN-1580).
 *
 * Ports the design mock's verdict color model, prevalence band, retention
 * timeline strip and IOC type glyphs into real components. The verdict band
 * (rare / uncommon / common) is the signal; first_seen is the scoper.
 */

import { Globe, ExternalLink, Hash } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { RetroVerdict } from '@/lib/api/types';

// ---------------------------------------------------------------------------
// time + format helpers
// ---------------------------------------------------------------------------
const RE_MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** Parse an ISO-8601 string to a Date, tolerant of null/empty. */
export const reDate = (s: string | null | undefined): Date | null => {
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
};

export const reFmtD = (s: string | null | undefined): string => {
  const d = reDate(s);
  if (!d) return '—';
  return `${RE_MON[d.getMonth()]} ${d.getDate()}`;
};

/** Whole days between `s` and now (positive = in the past). */
export const reAge = (s: string | null | undefined): number => {
  const d = reDate(s);
  if (!d) return 0;
  return Math.round((Date.now() - d.getTime()) / 86400000);
};

/** Whole days between two timestamps (active span). */
export const reSpan = (a: string | null | undefined, b: string | null | undefined): number => {
  const da = reDate(a);
  const db = reDate(b);
  if (!da || !db) return 0;
  return Math.max(0, Math.round((db.getTime() - da.getTime()) / 86400000));
};

/** Compact number formatting (1.2M / 5.4k / 1,204 / 47). */
export const reNum = (v: number): string => {
  if (v >= 1e6) return (v / 1e6).toFixed(1) + 'M';
  if (v >= 1e4) return (v / 1e3).toFixed(1) + 'k';
  if (v >= 1e3) return v.toLocaleString();
  return String(Math.round(v));
};

// ---------------------------------------------------------------------------
// verdict model (prevalence band)
// ---------------------------------------------------------------------------
interface VerdictStyle {
  label: string;
  c: string;
  dim: string;
  bd: string;
}
export const RE_VERDICT: Record<RetroVerdict, VerdictStyle> = {
  rare: { label: 'RARE', c: 'oklch(64% 0.19 25)', dim: 'oklch(64% 0.19 25 / 0.13)', bd: 'oklch(64% 0.19 25 / 0.42)' },
  uncommon: { label: 'UNCOMMON', c: 'oklch(76% 0.14 70)', dim: 'oklch(76% 0.14 70 / 0.13)', bd: 'oklch(76% 0.14 70 / 0.40)' },
  common: { label: 'COMMON', c: 'var(--color-fg-3)', dim: 'color-mix(in srgb, var(--color-fg) 7%, transparent)', bd: 'var(--color-border-2)' },
};

/** Verdict band: rare ≤ 0.02, uncommon ≤ 0.15, else common (denominator = env hosts). */
export const reVerdict = (hosts: number, total: number): RetroVerdict => {
  const r = total > 0 ? hosts / total : 0;
  if (r <= 0.02) return 'rare';
  if (r <= 0.15) return 'uncommon';
  return 'common';
};

/** log-ish position on the prevalence band track (0..1). */
export const rePrevPos = (pct: number): number => {
  if (pct <= 2) return (pct / 2) * 0.34;
  if (pct <= 15) return 0.34 + ((pct - 2) / 13) * 0.33;
  return 0.67 + Math.min(1, (pct - 15) / 85) * 0.33;
};

// ---------------------------------------------------------------------------
// IOC type glyph
// ---------------------------------------------------------------------------
const RE_TYPE_ICON: Record<string, typeof Globe> = {
  ip: Globe,
  domain: Globe,
  url: ExternalLink,
  sha256: Hash,
  md5: Hash,
  sha1: Hash,
};

export function TypeChip({ t }: { t: string }) {
  const Ico = RE_TYPE_ICON[t] ?? Hash;
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-[1px] rounded-[3px] bg-fg/6 text-fg-3 font-mono text-[9.5px] uppercase tracking-[0.1em] font-semibold shrink-0">
      <Ico className="w-[10px] h-[10px]" />
      {t}
    </span>
  );
}

export function VerdictBadge({ v, size = 'md' }: { v: RetroVerdict; size?: 'sm' | 'md' }) {
  const d = RE_VERDICT[v];
  const pad = size === 'sm' ? 'px-1.5 py-[1px] text-[9px]' : 'px-2 py-[2px] text-[10px]';
  return (
    <span
      className={cn('inline-flex items-center gap-1 rounded-[3px] font-mono font-bold tracking-[0.14em] whitespace-nowrap', pad)}
      style={{ background: d.dim, color: d.c, border: `1px solid ${d.bd}` }}
    >
      {v === 'rare' && (
        <span className="w-[5px] h-[5px] rounded-full" style={{ background: d.c, boxShadow: `0 0 5px ${d.c}` }} />
      )}
      {d.label}
    </span>
  );
}

export function PrevalenceBand({ hosts, total, verdict }: { hosts: number; total: number; verdict: RetroVerdict }) {
  const pct = total > 0 ? (hosts / total) * 100 : 0;
  const pos = rePrevPos(pct);
  const d = RE_VERDICT[verdict];
  return (
    <div className="w-full">
      <div
        className="relative h-[10px] rounded-full overflow-hidden flex"
        style={{ background: 'var(--color-bg)', border: '1px solid var(--color-border)' }}
      >
        <div style={{ width: '34%', background: 'oklch(64% 0.19 25 / 0.30)' }} />
        <div style={{ width: '33%', background: 'oklch(76% 0.14 70 / 0.22)' }} />
        <div style={{ width: '33%', background: 'color-mix(in srgb, var(--color-fg) 6%, transparent)' }} />
      </div>
      {/* marker */}
      <div className="relative h-0">
        <div className="absolute -top-[14px] -translate-x-1/2 flex flex-col items-center" style={{ left: `${pos * 100}%` }}>
          <div className="w-[2px] h-[16px] rounded-full" style={{ background: d.c }} />
        </div>
      </div>
      <div className="flex justify-between mt-1.5 font-mono text-[9px] uppercase tracking-[0.12em] text-fg-4">
        <span style={{ color: 'oklch(64% 0.19 25)' }}>rare</span>
        <span style={{ color: 'oklch(76% 0.14 70)' }}>uncommon</span>
        <span>common</span>
      </div>
    </div>
  );
}

function Marker({ pos, label, tag }: { pos: number; label: string; tag: string }) {
  return (
    <div className="absolute top-1/2 -translate-y-1/2 -translate-x-1/2 flex flex-col items-center z-10" style={{ left: `${pos * 100}%` }}>
      <span className="absolute -top-[15px] font-mono text-[8.5px] uppercase tracking-[0.1em] whitespace-nowrap" style={{ color: 'oklch(64% 0.19 25)' }}>
        {tag}
      </span>
      <span className="w-[9px] h-[9px] rounded-full border-2" style={{ background: 'var(--color-bg)', borderColor: 'oklch(64% 0.19 25)' }} />
      <span className="absolute top-[12px] font-mono text-[9px] text-fg-2 tabular-nums whitespace-nowrap">{label}</span>
    </div>
  );
}

/**
 * Horizontal retention timeline w/ active band + first/last markers. The track
 * spans [retentionStart, now]; first/last seen are positioned as fractions and
 * month ticks are derived from the retention floor. retentionStart defaults to
 * Jan 1 of the current year ("all history") when no window is supplied.
 */
export function TimelineStrip({
  firstSeen,
  lastSeen,
  label,
  retentionStart,
}: {
  firstSeen: string | null | undefined;
  lastSeen: string | null | undefined;
  label?: string;
  retentionStart?: Date;
}) {
  const now = new Date();
  const start = retentionStart ?? new Date(now.getFullYear(), 0, 1);
  const total = Math.max(1, now.getTime() - start.getTime());
  const frac = (s: string | null | undefined): number => {
    const d = reDate(s);
    if (!d) return 0;
    return Math.max(0, Math.min(1, (d.getTime() - start.getTime()) / total));
  };
  const f = frac(firstSeen);
  const l = frac(lastSeen);
  const span = reSpan(firstSeen, lastSeen);
  const age = reAge(firstSeen);

  // month grid from retention floor through now
  const months: { pos: number; lbl: string }[] = [];
  const cursor = new Date(start.getFullYear(), start.getMonth(), 1);
  while (cursor <= now) {
    months.push({ pos: (cursor.getTime() - start.getTime()) / total, lbl: RE_MON[cursor.getMonth()] });
    cursor.setMonth(cursor.getMonth() + 1);
  }

  return (
    <div className="rounded-lg border border-border p-3.5" style={{ background: 'var(--color-panel)' }}>
      <div className="flex items-center justify-between mb-3">
        <span className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-fg-3 font-semibold">
          {label || 'Timeline · all history'}
        </span>
        <span className="font-mono text-[10px] text-fg-2">
          active <span className="text-fg font-semibold tabular-nums">{span}d</span>
          <span className="text-fg-4 mx-1.5">·</span>
          first seen <span className="text-fg font-semibold tabular-nums">{age}d</span> ago
        </span>
      </div>
      <div className="relative h-[34px]">
        {/* baseline */}
        <div className="absolute left-0 right-0 top-1/2 -translate-y-1/2 h-px bg-border-2" />
        {/* month grid */}
        {months.map((mo, i) => (
          <div key={i} className="absolute top-0 bottom-0 flex flex-col items-center" style={{ left: `${mo.pos * 100}%` }}>
            <div className="w-px flex-1 bg-border/70" />
          </div>
        ))}
        {/* active band */}
        <div
          className="absolute top-1/2 -translate-y-1/2 h-[6px] rounded-full"
          style={{
            left: `${f * 100}%`,
            width: `${Math.max(0.5, (l - f) * 100)}%`,
            background: 'linear-gradient(90deg, oklch(64% 0.19 25 / 0.85), oklch(64% 0.19 25 / 0.45))',
            boxShadow: '0 0 10px oklch(64% 0.19 25 / 0.4)',
          }}
        />
        {Math.abs(l - f) < 0.03 ? (
          // first ≈ last (e.g. a single-day / one-shot hit): render ONE marker so
          // the "first"/"last" tags and the two dates don't stack into a blur.
          <Marker pos={(f + l) / 2} label={reFmtD(firstSeen)} tag="seen" />
        ) : (
          <>
            <Marker pos={f} label={reFmtD(firstSeen)} tag="first" />
            <Marker pos={l} label={reFmtD(lastSeen)} tag="last" />
          </>
        )}
        {/* now */}
        <div className="absolute top-1/2 -translate-y-1/2 right-0 flex items-center gap-1">
          <span className="w-[2px] h-[12px] rounded-full bg-fg-4" />
        </div>
      </div>
      <div className="relative h-[12px] mt-0.5">
        {months.map((mo, i) => (
          <span
            key={i}
            className="absolute -translate-x-1/2 font-mono text-[8.5px] text-fg-4 uppercase tracking-wide"
            style={{ left: `${mo.pos * 100}%` }}
          >
            {mo.lbl}
          </span>
        ))}
        <span className="absolute right-0 font-mono text-[8.5px] text-fg-4 uppercase tracking-wide">now</span>
      </div>
    </div>
  );
}
