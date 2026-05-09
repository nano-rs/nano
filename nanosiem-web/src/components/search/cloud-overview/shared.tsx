// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';
import type { ReactNode } from 'react';
import type { CloudRiskBand } from '@/lib/api/types';

// ---------------------------------------------------------------------------
// Shared visual primitives for the | cloud overview sections. Deliberately
// tone-separate from asset/helpers.tsx because the mockup uses warmer/less
// saturated swatches for the cloud surfaces, and we want to lift the tones
// verbatim from `design-ref/shadcn/cloud-sections.jsx`.
// ---------------------------------------------------------------------------

export interface SevTone {
  bg: string;
  text: string;
  border: string;
  dot: string;
}

export function cloudSevTone(sev: CloudRiskBand | string | null | undefined): SevTone {
  switch (sev) {
    case 'critical':
      return {
        bg: 'bg-[oklch(62%_0.18_28/0.15)]',
        text: 'text-[oklch(72%_0.17_28)]',
        border: 'border-[oklch(62%_0.18_28/0.45)]',
        dot: 'bg-[oklch(68%_0.18_28)]',
      };
    case 'high':
      return {
        bg: 'bg-[oklch(70%_0.16_55/0.15)]',
        text: 'text-[oklch(78%_0.14_60)]',
        border: 'border-[oklch(70%_0.16_55/0.45)]',
        dot: 'bg-[oklch(76%_0.15_60)]',
      };
    case 'medium':
      return {
        bg: 'bg-[oklch(72%_0.14_80/0.15)]',
        text: 'text-[oklch(80%_0.13_85)]',
        border: 'border-[oklch(72%_0.14_80/0.45)]',
        dot: 'bg-[oklch(78%_0.14_85)]',
      };
    case 'low':
      return {
        bg: 'bg-[oklch(70%_0.08_220/0.15)]',
        text: 'text-muted-foreground',
        border: 'border-border',
        dot: 'bg-muted-foreground/70',
      };
    default:
      return {
        bg: '',
        text: 'text-muted-foreground',
        border: 'border-border',
        dot: 'bg-muted-foreground/70',
      };
  }
}

export function fmtCount(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
  return String(n);
}

export function postureBandForScore(score: number): CloudRiskBand {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'medium';
  return 'low';
}

// ---------------------------------------------------------------------------
// CloudCard — the card chrome used by every overview section. Matches the
// CloudCard component in design-ref/shadcn/cloud-sections.jsx.
// ---------------------------------------------------------------------------

interface CloudCardProps {
  title: string;
  subtitle?: ReactNode;
  /** OKLCH color for the left accent bar on the header */
  accent?: string;
  /** Right-aligned chip/toolbar (sort buttons, filter pills, …) */
  chip?: ReactNode;
  children: ReactNode;
  className?: string;
}

export function CloudCard({ title, subtitle, accent, chip, children, className }: CloudCardProps) {
  return (
    <div className={cn('bg-card border border-border rounded-lg flex flex-col', className)}>
      <div className="px-3.5 py-2 border-b border-border flex items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold">
        {accent && <span className="w-1 h-3 rounded-sm shrink-0" style={{ background: accent }} />}
        <span>{title}</span>
        {subtitle && (
          <span className="normal-case tracking-normal text-muted-foreground/80">· {subtitle}</span>
        )}
        <span className="flex-1" />
        {chip}
      </div>
      <div className="flex-1 min-h-0">{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// CloudFact — small stat column used inside the org header
// ---------------------------------------------------------------------------

export function CloudFact({ k, v, sub }: { k: string; v: ReactNode; sub?: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70">
        {k}
      </div>
      <div className="text-foreground truncate mt-0.5">{v}</div>
      {sub !== undefined && sub !== null && sub !== '' && (
        <div className="text-[10.5px] text-muted-foreground/70 font-mono truncate">{sub}</div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// CloudRiskGauge — circular posture / risk gauge (mirror of cloud-sections.jsx)
// ---------------------------------------------------------------------------

export function CloudRiskGauge({
  score,
  band,
  size = 40,
}: {
  score: number;
  band: CloudRiskBand;
  size?: number;
}) {
  const r = 16;
  const c = 2 * Math.PI * r;
  const pct = Math.min(100, Math.max(0, score)) / 100;
  const color =
    band === 'critical'
      ? 'oklch(68% 0.18 28)'
      : band === 'high'
      ? 'oklch(76% 0.15 60)'
      : band === 'medium'
      ? 'oklch(78% 0.14 85)'
      : 'oklch(70% 0.08 220)';
  return (
    <svg viewBox="0 0 40 40" className="shrink-0" style={{ width: size, height: size }}>
      <circle cx="20" cy="20" r={r} fill="none" stroke="currentColor" strokeWidth="3" className="text-foreground/10" />
      <circle
        cx="20"
        cy="20"
        r={r}
        fill="none"
        stroke={color}
        strokeWidth="3"
        strokeLinecap="round"
        strokeDasharray={c}
        strokeDashoffset={c * (1 - pct)}
        transform="rotate(-90 20 20)"
      />
    </svg>
  );
}
