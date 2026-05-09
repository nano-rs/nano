// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';
import { formatCompact } from '../helpers';

// ---------------------------------------------------------------------------
// Shared primitives for asset dossier section cards.
// Previously these lived alongside `AlertsCard` and were implicitly re-exported
// from that file — moved here so every section imports from the same place.
// ---------------------------------------------------------------------------

interface SectionCardProps {
  title: string;
  count?: number;
  /** Subtitle chip (e.g. "3 rare") */
  badge?: React.ReactNode;
  /** Action label (right-aligned) — clickable text link for "open ↗" */
  action?: React.ReactNode;
  /** Optional leading icon */
  icon?: React.ReactNode;
  children: React.ReactNode;
}

export function SectionCard({ title, count, badge, action, icon, children }: SectionCardProps) {
  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden group">
      <div className="px-4 py-2.5 border-b border-border flex items-center gap-2">
        {icon}
        <div className="text-[12.5px] font-semibold text-foreground">{title}</div>
        {typeof count === 'number' && (
          <span className="text-[10.5px] font-mono px-1.5 py-0.5 rounded bg-foreground/5 text-muted-foreground/70 tabular-nums">
            {count}
          </span>
        )}
        {badge}
        <span className="flex-1" />
        {action && (
          <span className="text-[10.5px] font-mono text-primary hover:text-primary/80 cursor-pointer">
            {action}
          </span>
        )}
      </div>
      <div className="px-4 py-3">{children}</div>
    </div>
  );
}

export function EmptyCell({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[11.5px] text-muted-foreground/70 py-4 text-center">{children}</div>
  );
}

export type StatCellTone = 'default' | 'warn' | 'critical';

interface StatCellProps {
  value: number | string;
  label: string;
  tone?: StatCellTone;
}

/**
 * Small centered number-over-label tile. Numeric values are compacted
 * (e.g. 1234 → "1.2K"); strings (like a country code) pass through as-is.
 */
export function StatCell({ value, label, tone = 'default' }: StatCellProps) {
  const toneClass =
    tone === 'critical'
      ? 'text-[oklch(62%_0.18_28)]'
      : tone === 'warn'
      ? 'text-[oklch(72%_0.14_80)]'
      : 'text-foreground';
  return (
    <div className="rounded-md border border-border bg-muted/20 px-2 py-2 flex flex-col items-center">
      <div className={cn('text-[18px] font-semibold tabular-nums leading-none', toneClass)}>
        {typeof value === 'number' ? formatCompact(value) : value}
      </div>
      <div className="text-[9.5px] font-mono uppercase tracking-[0.08em] text-muted-foreground/70 mt-1.5">
        {label}
      </div>
    </div>
  );
}
