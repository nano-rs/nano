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
  /** Click handler for the action label. When set, the action renders as a button. */
  onActionClick?: () => void;
  /** Optional leading icon */
  icon?: React.ReactNode;
  children: React.ReactNode;
}

export function SectionCard({ title, count, badge, action, onActionClick, icon, children }: SectionCardProps) {
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
          onActionClick ? (
            <button
              type="button"
              onClick={onActionClick}
              className="text-[10.5px] font-mono text-primary hover:text-primary/80 cursor-pointer focus:outline-none focus-visible:ring-1 focus-visible:ring-primary rounded"
            >
              {action}
            </button>
          ) : (
            <span className="text-[10.5px] font-mono text-muted-foreground/50">{action}</span>
          )
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
  /** Click handler — renders the tile as a button when present. */
  onClick?: () => void;
  /** Disabled drilldown (e.g. no data) — keeps the visual but blocks interaction. */
  disabled?: boolean;
  /** Optional native tooltip / aria-label override. */
  title?: string;
}

/**
 * Small centered number-over-label tile. Numeric values are compacted
 * (e.g. 1234 → "1.2K"); strings (like a country code) pass through as-is.
 *
 * When `onClick` is provided the tile renders as a button so the entire surface
 * is keyboard-accessible — this is how the dossier wires drilldowns from
 * SUCCESS/FAILURE/UNIQ DSTS/etc. to scoped searches.
 */
export function StatCell({ value, label, tone = 'default', onClick, disabled, title }: StatCellProps) {
  const toneClass =
    tone === 'critical'
      ? 'text-[oklch(62%_0.18_28)]'
      : tone === 'warn'
      ? 'text-[oklch(72%_0.14_80)]'
      : 'text-foreground';

  const inner = (
    <>
      <div className={cn('text-[18px] font-semibold tabular-nums leading-none', toneClass)}>
        {typeof value === 'number' ? formatCompact(value) : value}
      </div>
      <div className="text-[9.5px] font-mono uppercase tracking-[0.08em] text-muted-foreground/70 mt-1.5">
        {label}
      </div>
    </>
  );

  if (onClick && !disabled) {
    return (
      <button
        type="button"
        onClick={onClick}
        title={title ?? `Search ${label.toLowerCase()}`}
        aria-label={title ?? `Search ${label.toLowerCase()}`}
        className="rounded-md border border-border bg-muted/20 px-2 py-2 flex flex-col items-center text-left hover:bg-muted/40 hover:border-primary/40 transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-primary"
      >
        {inner}
      </button>
    );
  }

  return (
    <div
      className={cn(
        'rounded-md border border-border bg-muted/20 px-2 py-2 flex flex-col items-center',
        disabled && 'opacity-60 cursor-not-allowed'
      )}
      title={title}
    >
      {inner}
    </div>
  );
}
