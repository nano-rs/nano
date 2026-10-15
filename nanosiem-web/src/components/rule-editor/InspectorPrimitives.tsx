// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-3023 — shared building blocks for the rule editor's right-side
// Inspector (pivt / Cases / Versions). One visual vocabulary across the three
// tabs, from the "Rules pivt Panel" design handoff, mapped onto the app's
// type scale: 11.5–12px body, 10.5px mono meta, 24–28px controls, single 1px
// borders, no icons in section headings.

import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

/** Mono count / status badge used after section and sub-tab labels. */
export function CountBadge({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center h-4 px-[5px] rounded-sm bg-foreground/[0.06] font-mono text-[10.5px] font-normal tracking-normal normal-case text-muted-foreground tabular-nums',
        className,
      )}
    >
      {children}
    </span>
  );
}

/** Mono uppercase label + optional badge + a 1px rule filling the row. */
export function SectionHeading({
  children,
  badge,
  className,
}: {
  children: ReactNode;
  badge?: ReactNode;
  /** Override the label color (pivt hint groups use semantic colors). */
  className?: string;
}) {
  return (
    <div className="flex items-center gap-2">
      <span
        className={cn(
          'font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] text-muted-foreground',
          className,
        )}
      >
        {children}
      </span>
      {badge != null && <CountBadge>{badge}</CountBadge>}
      <span aria-hidden className="flex-1 h-px bg-border" />
    </div>
  );
}

/** One-sentence helper copy under a heading. */
export function HelperText({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <p className={cn('text-[11.5px] leading-[16px] text-muted-foreground text-pretty', className)}>
      {children}
    </p>
  );
}

export interface SegmentOption<T extends string> {
  value: T;
  label: string;
  /** Optional 6px leading dot color (CSS color / var). */
  dot?: string;
}

/** Equal-width segmented control; a DetailCard usually sits directly under it. */
export function Segmented<T extends string>({
  value,
  options,
  onChange,
  disabled,
  ariaLabel,
}: {
  value: T;
  options: Array<SegmentOption<T>>;
  onChange: (value: T) => void;
  disabled?: boolean;
  ariaLabel?: string;
}) {
  return (
    <div
      role="radiogroup"
      aria-label={ariaLabel}
      className="grid gap-1 p-[3px] rounded-lg border border-input-border bg-input"
      style={{ gridTemplateColumns: `repeat(${options.length}, minmax(0, 1fr))` }}
    >
      {options.map((o) => {
        const selected = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={selected}
            disabled={disabled}
            onClick={() => onChange(o.value)}
            className={cn(
              'h-6 min-w-0 inline-flex items-center justify-center gap-1.5 rounded-[4px] text-[11.5px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60',
              selected
                ? 'bg-foreground/[0.09] text-foreground'
                : 'text-muted-foreground hover:text-foreground',
            )}
          >
            {o.dot && (
              <span aria-hidden className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: o.dot }} />
            )}
            <span className="truncate">{o.label}</span>
          </button>
        );
      })}
    </div>
  );
}

/** Bordered card that explains / configures the selected segment. */
export function DetailCard({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn('flex flex-col gap-2 p-3 rounded-lg border border-border bg-card', className)}>
      {children}
    </div>
  );
}

export function DetailCardTitle({ children }: { children: ReactNode }) {
  return <div className="text-[12px] font-medium text-foreground">{children}</div>;
}

/** Dashed empty-state box. */
export function EmptyState({ title, children }: { title: ReactNode; children?: ReactNode }) {
  return (
    <div className="flex flex-col gap-1 px-3 py-3 rounded-lg border border-dashed border-border-2">
      <div className="text-[12px] font-medium text-foreground">{title}</div>
      {children && <div className="text-[11.5px] leading-[16px] text-muted-foreground">{children}</div>}
    </div>
  );
}

/** Shared input chrome (select / text input / textarea) for the Inspector. */
export const inspectorInputClass =
  'w-full rounded-md border border-input-border bg-input text-[12px] text-foreground placeholder:text-fg-4 focus:outline-none focus:border-ai disabled:cursor-not-allowed disabled:opacity-60';

/** Secondary (outline) button — 24px, 11.5px. */
export const inspectorSecondaryButtonClass =
  'h-6 inline-flex items-center gap-1.5 px-2 rounded-md border border-border-2 bg-transparent text-[11.5px] font-medium text-foreground hover:bg-foreground/5 transition-colors disabled:opacity-50 disabled:pointer-events-none';
