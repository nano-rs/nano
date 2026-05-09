// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-504 — small visual primitives shared across the redesigned Rule
// Repositories page. StatusChip / SeverityDot / FilterPills / Chk are lifted
// verbatim from design-ref/shadcn/repos-table.jsx.

import { useEffect, useRef } from 'react';
import { cn } from '@/lib/utils';
import type { CategoryCount, RepoRuleStatus, RepoSeverity } from './helpers';

interface StatusMeta {
  color: string;
  bg: string;
  label: string;
}

const STATUS_META: Record<RepoRuleStatus, StatusMeta> = {
  NEW: {
    color: 'var(--color-primary)',
    bg: 'color-mix(in srgb, var(--color-primary) 14%, transparent)',
    label: 'NEW',
  },
  UPDATED: {
    color: 'var(--color-warning)',
    bg: 'color-mix(in srgb, var(--color-warning) 14%, transparent)',
    label: 'UPDATED',
  },
  IMPORTED: {
    color: 'var(--color-success)',
    bg: 'color-mix(in srgb, var(--color-success) 14%, transparent)',
    label: 'IMPORTED',
  },
  DRIFT: {
    color: 'var(--color-destructive)',
    bg: 'color-mix(in srgb, var(--color-destructive) 14%, transparent)',
    label: 'DRIFT',
  },
  DELETED: {
    color: 'var(--color-muted-foreground)',
    bg: 'color-mix(in srgb, var(--color-muted-foreground) 14%, transparent)',
    label: 'DELETED',
  },
  AVAILABLE: {
    color: 'var(--color-foreground)',
    bg: 'color-mix(in srgb, var(--color-foreground) 6%, transparent)',
    label: 'AVAILABLE',
  },
};

export function StatusChip({ status, mini }: { status: RepoRuleStatus; mini?: boolean }) {
  const m = STATUS_META[status];
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md font-mono uppercase tracking-wider font-semibold',
        mini ? 'text-[9px] px-1 py-[1px]' : 'text-[9.5px] px-1.5 py-[2px]',
      )}
      style={{ color: m.color, background: m.bg }}
    >
      <span className="w-1 h-1 rounded-full" style={{ background: m.color }} />
      {m.label}
    </span>
  );
}

const SEV_COLOR: Record<RepoSeverity, string> = {
  critical: 'var(--color-destructive)',
  high: 'var(--color-destructive)',
  medium: 'var(--color-warning)',
  low: 'var(--color-success)',
  unknown: 'var(--color-muted-foreground)',
};

export function SeverityDot({ sev }: { sev: RepoSeverity }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[10px] font-mono tabular-nums text-muted-foreground">
      <span className="w-[7px] h-[7px] rounded-full" style={{ background: SEV_COLOR[sev] }} />
      {sev}
    </span>
  );
}

export function FilterPills({
  categories,
  activeId,
  onActivate,
}: {
  categories: CategoryCount[];
  activeId: CategoryCount['id'];
  onActivate: (id: CategoryCount['id']) => void;
}) {
  return (
    <div className="flex items-center gap-1 flex-wrap">
      {categories.map((c) => {
        const active = activeId === c.id;
        return (
          <button
            key={c.id}
            type="button"
            onClick={() => onActivate(c.id)}
            className={cn(
              'h-[26px] px-2.5 rounded-md text-[11.5px] border transition flex items-center gap-1.5',
              active
                ? 'border-primary/40 bg-primary/10 text-primary'
                : 'border-border bg-card hover:border-border/80 text-foreground/70 hover:text-foreground',
            )}
          >
            {c.label}
            <span
              className={cn(
                'font-mono text-[10px] tabular-nums rounded px-[5px] py-[1px]',
                active ? 'bg-primary/15 text-primary' : 'bg-foreground/5 text-muted-foreground',
              )}
            >
              {c.count}
            </span>
          </button>
        );
      })}
    </div>
  );
}

interface ChkProps {
  checked?: boolean;
  indeterminate?: boolean;
  disabled?: boolean;
  onChange?: () => void;
  ariaLabel?: string;
}

export function Chk({ checked, indeterminate, disabled, onChange, ariaLabel }: ChkProps) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = !!indeterminate;
  }, [indeterminate]);
  return (
    <label
      className={cn(
        'inline-flex items-center justify-center',
        disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer',
      )}
    >
      <input
        ref={ref}
        type="checkbox"
        checked={checked || false}
        onChange={onChange || (() => {})}
        disabled={disabled}
        aria-label={ariaLabel}
        className="sr-only peer"
      />
      <span
        className={cn(
          'w-[14px] h-[14px] rounded-[3px] border flex items-center justify-center transition-colors shrink-0',
          checked || indeterminate
            ? 'bg-primary border-primary'
            : 'border-muted-foreground/50 hover:border-foreground/70 bg-card',
        )}
      >
        {indeterminate ? (
          <svg
            viewBox="0 0 14 14"
            className="w-[10px] h-[10px]"
            fill="none"
            stroke="var(--color-brand-ink)"
            strokeWidth="2.5"
            strokeLinecap="round"
          >
            <path d="M3 7h8" />
          </svg>
        ) : checked ? (
          <svg
            viewBox="0 0 14 14"
            className="w-[10px] h-[10px]"
            fill="none"
            stroke="var(--color-brand-ink)"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M3 7.5l3 3 5.5-6" />
          </svg>
        ) : null}
      </span>
    </label>
  );
}
