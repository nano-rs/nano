// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-526 — small visual primitives for the redesigned Parser Repositories
// page. Lifted in spirit from rule-repositories `chips.tsx` plus the
// CategoryChip / TransportChip from design-ref/shadcn/log-repos-table.jsx.

import { useEffect, useRef } from 'react';
import { Database, Download, GitBranch, Link as LinkIcon, Package, Tally1 } from 'lucide-react';
import { cn } from '@/lib/utils';
import type {
  CategoryCount,
  RepoParserStatus,
  RepoTransport,
} from './helpers';

// ------------------------------------------------------------------
// Status chip
// ------------------------------------------------------------------

interface StatusMeta {
  color: string;
  bg: string;
  label: string;
}

const STATUS_META: Record<RepoParserStatus, StatusMeta> = {
  AVAILABLE: {
    color: 'var(--color-foreground)',
    bg: 'color-mix(in srgb, var(--color-foreground) 6%, transparent)',
    label: 'AVAILABLE',
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
};

export function StatusChip({ status, mini }: { status: RepoParserStatus; mini?: boolean }) {
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

// ------------------------------------------------------------------
// Category chip — colored to match the mock palette
// ------------------------------------------------------------------

const CATEGORY_COLORS: Record<string, string> = {
  cloud: 'oklch(72% 0.13 240)',
  security: 'oklch(72% 0.14 290)',
  network: 'oklch(72% 0.13 180)',
  endpoint: 'oklch(72% 0.13 60)',
  web: 'oklch(72% 0.13 140)',
  identity: 'oklch(72% 0.14 320)',
  database: 'oklch(72% 0.13 30)',
  application: 'oklch(72% 0.13 100)',
};

export function CategoryChip({ cat }: { cat: string | null | undefined }) {
  if (!cat) return null;
  const color = CATEGORY_COLORS[cat.toLowerCase()] || 'var(--color-muted-foreground)';
  return (
    <span
      className="inline-flex items-center gap-1 rounded-md font-mono uppercase tracking-wider text-[9px] px-1.5 py-[1.5px] border"
      style={{
        color,
        borderColor: `color-mix(in srgb, ${color} 30%, transparent)`,
        background: `color-mix(in srgb, ${color} 8%, transparent)`,
      }}
    >
      {cat}
    </span>
  );
}

// ------------------------------------------------------------------
// Transport chip
// ------------------------------------------------------------------

const TRANSPORT_META: Record<RepoTransport, { Icon: typeof Database; label: string }> = {
  http: { Icon: LinkIcon, label: 'HTTP' },
  vector: { Icon: Tally1, label: 'Vector' },
  s3: { Icon: Database, label: 'S3' },
  pubsub: { Icon: Download, label: 'Pub/Sub' },
  syslog: { Icon: GitBranch, label: 'Syslog' },
  kafka: { Icon: Tally1, label: 'Kafka' },
  splunk_hec: { Icon: Package, label: 'Splunk HEC' },
};

export function TransportChip({ t }: { t: RepoTransport | null | undefined }) {
  if (!t) return null;
  const meta = TRANSPORT_META[t] ?? { Icon: Package, label: String(t) };
  const Icon = meta.Icon;
  return (
    <span className="inline-flex items-center gap-1 font-mono text-[10.5px] text-foreground/70 border border-border rounded px-1.5 py-[1.5px] bg-background">
      <Icon className="w-[9px] h-[9px] text-muted-foreground" strokeWidth={1.5} />
      {meta.label}
    </span>
  );
}

// ------------------------------------------------------------------
// Filter pills
// ------------------------------------------------------------------

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

// ------------------------------------------------------------------
// Checkbox
// ------------------------------------------------------------------

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
