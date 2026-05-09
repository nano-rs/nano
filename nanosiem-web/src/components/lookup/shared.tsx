// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-509 — shared atoms for the Lookup Tables redesign.
// Ports `design-ref/shadcn/lookup-shared.jsx` to the real app's tokens
// (`var(--primary)`/`var(--warning)`/`var(--success)` instead of brand/warn/good).

import { useMemo, useState } from 'react';
import { ArrowUpRight, Download, Pencil } from 'lucide-react';
import { cn } from '@/lib/utils';

// --------------------------------------------------------------------
// Type chips — mirrors LOOKUP_TYPES from the mockup. Used wherever a
// column's data type needs to be surfaced (schema view, type picker,
// upload preview type confirmation).
// --------------------------------------------------------------------

export type LookupColumnType =
  | 'string' | 'int' | 'float' | 'bool' | 'ip' | 'cidr'
  | 'enum' | 'ts' | 'email' | 'url';

interface TypeMeta {
  label: string;
  hint: string;
  tone: 'neutral' | 'primary' | 'warning' | 'success';
}

const TYPE_META: Record<LookupColumnType, TypeMeta> = {
  string: { label: 'string', hint: 'free text',     tone: 'neutral' },
  int:    { label: 'int',    hint: 'integer',       tone: 'primary' },
  float:  { label: 'float',  hint: 'decimal',       tone: 'primary' },
  bool:   { label: 'bool',   hint: 'true / false',  tone: 'primary' },
  ip:     { label: 'ip',     hint: 'IPv4 / IPv6',   tone: 'warning' },
  cidr:   { label: 'cidr',   hint: 'IP block',      tone: 'warning' },
  enum:   { label: 'enum',   hint: 'fixed set',     tone: 'success' },
  ts:     { label: 'ts',     hint: 'timestamp',     tone: 'neutral' },
  email:  { label: 'email',  hint: 'user@host',     tone: 'neutral' },
  url:    { label: 'url',    hint: 'http(s)',       tone: 'neutral' },
};

const TONE_CLASS = {
  neutral: 'text-foreground/80 bg-foreground/[0.06] border-border',
  primary: 'text-primary bg-primary/10 border-primary/30',
  warning: 'text-[var(--warning)] bg-[color-mix(in_srgb,var(--warning)_10%,transparent)] border-[color-mix(in_srgb,var(--warning)_30%,transparent)]',
  success: 'text-[var(--success)] bg-[color-mix(in_srgb,var(--success)_10%,transparent)] border-[color-mix(in_srgb,var(--success)_30%,transparent)]',
} as const;

export function metaForType(type: string): TypeMeta {
  return (TYPE_META as Record<string, TypeMeta | undefined>)[type] ?? {
    label: type || 'unknown',
    hint: '',
    tone: 'neutral',
  };
}

export const LOOKUP_TYPES: ReadonlyArray<{ id: LookupColumnType; meta: TypeMeta }> = (
  Object.keys(TYPE_META) as LookupColumnType[]
).map((id) => ({ id, meta: TYPE_META[id] }));

interface TypeChipProps {
  type: string;
  size?: 'sm' | 'md';
  onClick?: () => void;
  className?: string;
}

export function TypeChip({ type, size = 'sm', onClick, className }: TypeChipProps) {
  const meta = metaForType(type);
  const cls = cn(
    'inline-flex items-center gap-1 rounded-sm border font-mono leading-none tracking-[-0.01em]',
    TONE_CLASS[meta.tone],
    size === 'sm'
      ? 'text-[9.5px] px-1 py-[1px] h-[15px]'
      : 'text-[10.5px] px-1.5 py-[2px] h-[18px]',
    onClick && 'hover:brightness-125 cursor-pointer transition',
    className,
  );
  if (onClick) {
    return <button type="button" className={cls} onClick={onClick}>{meta.label}</button>;
  }
  return <span className={cls}>{meta.label}</span>;
}

// --------------------------------------------------------------------
// Source tag — distinguishes how a table was populated (file upload,
// schema definition, URL ingestion).
// --------------------------------------------------------------------

export type LookupSource = 'upload' | 'define' | 'url';

const SOURCE_META: Record<LookupSource, { label: string; Icon: typeof Download; tone: string }> = {
  upload: { label: 'upload', Icon: Download,      tone: 'text-primary' },
  define: { label: 'define', Icon: Pencil,        tone: 'text-[var(--warning)]' },
  url:    { label: 'url',    Icon: ArrowUpRight,  tone: 'text-[var(--success)]' },
};

export function SourceTag({
  source,
  className,
}: {
  source: LookupSource | string;
  className?: string;
}) {
  const meta = SOURCE_META[source as LookupSource] ?? SOURCE_META.define;
  const Icon = meta.Icon;
  return (
    <span className={cn('inline-flex items-center gap-1 font-mono text-[10.5px] text-muted-foreground', className)}>
      <Icon className={cn('w-[11px] h-[11px]', meta.tone)} strokeWidth={2} />
      <span>{meta.label}</span>
    </span>
  );
}

// --------------------------------------------------------------------
// Type picker — small popover that opens a list of available types.
// Pure-CSS click-outside; intentionally lightweight (no Radix Popover)
// because this lives inside dense table cells where stacking-context
// noise from a portal would be more trouble than it's worth.
// --------------------------------------------------------------------

interface TypePickerProps {
  value: string;
  onChange: (type: LookupColumnType) => void;
  disabled?: boolean;
}

export function TypePicker({ value, onChange, disabled }: TypePickerProps) {
  const [open, setOpen] = useState(false);
  const types = useMemo(() => LOOKUP_TYPES, []);
  return (
    <div className="relative inline-block">
      <button
        type="button"
        onClick={() => !disabled && setOpen((o) => !o)}
        disabled={disabled}
        className="disabled:opacity-50"
      >
        <TypeChip type={value} size="md" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div
            className="absolute top-full left-0 mt-1 z-50 w-[200px] rounded-md border border-border bg-card py-1"
            style={{ boxShadow: '0 12px 40px color-mix(in srgb, var(--foreground) 20%, transparent)' }}
          >
            {types.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => { onChange(t.id); setOpen(false); }}
                className={cn(
                  'w-full px-2 py-1.5 flex items-center gap-2 hover:bg-foreground/5',
                  value === t.id && 'bg-primary/10',
                )}
              >
                <TypeChip type={t.id} size="md" />
                <span className="text-[10.5px] text-muted-foreground font-mono">{t.meta.hint}</span>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
