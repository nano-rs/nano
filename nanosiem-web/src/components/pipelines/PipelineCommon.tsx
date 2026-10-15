// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ReactNode } from 'react';
import { AlertCircle, CheckCircle2, Clock, Info, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

export function PipelineNotice({
  title,
  children,
  tone = 'neutral',
}: {
  title: string;
  children?: ReactNode;
  tone?: 'neutral' | 'error' | 'warning';
}) {
  return (
    <div
      role={tone === 'error' ? 'alert' : 'status'}
      className={cn(
        'flex gap-2 rounded-md border px-3 py-2 text-[11.5px]',
        tone === 'error'
          ? 'border-destructive/30 bg-destructive/5'
          : tone === 'warning'
            ? 'border-warning/30 bg-warning/5'
            : 'border-border bg-card'
      )}
    >
      {tone === 'error' ? (
        <AlertCircle
          className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive"
          strokeWidth={1.5}
        />
      ) : (
        <Info
          className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground"
          strokeWidth={1.5}
        />
      )}
      <div className="min-w-0">
        <p className="font-medium text-foreground">{title}</p>
        {children && (
          <div className="mt-0.5 text-muted-foreground">{children}</div>
        )}
      </div>
    </div>
  );
}

export function PipelineStateBadge({ state }: { state: string }) {
  const live = state === 'live' || state === 'healthy' || state === 'validated';
  const failed = [
    'failed',
    'rejected',
    'invalid',
    'error',
    'delivery_errors',
  ].includes(state);
  const pending = [
    'pending',
    'building',
    'rolling_out',
    'running',
    'capturing',
    'connecting',
  ].includes(state);
  const Icon = pending
    ? Loader2
    : live
      ? CheckCircle2
      : failed
        ? AlertCircle
        : Clock;
  return (
    <span
      className={cn(
        'inline-flex h-5 items-center gap-1 rounded-sm border px-1.5 text-[10.5px]',
        live
          ? 'border-success/20 bg-success/10 text-success'
          : failed
            ? 'border-destructive/20 bg-destructive/10 text-destructive'
            : 'border-border bg-card text-muted-foreground'
      )}
    >
      <Icon
        className={cn('h-3 w-3', pending && 'animate-spin')}
        strokeWidth={1.5}
        aria-hidden="true"
      />
      {state.replaceAll('_', ' ')}
    </span>
  );
}

export function PipelinePageHeader({
  title,
  meta,
  actions,
}: {
  title: string;
  meta?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="shrink-0 border-b border-border bg-background px-4 pb-3 pt-3">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="mr-auto text-[16px] font-semibold tracking-[-0.01em]">
          {title}
        </h1>
        {actions}
      </div>
      {meta && (
        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10.5px] text-muted-foreground">
          {meta}
        </div>
      )}
    </header>
  );
}

export function JsonInspector({
  value,
  empty = 'Select an event to inspect it.',
}: {
  value: unknown;
  empty?: string;
}) {
  if (value === undefined)
    return <p className="p-3 text-[11.5px] text-muted-foreground">{empty}</p>;
  return (
    <pre className="overflow-auto whitespace-pre-wrap break-all p-3 font-mono text-[11px] leading-5 text-foreground">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function PipelineLoading({
  label = 'Loading pipelines…',
}: {
  label?: string;
}) {
  return (
    <div
      role="status"
      className="flex items-center gap-2 p-4 text-[12px] text-muted-foreground"
    >
      <Loader2 className="h-3.5 w-3.5 animate-spin" strokeWidth={1.5} />
      {label}
    </div>
  );
}

export function PipelineField({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <label className="block text-[11px] font-medium text-muted-foreground">
      <span className="mb-1 block">{label}</span>
      {children}
      {hint && (
        <span className="mt-1 block text-[10.5px] font-normal">{hint}</span>
      )}
    </label>
  );
}
