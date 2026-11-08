// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ReactNode } from 'react';
import { Check } from 'lucide-react';

import { cn } from '@/lib/utils';

export type ConnectStepState = 'active' | 'done' | 'locked' | 'warn' | 'error';

const MARK_TONE: Record<ConnectStepState, string> = {
  active: 'border-primary/60 text-primary',
  done: 'border-emerald-500/60 text-emerald-500',
  locked: 'border-border text-muted-foreground/60',
  warn: 'border-amber-500/60 text-amber-500',
  error: 'border-red-500/60 text-red-500',
};

const STATUS_TONE: Record<ConnectStepState, string> = {
  active: 'text-foreground/80',
  done: 'text-emerald-500',
  locked: 'text-muted-foreground/60',
  warn: 'text-amber-500',
  error: 'text-red-500',
};

/** One numbered row of the Connect sequence: credential → send → first events. */
export function ConnectStep({
  n,
  title,
  state,
  status,
  testId,
  children,
}: {
  n: number;
  title: string;
  state: ConnectStepState;
  status: string;
  testId: string;
  children: ReactNode;
}) {
  return (
    <li className="rounded-md border border-border" data-testid={testId} data-state={state}>
      <div className="flex items-center gap-2 px-3 h-7 border-b border-border/60">
        <span className={cn('w-4 h-4 shrink-0 inline-flex items-center justify-center rounded-sm border font-mono text-[10px] tabular-nums', MARK_TONE[state])}>
          {state === 'done' ? <Check className="w-2.5 h-2.5" strokeWidth={1.5} /> : n}
        </span>
        <span className={cn('text-[12px] font-medium', state === 'locked' ? 'text-muted-foreground' : 'text-foreground')}>{title}</span>
        <span className="flex-1" />
        <span className={cn('font-mono text-[10.5px]', STATUS_TONE[state])} data-testid={`${testId}-status`}>{status}</span>
      </div>
      <div className="px-3 py-2 space-y-2">{children}</div>
    </li>
  );
}
