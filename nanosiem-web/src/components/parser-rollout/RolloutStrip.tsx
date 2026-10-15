// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Parser-bundle rollout status strip (hosted-shared, NAN-2607, design §7.6):
 * Queued → Building → Validated → Rolling out → Live, or Failed (stage,
 * component and Vector's message) / Rolled back. Polls the rollout while it
 * moves; the tenant's parser cell keeps serving the previous bundle until the
 * new one is live.
 */

import { useEffect, useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Check, RotateCcw, Undo2, X } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { api } from '@/lib/api';
import type { TenantParserRollout } from '@/lib/api/types';
import {
  PARSER_ROLLOUT_QUERY_KEY,
  ROLLOUT_STEPS,
  clockTime,
  failureStageLabel,
  formatStageTimings,
  rolloutBatchInfo,
  rolloutPollInterval,
  rolloutStateLabel,
  rolloutStepIndex,
  shortSha,
} from '@/lib/parser-rollout';
import { cn } from '@/lib/utils';

const KIND_LABEL: Record<string, string> = { publish: 'publish', revert: 'revert', merge_base: 'platform merge' };

/** Poll one rollout by id and render it. `initial` (from the deploy/publish response) avoids a blank first frame. */
export function RolloutStatus({
  rolloutId,
  initial,
  onRetry,
  retrying,
  compact,
}: {
  rolloutId: string;
  initial?: TenantParserRollout | null;
  onRetry?: () => void;
  retrying?: boolean;
  compact?: boolean;
}) {
  const query = useQuery({
    queryKey: PARSER_ROLLOUT_QUERY_KEY(rolloutId),
    queryFn: () => api.getParserRollout(rolloutId),
    initialData: initial && initial.id === rolloutId ? initial : undefined,
    refetchInterval: (q) => rolloutPollInterval(q.state.data),
  });
  if (!query.data) {
    return (
      <div className="flex items-center gap-2 h-8 px-3 rounded-md border border-border text-[12px] text-muted-foreground" data-testid="rollout-strip-loading">
        <LoadingIcon className="h-3.5 w-3.5" strokeWidth={1.5} />
        {query.isError ? 'Rollout status unavailable' : 'Loading rollout…'}
      </div>
    );
  }
  return <RolloutStrip rollout={query.data} onRetry={onRetry} retrying={retrying} compact={compact} />;
}

/**
 * Publish coalescing (design §7.6): a queued publish/revert waits for the
 * tenant's batch window so every change in it ships in one parser roll.
 */
function RolloutBatchNote({ rollout }: { rollout: TenantParserRollout }) {
  const [now, setNow] = useState(() => Date.now());
  const info = rolloutBatchInfo(rollout, now);
  const ticking = info !== null && info.secondsLeft > 0;
  useEffect(() => {
    if (!ticking) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [ticking]);
  if (!info) return null;
  return (
    <span className="text-foreground/80" data-testid="rollout-batch">
      Queued ·{' '}
      {info.others > 0 ? (
        <>
          rolls with <span className="font-mono text-foreground tabular-nums">{info.others}</span> other{' '}
          {info.others === 1 ? 'change' : 'changes'} after{' '}
        </>
      ) : (
        <>
          batching changes for up to <span className="font-mono tabular-nums">{info.windowSeconds}</span> s, rolls after{' '}
        </>
      )}
      <span className="font-mono text-foreground tabular-nums" title={info.rollsAfter.toISOString()}>
        {clockTime(info.rollsAfter)}
      </span>
      {info.secondsLeft > 0 && <span className="font-mono tabular-nums"> ({info.secondsLeft}s)</span>}
    </span>
  );
}

type StepStatus = 'done' | 'active' | 'failed' | 'rolled_back' | 'pending';

function StepDot({ status }: { status: StepStatus }) {
  const base = 'h-4 w-4 flex-none rounded-full inline-flex items-center justify-center';
  switch (status) {
    case 'done':
      return (
        <span className={cn(base, 'bg-emerald-500 text-background')}>
          <Check className="h-2.5 w-2.5" strokeWidth={3} />
        </span>
      );
    case 'active':
      return (
        <span className={cn(base, 'border-2 border-amber-500')}>
          <span className="h-1.5 w-1.5 rounded-full bg-amber-500 animate-pulse" />
        </span>
      );
    case 'failed':
      return (
        <span className={cn(base, 'bg-red-500 text-background')}>
          <X className="h-2.5 w-2.5" strokeWidth={3} />
        </span>
      );
    case 'rolled_back':
      return (
        <span className={cn(base, 'bg-red-500 text-background')}>
          <Undo2 className="h-2.5 w-2.5" strokeWidth={2.5} />
        </span>
      );
    default:
      return <span className={cn(base, 'border-[1.5px] border-muted-foreground/40')} />;
  }
}

/** Pure rendering of one rollout. */
export function RolloutStrip({
  rollout,
  onRetry,
  retrying,
  compact,
  bare,
  eyebrow = 'Parser rollout',
  action,
}: {
  rollout: TenantParserRollout;
  onRetry?: () => void;
  retrying?: boolean;
  compact?: boolean;
  /** Drop the outer border (the caller's panel provides it). */
  bare?: boolean;
  /** Header label; the log source page calls it "Parser cell rollout". */
  eyebrow?: string;
  /** Extra header controls (e.g. "Revert to vN"). */
  action?: ReactNode;
}) {
  const current = rolloutStepIndex(rollout);
  const failed = rollout.state === 'failed';
  const rolledBack = rollout.state === 'rolled_back';
  const bad = failed || rolledBack;
  const live = rollout.state === 'live';
  const timings = formatStageTimings(rollout.stage_timings);
  const stage = failureStageLabel(rollout.failure_stage);
  const queued = rolloutBatchInfo(rollout, Date.now()) !== null;
  const keepServing = !compact && !bad && !live;
  const pad = compact ? 'px-3' : 'px-4';

  return (
    <div
      className={cn(!bare && 'rounded-md border border-border bg-card')}
      data-testid="rollout-strip"
      data-state={rollout.state}
    >
      <div className={cn('flex flex-wrap items-center gap-x-2.5 gap-y-1 border-b border-border', pad, 'py-2')}>
        <span className="font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{eyebrow}</span>
        <span className="text-[12px] font-semibold text-foreground">
          {KIND_LABEL[rollout.kind] ?? rollout.kind}
        </span>
        <span className="flex-1" />
        {rollout.bundle_revision != null && (
          <span className="font-mono text-[10.5px] text-muted-foreground" title={rollout.content_sha256 ?? undefined}>
            bundle r{rollout.bundle_revision}
            {rollout.content_sha256 ? ` · ${shortSha(rollout.content_sha256)}` : ''}
          </span>
        )}
        <span
          className={cn(
            'inline-flex items-center h-5 px-1.5 rounded-[3px] font-mono text-[10.5px] font-semibold uppercase tracking-[0.08em]',
            live && 'text-emerald-500 bg-emerald-500/10',
            bad && 'text-red-500 bg-red-500/10',
            !live && !bad && 'text-amber-500 bg-amber-500/10',
          )}
          data-testid="rollout-state"
        >
          {rolloutStateLabel(rollout.state)}
        </span>
        {action}
      </div>

      <ol
        className={cn('flex flex-wrap items-center gap-x-2.5 gap-y-2', pad, compact ? 'py-2.5' : 'py-3')}
        aria-label="Rollout progress"
      >
        {ROLLOUT_STEPS.map((step, i) => {
          const done = live ? true : i < current;
          const active = !live && i === current;
          const stopped = active && bad;
          const last = i === ROLLOUT_STEPS.length - 1;
          const status: StepStatus = done
            ? 'done'
            : stopped
              ? rolledBack
                ? 'rolled_back'
                : 'failed'
              : active
                ? 'active'
                : 'pending';
          return (
            <li
              key={step}
              className={cn('flex items-center gap-2.5 min-w-0', last ? 'flex-none' : compact ? 'flex-[1_1_90px]' : 'flex-[1_1_120px]')}
              aria-current={active ? 'step' : undefined}
            >
              <StepDot status={status} />
              <span
                className={cn(
                  'whitespace-nowrap',
                  'text-[11.5px]',
                  active ? 'font-semibold' : 'font-medium',
                  done && 'text-foreground',
                  active && !stopped && 'text-amber-500',
                  stopped && 'text-red-500',
                  !done && !active && 'text-muted-foreground',
                )}
              >
                {rolloutStateLabel(step)}
              </span>
              {!last && <span className={cn('h-px min-w-4 flex-1', done ? 'bg-emerald-500/70' : 'bg-border')} />}
            </li>
          );
        })}
      </ol>

      {(queued || keepServing) && (
        <div className={cn('flex flex-wrap gap-x-5 gap-y-1.5 text-[11.5px] leading-[18px] text-muted-foreground', pad, 'pb-3 -mt-1')}>
          <RolloutBatchNote rollout={rollout} />
          {keepServing && <span>Rolling out to your parser cell. The current parser keeps serving until the new bundle is live.</span>}
        </div>
      )}

      {bad && (
        <div className={cn('border-t border-border space-y-2.5', pad, 'py-2.5')} data-testid="rollout-failure">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11.5px]">
            <span className="font-medium text-red-500">
              {rolledBack ? 'Rolled back: your parser cell stayed on the previous bundle' : 'Build failed: nothing was rolled out'}
            </span>
            {stage && (
              <span className="font-mono text-[11.5px] text-muted-foreground" data-testid="rollout-failure-stage">
                stage {stage}
              </span>
            )}
            {rollout.failure_component && (
              <span className="font-mono text-[11.5px] text-foreground" data-testid="rollout-failure-component">
                {rollout.failure_component}
              </span>
            )}
          </div>
          {rollout.failure_reason && (
            <pre
              className="max-h-40 overflow-auto rounded-[3px] border border-red-500/20 bg-red-500/[0.06] px-2.5 py-1.5 font-mono text-[12px] leading-[17px] text-red-700 dark:text-red-300 whitespace-pre-wrap break-words"
              data-testid="rollout-failure-message"
            >
              {rollout.failure_reason}
            </pre>
          )}
          {onRetry && (
            <button
              type="button"
              onClick={onRetry}
              disabled={retrying}
              className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md border border-border text-[11.5px] font-medium hover:bg-muted disabled:opacity-50"
            >
              {retrying ? <LoadingIcon className="h-3.5 w-3.5" strokeWidth={1.5} /> : <RotateCcw className="h-3.5 w-3.5" strokeWidth={1.5} />}
              Retry rollout
            </button>
          )}
        </div>
      )}

      {!compact && timings.length > 0 && (
        <div className={cn('flex flex-wrap gap-x-4 gap-y-1 border-t border-border py-2.5', pad)} data-testid="rollout-timings">
          {timings.map(([label, value]) => (
            <span key={label} className="font-mono text-[11.5px] text-muted-foreground">
              {label} <span className="text-foreground">{value}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
