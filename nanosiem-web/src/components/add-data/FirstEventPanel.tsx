// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * First-event confirmation (NAN-2599, design §3.3 "First-event panel"): after
 * the token is copied, a live checklist "credential issued → first event
 * received at the edge → searchable" with timestamps and elapsed times. It
 * polls the credential's activity (NAN-2598) until the first event is
 * searchable, and maps the edge's last refusal and any parse failures to
 * troubleshooting hints.
 */

import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Check, Circle, Info, Radio, Search } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';

import { api } from '@/lib/api';
import { formatTimeUTC } from '@/lib/date-utils';
import {
  FIRST_EVENT_POLL_MS,
  RECEIVED_TARGET_MS,
  SEARCHABLE_TARGET_MS,
  firstEventSteps,
  formatElapsed,
  troubleshootingHints,
  type FirstEventStep,
  type TroubleshootingHint,
} from '@/lib/first-event';
import { cn } from '@/lib/utils';

/** Stop polling a credential nobody has sent to after this long (resume with the button). */
const MAX_WAIT_MS = 30 * 60 * 1000;

function credentialActivityQueryKey(credentialId: string) {
  return ['ingest-credential-activity', credentialId] as const;
}

function StepIcon({ step }: { step: FirstEventStep }) {
  if (step.state === 'done') {
    return (
      <span className={cn('w-4 h-4 rounded-full inline-flex items-center justify-center border', step.overTarget ? 'border-amber-500/60 text-amber-500' : 'border-emerald-500/60 text-emerald-500')}>
        <Check className="w-2.5 h-2.5" strokeWidth={1.5} />
      </span>
    );
  }
  if (step.state === 'active') return <LoadingIcon className="w-4 h-4 text-primary" strokeWidth={1.5} />;
  return <Circle className="w-4 h-4 text-muted-foreground/40" strokeWidth={1.5} />;
}

function HintRow({ hint, parserHref }: { hint: TroubleshootingHint; parserHref?: string }) {
  const tone =
    hint.tone === 'error'
      ? 'border-red-500/40 bg-red-500/[0.04]'
      : hint.tone === 'warning'
        ? 'border-amber-500/40 bg-amber-500/[0.04]'
        : 'border-border';
  const Icon = hint.tone === 'info' ? Info : AlertTriangle;
  const iconTone = hint.tone === 'error' ? 'text-red-500' : hint.tone === 'warning' ? 'text-amber-500' : 'text-muted-foreground';
  return (
    <div className={cn('flex items-start gap-2 rounded-md border px-3 py-2', tone)} data-testid={`first-event-hint-${hint.id}`}>
      <Icon className={cn('w-3.5 h-3.5 mt-px shrink-0', iconTone)} strokeWidth={1.5} />
      <div className="text-[11px] leading-relaxed min-w-0">
        <div className="text-foreground font-medium">
          {hint.title}
          {hint.hecCode !== undefined && <span className="ml-1.5 font-mono text-[10.5px] text-muted-foreground">code {hint.hecCode}</span>}
        </div>
        <div className="text-muted-foreground">{hint.detail}</div>
        {hint.parserLink && parserHref && (
          <Link to={parserHref} className="text-primary hover:underline" data-testid="first-event-parser-link">
            Open the parser
          </Link>
        )}
      </div>
    </div>
  );
}

export function FirstEventPanel({
  credentialId,
  issuedAt,
  sourceSlugs,
  parserHref,
}: {
  credentialId: string;
  /** When the token was revealed (browser clock, ISO). */
  issuedAt: string;
  sourceSlugs: string[];
  /** Where "Open the parser" goes when the lake reports parse failures. */
  parserHref?: string;
}) {
  const [now, setNow] = useState(() => Date.now());
  const [waitFrom, setWaitFrom] = useState(() => new Date(issuedAt).getTime());
  const timedOut = now - waitFrom > MAX_WAIT_MS;

  const { data: activity, error, refetch } = useQuery({
    queryKey: credentialActivityQueryKey(credentialId),
    // One hour covers the first event; the counts shown are the first ones.
    queryFn: () => api.getIngestCredentialActivity(credentialId, 1),
    refetchInterval: (query) =>
      query.state.data?.first_event.state === 'searchable' || timedOut ? false : FIRST_EVENT_POLL_MS,
    refetchIntervalInBackground: true,
    retry: 1,
  });
  const searchable = activity?.first_event.state === 'searchable';

  // Tick the elapsed clocks while waiting.
  useEffect(() => {
    if (searchable || timedOut) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [searchable, timedOut]);

  const steps = useMemo(() => firstEventSteps(issuedAt, activity, now), [issuedAt, activity, now]);
  const hints = useMemo(
    () => troubleshootingHints(activity, now - new Date(issuedAt).getTime()),
    [activity, now, issuedAt],
  );
  const received = steps[1];
  const lake = activity?.lake;
  // `metadata.log_source` is the field Search scopes by on the lake.
  const firstSource = lake?.sources[0]?.source_slug ?? sourceSlugs[0];
  const searchQuery = firstSource ? `metadata.log_source="${firstSource}"` : '';

  return (
    <div className="rounded-md border border-border" data-testid="first-event-panel" role="region" aria-label="First event">
      <div className="flex items-center gap-2 px-3 h-8 border-b border-border">
        <Radio className="w-3.5 h-3.5 text-muted-foreground" strokeWidth={1.5} />
        <span className="text-[12px] font-medium text-foreground">
          {searchable ? 'First event is searchable' : 'Waiting for the first event'}
        </span>
        <span className="font-mono text-[10.5px] text-muted-foreground truncate">{sourceSlugs.join(', ')}</span>
        <span className="flex-1" />
        {!searchable && !timedOut && (
          <span className="font-mono text-[10.5px] text-muted-foreground/70" title={`Polling every ${FIRST_EVENT_POLL_MS / 1000} s`}>
            live
          </span>
        )}
      </div>

      <ol className="px-3 py-2 space-y-1" data-testid="first-event-steps">
        {steps.map((step) => (
          <li key={step.key} className="grid grid-cols-[16px_minmax(0,1fr)_auto_auto] items-center gap-2 h-6" data-testid={`first-event-step-${step.key}`} data-state={step.state}>
            <StepIcon step={step} />
            <span className={cn('text-[12px]', step.state === 'pending' ? 'text-muted-foreground' : 'text-foreground')}>{step.label}</span>
            <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums">{step.at ? formatTimeUTC(step.at) : ''}</span>
            <span
              className={cn('font-mono text-[10.5px] tabular-nums w-[88px] text-right', step.overTarget ? 'text-amber-500' : 'text-muted-foreground')}
              title={
                step.key === 'received'
                  ? `Target: ≤ ${RECEIVED_TARGET_MS / 1000} s after the first send`
                  : step.key === 'searchable'
                    ? `Target: ≤ ${SEARCHABLE_TARGET_MS / 60000} min after receipt`
                    : undefined
              }
            >
              {step.key === 'issued'
                ? ''
                : step.state === 'done'
                  ? `+${formatElapsed(step.elapsedMs)}`
                  : step.state === 'active' && step.key === 'searchable' && received.at
                    ? formatElapsed(now - new Date(received.at).getTime())
                    : step.state === 'active'
                      ? formatElapsed(now - new Date(issuedAt).getTime())
                      : ''}
            </span>
          </li>
        ))}
      </ol>

      {(activity?.edge || (lake && lake.events > 0)) && (
        <div className="flex flex-wrap gap-x-4 gap-y-1 px-3 pb-2 font-mono text-[10.5px] text-muted-foreground" data-testid="first-event-counts">
          {activity?.edge && (
            <span>
              edge <span className="text-foreground/80 tabular-nums">{activity.edge.events_24h.toLocaleString()}</span> events ·{' '}
              <span className="text-foreground/80 tabular-nums">{activity.edge.requests_24h.toLocaleString()}</span> requests
            </span>
          )}
          {lake && lake.events > 0 && (
            <span>
              lake <span className="text-foreground/80 tabular-nums">{lake.events.toLocaleString()}</span> events
              {lake.parse_failures > 0 && (
                <>
                  {' '}· <span className="text-amber-500 tabular-nums">{lake.parse_failures.toLocaleString()}</span> parse failures
                </>
              )}
            </span>
          )}
        </div>
      )}

      {(hints.length > 0 || error || timedOut || searchable) && (
        <div className="px-3 pb-3 space-y-2">
          {hints.map((hint) => (
            <HintRow key={hint.id} hint={hint} parserHref={parserHref} />
          ))}
          {error && (
            <div className="text-[11px] text-muted-foreground" role="status">
              Activity is unavailable right now; retrying.
            </div>
          )}
          {timedOut && !searchable && (
            <div className="flex items-center gap-2 text-[11px] text-muted-foreground" role="status">
              Stopped checking after 30 minutes.
              <button
                type="button"
                className="h-6 px-2 rounded border border-border text-[11px] text-foreground hover:bg-accent"
                onClick={() => {
                  setWaitFrom(Date.now());
                  setNow(Date.now());
                  void refetch();
                }}
              >
                Keep waiting
              </button>
            </div>
          )}
          {searchable && searchQuery && (
            <Link
              to={`/search?q=${encodeURIComponent(searchQuery)}`}
              className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md border border-border text-[11.5px] text-foreground hover:bg-accent"
              data-testid="first-event-search-link"
            >
              <Search className="w-3.5 h-3.5" strokeWidth={1.5} /> Search these events
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
