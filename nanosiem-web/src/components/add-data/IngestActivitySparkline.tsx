// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Hourly events for one log source over the last 24 h, with parse failures
 * highlighted (NAN-2599, LogSourceDetail on hosted-shared). From
 * `GET /api/log-sources/{id}/stats` (the lake's per-source counters, ≤2 min
 * fresh), which already applies the caller's source visibility.
 */

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Rss } from 'lucide-react';

import { api } from '@/lib/api';
import { formatCompactNumber } from '@/lib/date-utils';
import { refusalCause, hasRefusals } from '@/lib/ingest-refusal';
import { hourlyBuckets } from '@/lib/ingest-activity';
import { cn } from '@/lib/utils';

function hourLabel(t: number): string {
  return `${new Date(t).toISOString().slice(11, 16)}Z`;
}

/**
 * `embedded` (NAN-3297) renders as a borderless section of a parent card — a
 * top rule instead of its own rounded card, with a shorter chart — so it can
 * sit under the metadata rows of LogSourceDetail's About panel.
 */
export function IngestActivitySparkline({
  logSourceId,
  hours = 24,
  embedded = false,
}: {
  logSourceId: string;
  hours?: number;
  embedded?: boolean;
}) {
  const { data: stats, error } = useQuery({
    queryKey: ['log-source-stats', logSourceId, hours],
    queryFn: () => api.getLogSourceStats(logSourceId, hours),
    refetchInterval: 60_000,
    retry: 1,
  });
  const buckets = useMemo(() => hourlyBuckets(stats?.points ?? [], hours, Date.now()), [stats, hours]);
  const max = Math.max(1, ...buckets.map((b) => b.events));
  const totalFailures = stats?.total_parse_failures ?? 0;
  // NAN-3680: rows the lake refused at OCSF admission (absent = not recorded).
  const totalRefused = stats?.total_refused_events;
  const refusedCause = refusalCause(stats?.last_refusal);

  const shell = embedded ? 'min-w-0 border-t border-border' : 'rounded-md border border-border bg-card min-w-0';
  const chartH = embedded ? 64 : 96;
  const header = (
    <div className={cn('flex flex-wrap items-center gap-x-2.5 gap-y-1 px-4 border-b border-border', embedded ? 'py-1.5' : 'py-2')}>
      <span className="font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Ingest</span>
      <span className="text-[12px] font-semibold text-foreground">Events per hour</span>
      <span className="font-mono text-[10.5px] text-muted-foreground">· {hours}h</span>
      <span className="flex-1" />
      {stats && (
        <span className="font-mono text-[10.5px] text-muted-foreground" data-testid="ingest-sparkline-totals">
          <span className="text-foreground tabular-nums">{formatCompactNumber(stats.total_events)}</span> events
          {totalFailures > 0 && (
            <>
              {' '}· <span className="text-amber-500 tabular-nums">{formatCompactNumber(totalFailures)}</span> parse failures
            </>
          )}
          {hasRefusals(totalRefused) && (
            <span data-testid="ingest-sparkline-refused" title={`${totalRefused.toLocaleString()} events refused by OCSF validation${refusedCause ? ` (${refusedCause})` : ''}`}>
              {' '}· <span className="text-red-500 tabular-nums">{formatCompactNumber(totalRefused)}</span> refused
              {refusedCause && <> ({refusedCause})</>}
            </span>
          )}
        </span>
      )}
    </div>
  );

  if (error) {
    return (
      <div className={shell} data-testid="ingest-sparkline">
        {header}
        <div className="px-4 py-6 text-[11.5px] text-muted-foreground">Ingest activity is unavailable for this source.</div>
      </div>
    );
  }
  if (stats && !stats.observed) {
    return (
      <div className={shell} data-testid="ingest-sparkline">
        {header}
        <div className="flex items-center gap-2 px-4 py-6 text-[11.5px] text-muted-foreground">
          <Rss className="w-4 h-4 opacity-50" strokeWidth={1.5} />
          {stats.verdict?.detail ?? 'No events admitted in the window.'}
        </div>
      </div>
    );
  }

  const W = 24 * 20;
  const H = chartH;
  const slot = W / buckets.length;
  const bar = Math.max(1, slot - 3);
  return (
    <div className={shell} data-testid="ingest-sparkline">
      {header}
      <div className={embedded ? 'px-4 py-3' : 'p-4'}>
        <svg viewBox={`0 0 ${W} ${H}`} style={{ height: H }} className="w-full border-b border-border" preserveAspectRatio="none" role="img" aria-label="Events per hour">
          {buckets.map((b, i) => {
            const h = b.events > 0 ? Math.max(1, (b.events / max) * (H - 2)) : 0;
            const fh = b.events > 0 ? Math.max(b.parseFailures > 0 ? 1.5 : 0, (b.parseFailures / b.events) * h) : 0;
            const x = i * slot + 1;
            return (
              <g key={b.hour} data-testid="ingest-sparkline-bar" data-failures={b.parseFailures}>
                <title>
                  {`${hourLabel(b.hour)} · ${b.events.toLocaleString()} events${b.parseFailures > 0 ? ` · ${b.parseFailures.toLocaleString()} parse failures` : ''}`}
                </title>
                {b.parseFailures > 0 && <rect x={x - 1} y={0} width={slot} height={H} fill="rgb(245 158 11)" fillOpacity={0.08} />}
                <rect x={x} y={H - h} width={bar} height={h} fill="var(--primary)" fillOpacity={0.75} />
                {fh > 0 && <rect x={x} y={H - h} width={bar} height={fh} fill="rgb(239 68 68)" fillOpacity={0.9} />}
                {b.events === 0 && <rect x={x} y={H - 1} width={bar} height={1} fill="var(--border)" />}
              </g>
            );
          })}
        </svg>
        <div className="mt-1.5 flex justify-between font-mono text-[10.5px] text-muted-foreground/70 tabular-nums">
          <span>{hourLabel(buckets[0].hour)}</span>
          <span className={cn(totalFailures > 0 && 'text-amber-500')}>
            {totalFailures > 0 ? 'red = parse failures' : `peak ${formatCompactNumber(max)} / h`}
          </span>
          <span>{hourLabel(buckets[buckets.length - 1].hour)}</span>
        </div>
      </div>
    </div>
  );
}
