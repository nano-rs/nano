// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useEffect, useMemo } from 'react';
import { X, Clock, CalendarRange, CircleCheck, Rows3, Crosshair, Timer, Terminal } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { formatCompactNumber } from '@/lib/date-utils';
import { useLayoutOptional } from '@/contexts/LayoutContext';
import type { SearchJobProgress } from '@/lib/api/types';
import { backgroundJobPhaseLabel, coldScanLabel, hasMeasuredProgress, isColdScanProgress } from '@/lib/cold-scan-progress';

interface SearchStatsBarProps {
  isSearching: boolean;
  hasSearched: boolean;
  totalCount: number;
  /**
   * NAN-2550: false when `totalCount` is a proven lower bound rather than a
   * total (a lake page, a native-OTLP page, a clamped ClickHouse count). The
   * count then renders as `N+`. Defaults to `true` so callers that genuinely
   * know their count is exact need not pass it.
   */
  totalCountExact?: boolean;
  executionTimeMs: number | null;
  firstRowsMs?: number;
  completionMs?: number;
  asyncJobProgress: SearchJobProgress | null;
  asyncJobStatus: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | null;
  /** NAN-3883: the search runs as a durable background job (not a stream). */
  backgroundJob?: boolean;
  queuePosition: number | null;
  isStreamingResults: boolean;
  onCancel?: () => void;
  tailActive?: boolean;
  tailInterval?: number;
  /** NAN-3884: the run's resolved window, e.g. `7d · Oct 8 10:02 → Oct 15 10:02 EDT`. */
  timeWindow?: string;
}

function Stat({ icon, children }: { icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <span className="flex items-center gap-1.5">
      {icon}
      {children}
    </span>
  );
}

/**
 * SearchStatsBar — since NAN-376 this no longer renders a fixed overlay.
 * Instead it builds a status fragment and pushes it into the global
 * `LayoutContext.pageStatus` slot, so the app's StatusBar footer displays
 * query progress inline with the platform dot + page name.
 */
export function SearchStatsBar({
  isSearching,
  hasSearched,
  totalCount,
  totalCountExact = true,
  executionTimeMs,
  firstRowsMs,
  completionMs,
  asyncJobProgress,
  asyncJobStatus,
  backgroundJob = false,
  queuePosition,
  isStreamingResults,
  onCancel,
  tailActive,
  tailInterval,
  timeWindow,
}: SearchStatsBarProps) {
  const layout = useLayoutOptional();

  const formatTime = (ms: number) =>
    ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(2)}s`;

  // NAN-2550: a lower bound reads as "50+ hits" inline, next to the number it
  // qualifies. It is a property of the count, not an incident, so it does not
  // get a banner.
  const hits = `${formatCompactNumber(totalCount)}${totalCountExact ? '' : '+'}`;

  const content = useMemo<React.ReactNode>(() => {
    if (!isSearching && !hasSearched) return null;

    // Queued state
    if (asyncJobStatus === 'queued') {
      return (
        <>
          <Stat icon={<Clock className="w-3 h-3 text-amber-500" />}>
            Queued{queuePosition ? <> &middot; Slot {queuePosition}</> : ''}
          </Stat>
          {onCancel && (
            <button onClick={onCancel} className="ml-auto hover:text-foreground transition-colors" aria-label="Cancel search">
              <X className="w-3 h-3" />
            </button>
          )}
        </>
      );
    }

    // Searching / streaming
    if (isSearching || isStreamingResults) {
      const elapsed = asyncJobProgress ? formatTime(asyncJobProgress.elapsed_ms) : null;
      return (
        <>
          <LoadingIcon className="w-3 h-3 text-primary flex-shrink-0" />
          {backgroundJob && asyncJobProgress && !hasMeasuredProgress(asyncJobProgress) && !isColdScanProgress(asyncJobProgress) ? (
            <>
              <span>{backgroundJobPhaseLabel(asyncJobProgress)}</span>
              {elapsed && (
                <Stat icon={<Timer className="w-3 h-3" />}>{elapsed}</Stat>
              )}
            </>
          ) : asyncJobProgress ? (
            <>
              <div className="w-20 h-1 bg-muted rounded-full overflow-hidden flex-shrink-0">
                <div
                  className="h-full bg-primary transition-all duration-300"
                  style={{ width: `${asyncJobProgress.percent}%` }}
                />
              </div>
              <span className="tabular-nums">{asyncJobProgress.percent}%</span>
              {isColdScanProgress(asyncJobProgress) && (
                <span className="font-mono tabular-nums">{coldScanLabel(asyncJobProgress)}</span>
              )}
              {asyncJobProgress.rows_total > 0 && (
                <Stat icon={<Rows3 className="w-3 h-3" />}>
                  {formatCompactNumber(asyncJobProgress.rows_scanned)} / {formatCompactNumber(asyncJobProgress.rows_total)}
                </Stat>
              )}
              {elapsed && (
                <Stat icon={<Timer className="w-3 h-3" />}>{elapsed}</Stat>
              )}
            </>
          ) : (
            <span>Executing query…</span>
          )}
          {isStreamingResults && totalCount > 0 && (
            <Stat icon={<Crosshair className="w-3 h-3" />}>
              <span className="font-mono tabular-nums">{hits}</span> hits
            </Stat>
          )}
          {onCancel && (
            <button onClick={onCancel} className="ml-auto hover:text-foreground transition-colors" aria-label="Cancel search">
              <X className="w-3 h-3" />
            </button>
          )}
        </>
      );
    }

    // Completed
    if (hasSearched && executionTimeMs !== null) {
      const tailLabel = tailActive && tailInterval
        ? tailInterval < 60000 ? `${tailInterval / 1000}s` : `${tailInterval / 60000}m`
        : null;
      return (
        <>
          <Stat icon={<CircleCheck className="w-3 h-3" style={{ color: 'var(--success)' }} />}>
            <span style={{ color: 'var(--success)' }}>{firstRowsMs !== undefined && completionMs === undefined ? 'Rows ready' : 'Query complete'}</span>
          </Stat>
          <Stat icon={<Crosshair className="w-3 h-3" />}>
            <span
              className="font-mono tabular-nums"
              title={totalCountExact ? undefined : 'At least this many events match; an exact total is not available for this result.'}
            >
              {hits}
            </span>{' '}hits
          </Stat>
          <Stat icon={<Timer className="w-3 h-3" />}>
            {firstRowsMs === undefined ? formatTime(executionTimeMs) : `${formatTime(firstRowsMs)} first rows`}
            {completionMs !== undefined && ` · ${formatTime(completionMs)} complete`}
          </Stat>
          {timeWindow && (
            <Stat icon={<CalendarRange className="w-3 h-3" />}>
              <span className="font-mono text-[10.5px] tabular-nums" data-testid="search-time-window">{timeWindow}</span>
            </Stat>
          )}
          {tailActive && (
            <Stat icon={<Terminal className="w-3 h-3" style={{ color: 'var(--success)' }} />}>
              <span className="font-mono" style={{ color: 'var(--success)' }}>tail -f</span>
              {tailLabel && <span className="text-muted-foreground">&middot; {tailLabel}</span>}
            </Stat>
          )}
        </>
      );
    }

    return null;
  }, [
    isSearching,
    hasSearched,
    hits,
    totalCount,
    totalCountExact,
    executionTimeMs,
    firstRowsMs,
    completionMs,
    asyncJobProgress,
    asyncJobStatus,
    backgroundJob,
    queuePosition,
    isStreamingResults,
    onCancel,
    tailActive,
    tailInterval,
    timeWindow,
  ]);

  useEffect(() => {
    layout?.setPageStatus(content);
    return () => layout?.setPageStatus(null);
  }, [content, layout]);

  return null;
}
