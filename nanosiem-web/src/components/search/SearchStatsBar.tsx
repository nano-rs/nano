// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useEffect, useMemo } from 'react';
import { Loader2, X, Clock, CircleCheck, Rows3, Crosshair, Timer, Terminal } from 'lucide-react';
import { formatCompactNumber } from '@/lib/date-utils';
import { useLayoutOptional } from '@/contexts/LayoutContext';

interface SearchStatsBarProps {
  isSearching: boolean;
  hasSearched: boolean;
  totalCount: number;
  executionTimeMs: number | null;
  asyncJobProgress: { rows_scanned: number; rows_total: number; percent: number; elapsed_ms: number } | null;
  asyncJobStatus: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | null;
  queuePosition: number | null;
  isStreamingResults: boolean;
  onCancel?: () => void;
  tailActive?: boolean;
  tailInterval?: number;
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
  executionTimeMs,
  asyncJobProgress,
  asyncJobStatus,
  queuePosition,
  isStreamingResults,
  onCancel,
  tailActive,
  tailInterval,
}: SearchStatsBarProps) {
  const layout = useLayoutOptional();

  const formatTime = (ms: number) =>
    ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(2)}s`;

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
          <Loader2 className="w-3 h-3 animate-spin text-primary flex-shrink-0" />
          {asyncJobProgress ? (
            <>
              <div className="w-20 h-1 bg-muted rounded-full overflow-hidden flex-shrink-0">
                <div
                  className="h-full bg-primary transition-all duration-300"
                  style={{ width: `${asyncJobProgress.percent}%` }}
                />
              </div>
              <span className="tabular-nums">{asyncJobProgress.percent}%</span>
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
              {formatCompactNumber(totalCount)} hits
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
            <span style={{ color: 'var(--success)' }}>Query complete</span>
          </Stat>
          <Stat icon={<Crosshair className="w-3 h-3" />}>
            {formatCompactNumber(totalCount)} hits
          </Stat>
          <Stat icon={<Timer className="w-3 h-3" />}>
            {formatTime(executionTimeMs)}
          </Stat>
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
    totalCount,
    executionTimeMs,
    asyncJobProgress,
    asyncJobStatus,
    queuePosition,
    isStreamingResults,
    onCancel,
    tailActive,
    tailInterval,
  ]);

  useEffect(() => {
    layout?.setPageStatus(content);
    return () => layout?.setPageStatus(null);
  }, [content, layout]);

  return null;
}
