// SPDX-License-Identifier: AGPL-3.0-or-later

// TracePageView (NAN-1560) — renders the `| trace <id>` command-page by reusing
// the Observability console's TraceWaterfall. The page-level TracePage is
// router-param-coupled (useParams), so we reuse the inner waterfall and do the
// fetch here (same query as TracePage). The nPL command short-circuits to a
// marker row carrying `_trace_id`.

import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Loader2 } from 'lucide-react';
import { api } from '@/lib/api';
import { TraceWaterfall } from '@/components/observability/TraceWaterfall';
import { useReportPhase2 } from './footer-reporter';

export interface TracePageViewProps {
  traceId: string;
}

export function TracePageView({ traceId }: TracePageViewProps) {
  const navigate = useNavigate();
  const reportPhase2 = useReportPhase2();
  const { data, isLoading, isFetching, error } = useQuery({
    queryKey: ['otel-trace', traceId],
    queryFn: () => api.getTrace(traceId),
    enabled: traceId.length > 0,
  });
  const spans = data?.spans ?? [];

  // NAN-1599: publish the real trace fetch status to the search footer (first
  // adopter of the NAN-1598 phase-2 reporter). The footer then shows a spinner
  // until the trace loads, then "<span count> hits · <ms>" (client-measured),
  // instead of the phase-1 marker query's misleading "0 hits · 0ms". No-op when
  // this view is reused outside the search page (useReportPhase2 → noop).
  const fetchStartRef = useRef<number | null>(null);
  useEffect(() => {
    if (isFetching) {
      if (fetchStartRef.current == null) fetchStartRef.current = performance.now();
      reportPhase2({ loading: true });
      return;
    }
    // Settled. Report done on success or error — including the case where React
    // Query served the trace instantly from its cache (no observed loading
    // transition), so the footer never hangs on the spinner. Omit the time when
    // we never measured a real fetch rather than reporting a misleading 0ms.
    if (data || error) {
      const ms = fetchStartRef.current != null ? Math.round(performance.now() - fetchStartRef.current) : undefined;
      fetchStartRef.current = null;
      reportPhase2(
        error ? { loading: false } : { loading: false, executionTimeMs: ms, totalCount: spans.length }
      );
    }
  }, [isFetching, data, error, spans.length, reportPhase2]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (error) {
    return (
      <div className="text-center py-16 text-sm text-muted-foreground">
        Failed to load trace.
      </div>
    );
  }
  if (spans.length === 0) {
    return (
      <div className="text-center py-16 text-sm text-muted-foreground">
        No spans found for this trace.
      </div>
    );
  }
  return (
    // Match the Observability console's tab-body inset (NAN-1560).
    <div className="px-4 py-3">
      <TraceWaterfall
        traceId={traceId}
        spans={spans}
        onBack={() => navigate(-1)}
        backLabel="Back"
      />
    </div>
  );
}

export default TracePageView;
