// SPDX-License-Identifier: AGPL-3.0-or-later

// TracePage (NAN-1528) — full-page distributed-trace view. Fetches an OTLP
// trace by id (GET /api/search/trace/:id) and renders the waterfall. Reached
// from the event inspector's "View trace" pivot when a log row carries a
// trace_id, from the Services / Traces drill-ins, or directly via /trace/:id.
//
// NAN-1547: this page now renders the richer Observability-console waterfall
// (TraceWaterfall + SpanDrawer) instead of the original rougher
// TraceWaterfallView, so every trace drill-in — Traces tab, Services, the
// log→trace pivot, direct link — lands on the same surface. TraceWaterfall
// brings its own header (back / title / id / "Logs for this trace" pivot) and
// meta strip, so the page is just the data fetch + a padded wrapper.

import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Loader2 } from 'lucide-react';
import { api } from '@/lib/api';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { TraceWaterfall } from '@/components/observability/TraceWaterfall';

export function TracePage() {
  const { traceId = '' } = useParams<{ traceId: string }>();
  const navigate = useNavigate();

  useDocumentTitle('Trace');
  useBreadcrumbTitle(traceId ? `Trace ${traceId.slice(0, 12)}…` : 'Trace');

  const { data, isLoading, error } = useQuery({
    queryKey: ['otel-trace', traceId],
    queryFn: () => api.getTrace(traceId),
    enabled: traceId.length > 0,
  });

  const spans = data?.spans ?? [];

  return (
    <div className="px-4 py-3 w-full">
      {isLoading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
        </div>
      ) : error ? (
        <div className="text-center py-16 text-sm text-muted-foreground">
          Failed to load trace.
        </div>
      ) : spans.length === 0 ? (
        <div className="text-center py-16 text-sm text-muted-foreground">
          No spans found for this trace.
        </div>
      ) : (
        <TraceWaterfall traceId={traceId} spans={spans} onBack={() => navigate(-1)} backLabel="Back" />
      )}
    </div>
  );
}

export default TracePage;
