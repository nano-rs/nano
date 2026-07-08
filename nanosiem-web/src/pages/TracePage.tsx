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

import { useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Loader2 } from 'lucide-react';
import { api } from '@/lib/api';
import type { CacheMeta } from '@/lib/api';
import { CachedNotice } from '@/components/search/CachedNotice';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { TraceWaterfall } from '@/components/observability/TraceWaterfall';

export function TracePage() {
  const { traceId = '' } = useParams<{ traceId: string }>();
  const navigate = useNavigate();

  useDocumentTitle('Trace');
  useBreadcrumbTitle(traceId ? `Trace ${traceId.slice(0, 12)}…` : 'Trace');

  // NAN-1721 (O36): the trace fetch is server-cached (x-nano-cache). Surface the
  // "cached · refresh" badge and let a refresh force a live refetch. Goes via
  // api.observability.getTrace, the getTrace variant that threads cacheOpts.
  const [cacheMeta, setCacheMeta] = useState<CacheMeta | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const bypassRef = useRef(false);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['otel-trace', traceId],
    queryFn: () => {
      const bypass = bypassRef.current;
      bypassRef.current = false;
      return api.observability.getTrace(traceId, { onMeta: setCacheMeta, bypass });
    },
    enabled: traceId.length > 0,
  });

  const refresh = () => {
    if (refreshing) return;
    bypassRef.current = true;
    setRefreshing(true);
    void refetch().finally(() => setRefreshing(false));
  };

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
        <TraceWaterfall
          traceId={traceId}
          spans={spans}
          onBack={() => navigate(-1)}
          backLabel="Back"
          cacheNotice={
            <CachedNotice meta={cacheMeta} onRefresh={refresh} refreshing={refreshing} />
          }
        />
      )}
    </div>
  );
}

export default TracePage;
