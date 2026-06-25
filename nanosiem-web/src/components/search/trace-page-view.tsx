// SPDX-License-Identifier: AGPL-3.0-or-later

// TracePageView (NAN-1560) — renders the `| trace <id>` command-page by reusing
// the Observability console's TraceWaterfall. The page-level TracePage is
// router-param-coupled (useParams), so we reuse the inner waterfall and do the
// fetch here (same query as TracePage). The nPL command short-circuits to a
// marker row carrying `_trace_id`.

import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Loader2 } from 'lucide-react';
import { api } from '@/lib/api';
import { TraceWaterfall } from '@/components/observability/TraceWaterfall';

export interface TracePageViewProps {
  traceId: string;
}

export function TracePageView({ traceId }: TracePageViewProps) {
  const navigate = useNavigate();
  const { data, isLoading, error } = useQuery({
    queryKey: ['otel-trace', traceId],
    queryFn: () => api.getTrace(traceId),
    enabled: traceId.length > 0,
  });
  const spans = data?.spans ?? [];

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
