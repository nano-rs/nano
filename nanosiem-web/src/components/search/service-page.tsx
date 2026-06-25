// SPDX-License-Identifier: AGPL-3.0-or-later

// ServicePageView (NAN-1560) — renders the `| service <name>` command-page by
// reusing the Observability console's ServiceDetail drill-in. The nPL command
// short-circuits to a synthetic marker row carrying `_service`; this wrapper
// pulls that name and the page's absolute time range into ServiceDetail, which
// fetches its own RED/endpoints/exemplars data. No new backend endpoint.

import { useNavigate } from 'react-router-dom';
import { Box } from 'lucide-react';
import { ServiceDetail } from '@/pages/observability/ServiceDetail';
import type { TimeRange } from '@/lib/api/types';

export interface ServicePageViewProps {
  service: string;
  /** Resolved absolute range from SearchResults (Search.tsx passes apiTimeRange). */
  timeRange?: { start: string; end: string };
}

export function ServicePageView({ service, timeRange }: ServicePageViewProps) {
  const navigate = useNavigate();
  // Guard a degenerate/empty marker (mirrors TracePageView's `enabled` gate):
  // render a neutral empty state rather than fetching ServiceDetail with a blank
  // service name. The parser requires a non-empty name, so this only trips on a
  // transient empty result set.
  if (!service.trim()) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <Box className="w-6 h-6 text-fg-4 mb-2" />
        <div className="text-[12.5px] text-fg-2">
          No service specified. Try <span className="font-mono">| service &lt;name&gt;</span>.
        </div>
      </div>
    );
  }
  // ServiceDetail needs an absolute {start,end}. SearchResults' `timeRange`
  // prop is fed `apiTimeRange` (already resolved) at the Search.tsx call site,
  // so this is the real range; fall back to an empty range only if absent.
  const apiTimeRange: TimeRange = timeRange ?? { start: '', end: '' };
  return (
    // Match the Observability console's tab-body inset (NAN-1560).
    <div className="px-4 py-3">
      <ServiceDetail
        service={service}
        apiTimeRange={apiTimeRange}
        onBack={() => navigate('/observability/services')}
        onOpenTrace={(traceId) => navigate(`/trace/${traceId}`)}
      />
    </div>
  );
}

export default ServicePageView;
