// SPDX-License-Identifier: AGPL-3.0-or-later

// ServicesPageView (NAN-1560) — renders the bare `| services` command-page by
// reusing the Observability console's ServicesTab (the services overview grid /
// list). The nPL command short-circuits to a synthetic marker row with
// `_display_type === 'services'` and no entity. Drill-ins route to the standalone
// observability surfaces (service detail / trace waterfall).

import { useNavigate } from 'react-router-dom';
import { ServicesTab } from '@/pages/observability/tabs/ServicesTab';
import type { TimeRange } from '@/lib/api/types';
import type { TimeRangeValue } from '@/hooks/use-api';

export interface ServicesPageViewProps {
  /** Resolved absolute range from SearchResults (Search.tsx passes apiTimeRange). */
  timeRange?: { start: string; end: string };
}

export function ServicesPageView({ timeRange }: ServicesPageViewProps) {
  const navigate = useNavigate();
  const apiTimeRange: TimeRange = timeRange ?? { start: '', end: '' };
  // ServicesTab consumes apiTimeRange + onOpenService; the picker-value
  // `timeRange` is unused by the tab body, so mirror the absolute range into a
  // `custom` TimeRangeValue to satisfy the prop contract.
  const pickerTimeRange: TimeRangeValue = {
    type: 'custom',
    start: timeRange?.start ? new Date(timeRange.start) : undefined,
    end: timeRange?.end ? new Date(timeRange.end) : undefined,
  };
  return (
    // Match the Observability console's tab-body inset (px-4 py-3) — the embedded
    // ServicesTab has no horizontal padding of its own, so without this the bare
    // "N services" toolbar label jams against the viewport edge (NAN-1560).
    <div className="px-4 py-3">
      <ServicesTab
        timeRange={pickerTimeRange}
        apiTimeRange={apiTimeRange}
        onOpenService={(service) =>
          navigate(`/observability/services?service=${encodeURIComponent(service)}`)
        }
        onOpenTrace={(traceId) => navigate(`/trace/${traceId}`)}
      />
    </div>
  );
}

export default ServicesPageView;
