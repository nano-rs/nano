// SPDX-License-Identifier: AGPL-3.0-or-later

// ObservabilityConsole (NAN-1536) — the single tabbed Observability surface.
// Subsumes the standalone NAN-1534 Traces/Metrics explorer pages. Tabs this
// pass: Services · Traces · Metrics · Alerts · SLOs. Drill-ins: Service detail
// (inline) and Trace waterfall (routes to the existing /trace/:id page so the
// log->trace pivot stays shared).
//
// Tab state lives in the URL (/observability/:tab); service drill-in lives in a
// ?service= query param so it's deep-linkable and survives refresh. The dense
// in-area tab bar mirrors the design handoff's ObsTabs.

import { lazy, Suspense, useMemo, useState, type ReactNode } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import {
  Loader2,
  Box,
  GitBranch,
  LineChart,
  Bell,
  Target,
  Server,
  MonitorSmartphone,
  Radar,
} from 'lucide-react';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { toApiTimeRange, type TimeRangeValue } from '@/hooks/use-api';
import { DateTimeRangePicker } from '@/components/ui/date-time-range-picker';
import { cn } from '@/lib/utils';
import type { ObservabilityTab, ObservabilityTabProps } from './types';
import { ServiceDetail } from './ServiceDetail';

// Lazy tab bodies — surface agents fill these; the shell only wires them.
const ServicesTab = lazy(() => import('./tabs/ServicesTab'));
const TracesTab = lazy(() => import('./tabs/TracesTab'));
const MetricsTab = lazy(() => import('./tabs/MetricsTab'));
const InfraTab = lazy(() => import('./tabs/InfraTab'));
const RumTab = lazy(() => import('./tabs/RumTab'));
const SyntheticsTab = lazy(() => import('./tabs/SyntheticsTab'));
const AlertsTab = lazy(() => import('./tabs/AlertsTab'));
const SlosTab = lazy(() => import('./tabs/SlosTab'));

const TABS: Array<{ id: ObservabilityTab; label: string; icon: typeof Box }> = [
  { id: 'services', label: 'Services', icon: Box },
  { id: 'traces', label: 'Traces', icon: GitBranch },
  { id: 'metrics', label: 'Metrics', icon: LineChart },
  { id: 'infrastructure', label: 'Infrastructure', icon: Server },
  { id: 'rum', label: 'RUM', icon: MonitorSmartphone },
  { id: 'synthetics', label: 'Synthetics', icon: Radar },
  { id: 'alerts', label: 'Alerts', icon: Bell },
  { id: 'slos', label: 'SLOs', icon: Target },
];

const VALID_TABS = new Set<string>(TABS.map((t) => t.id));

function TabFallback() {
  return (
    <div className="flex items-center justify-center py-16">
      <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
    </div>
  );
}

export function ObservabilityConsole() {
  const { tab: tabParam } = useParams<{ tab?: string }>();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const tab: ObservabilityTab =
    tabParam && VALID_TABS.has(tabParam) ? (tabParam as ObservabilityTab) : 'services';
  const service = searchParams.get('service') ?? undefined;

  useDocumentTitle(service ? `Observability · ${service}` : 'Observability');
  useBreadcrumbTitle(
    service ? `Observability / ${service}` : 'Observability'
  );

  // The console keeps a single shared time range; default to last hour to match
  // the design's topbar default. (Per-tab refinement can layer on later.)
  const [timeRange, setTimeRange] = useState<TimeRangeValue>({ type: 'preset', preset: 'Last 15 minutes' });
  const apiTimeRange = useMemo(() => toApiTimeRange(timeRange), [timeRange]);

  const goTab = (next: ObservabilityTab) => {
    // Switching tabs clears any service drill-in.
    navigate(`/observability/${next}`);
  };

  const openService = (svc: string) => {
    navigate(`/observability/services?service=${encodeURIComponent(svc)}`);
  };
  const closeService = () => navigate('/observability/services');

  // Trace drill-in reuses the shared full-page waterfall (keeps the log->trace
  // pivot single-sourced at /trace/:id).
  const openTrace = (traceId: string) => {
    navigate(`/trace/${encodeURIComponent(traceId)}`);
  };

  const tabProps: ObservabilityTabProps = {
    timeRange,
    apiTimeRange,
    onOpenService: openService,
    onOpenTrace: openTrace,
  };

  // Service drill-in takes over the body (only meaningful on the Services tab).
  const showServiceDetail = tab === 'services' && !!service;

  let body: ReactNode;
  if (showServiceDetail && service) {
    body = (
      <ServiceDetail
        service={service}
        apiTimeRange={apiTimeRange}
        onBack={closeService}
        onOpenTrace={openTrace}
      />
    );
  } else {
    body = (
      <Suspense fallback={<TabFallback />}>
        {tab === 'services' && <ServicesTab {...tabProps} />}
        {tab === 'traces' && <TracesTab {...tabProps} />}
        {tab === 'metrics' && <MetricsTab {...tabProps} />}
        {tab === 'infrastructure' && <InfraTab {...tabProps} />}
        {tab === 'rum' && <RumTab {...tabProps} />}
        {tab === 'synthetics' && <SyntheticsTab {...tabProps} />}
        {tab === 'alerts' && <AlertsTab {...tabProps} />}
        {tab === 'slos' && <SlosTab {...tabProps} />}
      </Suspense>
    );
  }

  return (
    <div className="px-4 py-3 w-full">
      {/* Meta row: tab bar + time range. The global TopBar owns the breadcrumb. */}
      <div className="flex items-center gap-3 border-b border-border pb-2.5 mb-3">
        <div className="flex items-center gap-0.5 overflow-x-auto scrollbar-thin">
          {TABS.map(({ id, label, icon: Icon }) => {
            const active = tab === id;
            return (
              <button
                key={id}
                onClick={() => goTab(id)}
                className={cn(
                  'inline-flex items-center gap-1.5 h-8 px-2.5 rounded-md text-[12.5px] font-medium transition-colors whitespace-nowrap shrink-0',
                  active
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                )}
              >
                <Icon className="w-[14px] h-[14px]" />
                {label}
              </button>
            );
          })}
        </div>
        <span className="flex-1" aria-hidden />
        <DateTimeRangePicker value={timeRange} onChange={setTimeRange} variant="search" />
      </div>

      {body}
    </div>
  );
}

export default ObservabilityConsole;
