// SPDX-License-Identifier: AGPL-3.0-or-later

import { TelemetrySetupHint } from '@/components/observability/TelemetryUnavailable';

// MetricsTab (NAN-1540) — metrics-v2 explorer.
//
// Rebuilt from the NAN-1536 single-metric panel into a full query builder over
// the metrics-v2 backend (POST /api/search/metrics/timeseries with agg /
// group_by / filters → series[]; GET /api/search/metrics/tags for tag
// discovery). The explorer (src/components/observability/MetricsExplorer) owns
// metric · aggregation · group-by · tag-filters · viz-switcher and the
// "Add to dashboard" / "Create monitor" actions; this tab loads the
// metric-name catalog and renders one explorer panel (plus any the user adds)
// and the saved-monitors list.
//
// NAN-4098: the catalog is a convenience, never a gate. While it loads, or
// after it fails, every panel still accepts a typed metric name, and a failed
// catalog shows its error with Retry. The tab starts with ONE panel; earlier
// builds keyed the explorer and the monitors list with the same React key, so
// reconciliation left stale duplicate explorers behind (three "select metric"
// panels on the ops tenant).
//
// Data: api.observability.listMetricNames() (catalog) + the explorer's own
// queryMetricsV2 / listMetricTags / metric-monitor CRUD calls.

import { Fragment, useCallback, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '@/contexts/AuthContext';
import { AlertCircle, LineChart, Plus, RotateCw } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';

import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import {
  MetricsExplorer,
  type MetricCatalogStatus,
} from '@/components/observability/MetricsExplorer';
import { MetricMonitorsList } from '@/components/observability/MetricMonitorsList';
import type { TimeRange } from '@/lib/api/types';
import type { ObservabilityTabProps } from '../types';

/** Upper bound on explorer panels in the tab. */
export const MAX_METRIC_PANELS = 6;

function formatWindowStart(iso: string | undefined): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export function MetricsTab({ apiTimeRange }: ObservabilityTabProps) {
  const { tenantRuntime } = useAuth();
  const catalog = useQuery({
    queryKey: ['metric-names', tenantRuntime.key],
    queryFn: () => api.observability.listMetricNames(),
    staleTime: 60_000,
    retry: false,
  });
  const metricNames = useMemo(
    () => catalog.data?.names.map((n) => n.metric_name).filter(Boolean) ?? [],
    [catalog.data]
  );
  const [monitorReloadKey, setMonitorReloadKey] = useState(0);
  const { refetch } = catalog;
  const retry = useCallback(() => {
    void refetch();
  }, [refetch]);

  const errorMessage =
    catalog.error instanceof Error ? catalog.error.message : 'Failed to load metric names';
  const catalogStatus: MetricCatalogStatus = useMemo(() => {
    if (catalog.isError) return { status: 'error', message: errorMessage, onRetry: retry };
    if (catalog.isPending || (catalog.isFetching && metricNames.length === 0)) {
      return { status: 'loading' };
    }
    return { status: 'ready', partial: catalog.data?.partial };
  }, [catalog.isError, catalog.isPending, catalog.isFetching, catalog.data, errorMessage, retry, metricNames.length]);

  const partialSince = catalog.data?.partial ? formatWindowStart(catalog.data.window_start) : null;

  return (
    <div className="flex flex-col gap-2.5">
      <div className="flex items-center gap-2">
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-fg-3">
          Metrics explorer
        </span>
        <span className="text-[11px] text-fg-4">
          — query · aggregate · group · filter · visualize
        </span>
        <div className="flex-1" />
        <span className="font-mono text-[10.5px] text-fg-4 tabular-nums">
          {catalogStatus.status === 'ready' ? `${metricNames.length} metrics` : '— metrics'}
        </span>
      </div>

      {catalogStatus.status === 'loading' && (
        <div role="status" className="flex items-center gap-2 text-[11px] text-fg-3">
          <LoadingIcon className="w-3.5 h-3.5" /> Loading metric catalog… You can type a metric
          name in the picker meanwhile.
        </div>
      )}
      {catalog.isError && (
        <div role="alert" className="flex items-center gap-2 text-[12px] text-destructive">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMessage}</span>
          <span className="text-[11px] text-fg-3">Type a metric name in the picker to chart it.</span>
          <Button
            variant="outline"
            className="h-7 gap-1.5 text-[11px]"
            onClick={retry}
            disabled={catalog.isFetching}
          >
            <RotateCw className="w-[12px] h-[12px]" />
            Retry
          </Button>
        </div>
      )}
      {catalog.isSuccess && partialSince && metricNames.length > 0 && (
        <div className="text-[11px] text-fg-3">
          Catalog lists names seen since <span className="font-mono">{partialSince}</span>; the
          rest of the last 24 h fills in shortly. Any metric name can be typed.
        </div>
      )}
      {catalog.isSuccess && metricNames.length === 0 && (
        <div className="text-[11px] text-fg-3">
          <LineChart className="w-4 h-4" /> No metrics ingested in the last 24 h.
          <TelemetrySetupHint />
        </div>
      )}

      {/* One keyed fragment: a tenant switch remounts the panels and the
          monitors list together, and the two never share a sibling key. */}
      <Fragment key={tenantRuntime.key}>
        <MetricPanels
          metricNames={metricNames}
          catalog={catalogStatus}
          apiTimeRange={apiTimeRange}
          onMonitorCreated={() => setMonitorReloadKey((k) => k + 1)}
        />
        <MetricMonitorsList reloadKey={monitorReloadKey} />
      </Fragment>
    </div>
  );
}

/** One explorer panel to start, plus "Add panel" (NAN-4098). */
function MetricPanels({
  metricNames,
  catalog,
  apiTimeRange,
  onMonitorCreated,
}: {
  metricNames: string[];
  catalog: MetricCatalogStatus;
  apiTimeRange: TimeRange;
  onMonitorCreated: () => void;
}) {
  const nextId = useRef(1);
  const [panels, setPanels] = useState<number[]>([0]);
  const addPanel = () => {
    setPanels((current) =>
      current.length >= MAX_METRIC_PANELS ? current : [...current, nextId.current++]
    );
  };
  const removePanel = (id: number) => {
    setPanels((current) => (current.length <= 1 ? current : current.filter((p) => p !== id)));
  };

  return (
    <>
      {panels.map((id) => (
        <MetricsExplorer
          key={id}
          metricNames={metricNames}
          catalog={catalog}
          apiTimeRange={apiTimeRange}
          onMonitorCreated={onMonitorCreated}
          onRemove={panels.length > 1 ? () => removePanel(id) : undefined}
        />
      ))}
      <div>
        <Button
          variant="outline"
          className="h-7 gap-1.5 text-[11px]"
          onClick={addPanel}
          disabled={panels.length >= MAX_METRIC_PANELS}
          title={
            panels.length >= MAX_METRIC_PANELS
              ? `At most ${MAX_METRIC_PANELS} panels`
              : undefined
          }
        >
          <Plus className="w-[12px] h-[12px]" />
          Add panel
        </Button>
      </div>
    </>
  );
}

export default MetricsTab;
