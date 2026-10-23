// SPDX-License-Identifier: AGPL-3.0-or-later

// MetricPageView (NAN-1560) — renders the `| metric <name>` command-page by
// reusing the Observability console's MetricsExplorer (same surface as the
// Metrics tab). Loads the metric-name catalog (MetricsExplorer sources its
// picker from it), then renders the explorer with `<name>` preselected when the
// command scoped one. The nPL command short-circuits to a marker carrying
// `_metric`.

import { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertCircle, LineChart, RotateCw } from 'lucide-react';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import {
  MetricsExplorer,
  type MetricCatalogStatus,
} from '@/components/observability/MetricsExplorer';
import { MetricMonitorsList } from '@/components/observability/MetricMonitorsList';
import { toApiTimeRange } from '@/hooks/use-api';
import type { TimeRange } from '@/lib/api/types';

export interface MetricPageViewProps {
  /** Metric name from `| metric <name>`; empty string ⇒ open explorer unscoped. */
  metric: string;
  /**
   * Service scope from `| metric <name> service=<svc>` (NAN-1564); empty string
   * ⇒ unscoped. Seeds MetricsExplorer's `service_name` query param (the promoted
   * `otel_metrics.service_name` column).
   */
  service?: string;
  /** Resolved absolute range from SearchResults (Search.tsx passes apiTimeRange). */
  timeRange?: { start: string; end: string };
}

export function MetricPageView({ metric, service, timeRange }: MetricPageViewProps) {
  const [metricNames, setMetricNames] = useState<string[]>([]);
  const [catalogLoading, setCatalogLoading] = useState(true);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [catalogAttempt, setCatalogAttempt] = useState(0);
  const [monitorReloadKey, setMonitorReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setCatalogLoading(true);
    setCatalogError(null);
    api.observability
      .listMetricNames()
      .then((r) => {
        if (cancelled) return;
        setMetricNames(r.names.map((n) => n.metric_name).filter(Boolean));
      })
      .catch((e: unknown) => {
        if (!cancelled)
          setCatalogError(e instanceof Error ? e.message : 'Failed to load metric names');
      })
      .finally(() => {
        if (!cancelled) setCatalogLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [catalogAttempt]);

  const retryCatalog = useCallback(() => setCatalogAttempt((n) => n + 1), []);
  const catalog: MetricCatalogStatus = useMemo(() => {
    if (catalogError) return { status: 'error', message: catalogError, onRetry: retryCatalog };
    if (catalogLoading) return { status: 'loading' };
    return { status: 'ready' };
  }, [catalogError, catalogLoading, retryCatalog]);

  // O57 (NAN-1721): fall back to a resolved default preset, not an empty
  // {start:'',end:''}. An empty window serializes to an invalid time_range and
  // the explorer's first fetch 4xxs; "Last hour" is the console's own default.
  const apiTimeRange: TimeRange = timeRange ?? toApiTimeRange('Last hour');

  // NAN-4098: the explorer renders at once, whatever the catalog is doing — a
  // `| metric <name>` chart needs no catalog, and the picker accepts typed
  // names. MetricsExplorer is the phase-2 reporter for `| metric` (NAN-1600).
  return (
    // Match the Observability console's tab-body inset (NAN-1560).
    <div className="flex flex-col gap-2.5 px-4 py-3">
      {catalogError && (
        <div role="alert" className="flex items-center gap-2 text-[12px] text-destructive">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{catalogError}</span>
          <span className="text-[11px] text-fg-3">Type a metric name in the picker to chart it.</span>
          <Button variant="outline" className="h-7 gap-1.5 text-[11px]" onClick={retryCatalog}>
            <RotateCw className="w-[12px] h-[12px]" />
            Retry
          </Button>
        </div>
      )}
      {!catalogLoading && !catalogError && metricNames.length === 0 && !metric && (
        <div className="flex items-center gap-2 text-[11px] text-fg-3">
          <LineChart className="w-4 h-4" /> No metrics ingested in the last 24 h.
        </div>
      )}
      <MetricsExplorer
        metricNames={metricNames}
        catalog={catalog}
        apiTimeRange={apiTimeRange}
        initialMetric={metric || undefined}
        initialService={service || undefined}
        onMonitorCreated={() => setMonitorReloadKey((k) => k + 1)}
      />
      <MetricMonitorsList reloadKey={monitorReloadKey} />
    </div>
  );
}

export default MetricPageView;
