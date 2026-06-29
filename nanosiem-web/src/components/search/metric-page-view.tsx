// SPDX-License-Identifier: AGPL-3.0-or-later

// MetricPageView (NAN-1560) — renders the `| metric <name>` command-page by
// reusing the Observability console's MetricsExplorer (same surface as the
// Metrics tab). Loads the metric-name catalog (MetricsExplorer sources its
// picker from it), then renders the explorer with `<name>` preselected when the
// command scoped one. The nPL command short-circuits to a marker carrying
// `_metric`.

import { useEffect, useState } from 'react';
import { AlertCircle, LineChart, Loader2 } from 'lucide-react';
import { api } from '@/lib/api';
import { MetricsExplorer } from '@/components/observability/MetricsExplorer';
import { MetricMonitorsList } from '@/components/observability/MetricMonitorsList';
import { useReportPhase2Status } from './footer-reporter';
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
  }, []);

  const apiTimeRange: TimeRange = timeRange ?? { start: '', end: '' };

  // NAN-1600: MetricsExplorer is the phase-2 reporter for `| metric`, but it
  // only mounts in the normal case — the catalog loading / error / no-metrics
  // states return early before it. Report those terminal states here so the
  // gated footer doesn't hang. In the normal case this is a no-op
  // (loading=false, settled=false) and MetricsExplorer takes over reporting.
  useReportPhase2Status({
    loading: catalogLoading,
    settled: !catalogLoading && (catalogError != null || metricNames.length === 0),
    error: catalogError,
    totalCount: 0,
  });

  if (catalogLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (catalogError) {
    return (
      <div className="flex items-center justify-center gap-2 py-16 text-[12.5px] text-destructive">
        <AlertCircle className="w-4 h-4" />
        {catalogError}
      </div>
    );
  }
  if (metricNames.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <LineChart className="w-6 h-6 text-fg-4 mb-2" />
        <div className="text-[12.5px] text-fg-2">No metrics ingested.</div>
      </div>
    );
  }

  return (
    // Match the Observability console's tab-body inset (NAN-1560).
    <div className="flex flex-col gap-2.5 px-4 py-3">
      <MetricsExplorer
        metricNames={metricNames}
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
