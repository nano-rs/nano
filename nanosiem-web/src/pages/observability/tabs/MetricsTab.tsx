// SPDX-License-Identifier: AGPL-3.0-or-later

// MetricsTab (NAN-1540) — metrics-v2 explorer.
//
// Rebuilt from the NAN-1536 single-metric panel into a full query builder over
// the metrics-v2 backend (POST /api/search/metrics/timeseries with agg /
// group_by / filters → series[]; GET /api/search/metrics/tags for tag
// discovery). The explorer (src/components/observability/MetricsExplorer) owns
// metric · aggregation · group-by · tag-filters · viz-switcher and the
// "Add to dashboard" / "Create monitor" actions; this tab just loads the
// metric-name catalog and renders the explorer + the saved-monitors list.
//
// Data: api.observability.listMetricNames() (catalog) + the explorer's own
// queryMetricsV2 / listMetricTags / metric-monitor CRUD calls.

import { useEffect, useState } from 'react';
import { AlertCircle, LineChart, Loader2 } from 'lucide-react';

import { api } from '@/lib/api';
import { MetricsExplorer } from '@/components/observability/MetricsExplorer';
import { MetricMonitorsList } from '@/components/observability/MetricMonitorsList';
import type { ObservabilityTabProps } from '../types';

export function MetricsTab({ apiTimeRange }: ObservabilityTabProps) {
  const [metricNames, setMetricNames] = useState<string[]>([]);
  const [catalogLoading, setCatalogLoading] = useState(true);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  // Incremented after creating a monitor so the list reloads.
  const [monitorReloadKey, setMonitorReloadKey] = useState(0);

  // Load the metric-name catalog once (the distinct-names endpoint is unbounded
  // by window, so it's independent of the time range).
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
        <div className="text-[11px] text-fg-4 mt-1 max-w-[260px]">
          OTLP metrics show up here once a service exports them to the collector.
        </div>
      </div>
    );
  }

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
          {metricNames.length} metrics
        </span>
      </div>

      <MetricsExplorer
        metricNames={metricNames}
        apiTimeRange={apiTimeRange}
        onMonitorCreated={() => setMonitorReloadKey((k) => k + 1)}
      />

      <MetricMonitorsList reloadKey={monitorReloadKey} />
    </div>
  );
}

export default MetricsTab;
