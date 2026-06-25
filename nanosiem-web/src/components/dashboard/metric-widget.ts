// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Metric-widget dashboard helpers (NAN-1540)
 *
 * The metrics builder (MetricsTab) calls `addMetricToDashboard` to persist its
 * current query as an `obs_metric` dashboard widget — either into an existing
 * dashboard or a new one. This mirrors AddToDashboardDialog's panel-append
 * logic but for the metric widget type, so the builder doesn't have to reach
 * into dashboard internals.
 */

import { api } from '@/lib/api';
import type {
  Dashboard,
  PanelConfig,
  DashboardLayout,
  LayoutItem,
  MetricWidgetConfig,
} from '@/lib/api';

function generatePanelId(): string {
  return `panel-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
}

/**
 * Build an `obs_metric` PanelConfig from a metric query. `query` is left empty
 * — metric widgets fetch from the metrics timeseries endpoint, not the nPL/SQL
 * panel-query path (see DashboardView.fetchPanelData / ObsMetricWidget).
 */
export function buildMetricPanelConfig(
  title: string,
  metricConfig: MetricWidgetConfig
): PanelConfig {
  return {
    id: generatePanelId(),
    title: title.trim() || metricConfig.metric_name,
    query: '',
    queryMode: 'piped',
    visualizationType: 'obs_metric',
    visualizationConfig: { unit: metricConfig.unit },
    timeRangeMode: 'dashboard',
    drilldownEnabled: false,
    metricConfig,
  };
}

/** Position a new panel below all existing layout items. */
function layoutItemBelow(panelId: string, items: LayoutItem[]): LayoutItem {
  let maxY = 0;
  for (const it of items) {
    const bottom = (it.y || 0) + (it.h || 4);
    if (bottom > maxY) maxY = bottom;
  }
  return { i: panelId, x: 0, y: maxY, w: 6, h: 4, minW: 2, minH: 2 };
}

export interface AddMetricToDashboardArgs {
  /** Append to this dashboard id, or omit/blank with `newDashboardName` to create one. */
  dashboardId?: string;
  newDashboardName?: string;
  title: string;
  metricConfig: MetricWidgetConfig;
}

/**
 * Persist a metric query as an `obs_metric` widget. Returns the dashboard id the
 * widget landed on, so callers can navigate to `/dashboards/<id>`.
 */
export async function addMetricToDashboard(args: AddMetricToDashboardArgs): Promise<string> {
  const panel = buildMetricPanelConfig(args.title, args.metricConfig);

  if (args.dashboardId) {
    const full: Dashboard = await api.getDashboard(args.dashboardId);
    const existingPanels: PanelConfig[] = Array.isArray(full.panels) ? full.panels : [];
    const existingLayout = full.layout || { columns: 12, rowHeight: 80, items: [] };
    const existingItems: LayoutItem[] = Array.isArray(existingLayout.items)
      ? existingLayout.items
      : [];

    const updatedLayout: DashboardLayout = {
      columns: existingLayout.columns || 12,
      rowHeight: existingLayout.rowHeight || 80,
      items: [...existingItems, layoutItemBelow(panel.id, existingItems)],
      variables: existingLayout.variables,
      defaultTimeRange: existingLayout.defaultTimeRange,
      autoRun: existingLayout.autoRun,
    };

    await api.updateDashboard(args.dashboardId, {
      panels: [...existingPanels, panel],
      layout: updatedLayout,
    });
    return args.dashboardId;
  }

  const name = (args.newDashboardName || '').trim() || 'Metrics';
  const layout: DashboardLayout = {
    columns: 12,
    rowHeight: 80,
    items: [{ i: panel.id, x: 0, y: 0, w: 6, h: 4, minW: 2, minH: 2 }],
  };
  const created = await api.createDashboard({
    name,
    description: 'Created from the metrics explorer',
    layout,
    panels: [panel],
  });
  return created.id;
}
