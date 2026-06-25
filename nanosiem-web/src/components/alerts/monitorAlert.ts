// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-1547 — monitor-alert payload parsing.
//
// The unified alert spine (NAN-1541) routes observability monitor breaches
// through the same `alerts` table as detection alerts, discriminated by `kind`.
// Monitor alerts carry `rule_id = NULL` and instead pack the breach context
// into `matched_events[0]` (the evaluator builds a single-element array — see
// `schedulers.rs` raise path and `synthetic_runner.rs`). The detection-centric
// alert UI looks rows up by rule, so these rendered as "Unknown Rule" / no
// value. This module normalizes the payload so the alert views can render a
// monitor-shaped surface instead.

import type { Alert, AlertKind } from '@/lib/api/types';

/** Alert-spine kinds that are observability monitors (everything but `detection`). */
export const MONITOR_KINDS = ['metric_monitor', 'slo', 'synthetic'] as const;
export type MonitorKind = (typeof MONITOR_KINDS)[number];

export function isMonitorKind(kind: AlertKind | string | undefined): kind is MonitorKind {
  return kind === 'metric_monitor' || kind === 'slo' || kind === 'synthetic';
}

/** Normalized monitor-alert view, kind-agnostic where the fields overlap. */
export interface MonitorAlertView {
  kind: MonitorKind;
  /** Display title — the monitor/check name, else a derived label. */
  title: string;
  /** Producer typeid (monitor / check id). */
  sourceId?: string;
  evaluatedAt?: string;

  // metric_monitor / slo
  metricName?: string;
  agg?: string;
  groupBy?: string | null;
  seriesKey?: string;
  comparator?: string;
  threshold?: number;
  value?: number;
  windowSecs?: number;

  // synthetic
  targetUrl?: string;
  expectedStatus?: number;
  observedStatus?: number;
  error?: string;
}

/** Human label for a monitor kind. */
export const MONITOR_KIND_LABEL: Record<MonitorKind, string> = {
  metric_monitor: 'Metric monitor',
  slo: 'SLO',
  synthetic: 'Synthetic check',
};

function firstPayload(matched: unknown): Record<string, unknown> {
  if (Array.isArray(matched) && matched.length > 0) {
    const first = matched[0];
    if (first && typeof first === 'object') return first as Record<string, unknown>;
  }
  return {};
}

const asStr = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);
const asNum = (v: unknown): number | undefined =>
  typeof v === 'number' && Number.isFinite(v) ? v : undefined;

/**
 * Parse a monitor breach payload off an alert. Returns null for detection
 * alerts (or any non-monitor kind) so callers can branch on a single value.
 */
export function parseMonitorAlert(
  alert: Pick<Alert, 'kind' | 'source_id' | 'matched_events'>,
): MonitorAlertView | null {
  if (!isMonitorKind(alert.kind)) return null;
  const kind = alert.kind;
  const p = firstPayload(alert.matched_events);

  if (kind === 'synthetic') {
    return {
      kind,
      title: asStr(p.check_name) ?? asStr(p.target_url) ?? MONITOR_KIND_LABEL.synthetic,
      sourceId: alert.source_id ?? asStr(p.check_id),
      evaluatedAt: asStr(p.evaluated_at),
      targetUrl: asStr(p.target_url),
      expectedStatus: asNum(p.expected_status),
      observedStatus: asNum(p.observed_status),
      error: asStr(p.error),
    };
  }

  // metric_monitor + slo share the metric-breach payload shape.
  return {
    kind,
    title: asStr(p.monitor_name) ?? asStr(p.metric_name) ?? MONITOR_KIND_LABEL[kind],
    sourceId: alert.source_id ?? asStr(p.monitor_id),
    evaluatedAt: asStr(p.evaluated_at),
    metricName: asStr(p.metric_name),
    agg: asStr(p.agg),
    groupBy: asStr(p.group_by) ?? null,
    seriesKey: asStr(p.series_key),
    comparator: asStr(p.comparator),
    threshold: asNum(p.threshold),
    value: asNum(p.value),
    windowSecs: asNum(p.window_secs),
  };
}

/** Math symbol for a breach comparator (`gt` → `>`). Falls back to the raw token. */
export function comparatorSymbol(c?: string): string {
  switch (c) {
    case 'gt':
      return '>';
    case 'gte':
      return '≥';
    case 'lt':
      return '<';
    case 'lte':
      return '≤';
    case 'eq':
      return '=';
    case 'ne':
      return '≠';
    default:
      return c ?? '';
  }
}

/** Compact window label, e.g. 900 → "15m", 3600 → "1h". */
export function formatWindow(secs?: number): string {
  if (!secs || secs <= 0) return '—';
  if (secs % 3600 === 0) return `${secs / 3600}h`;
  if (secs % 60 === 0) return `${secs / 60}m`;
  return `${secs}s`;
}

/** Trim a metric value to ≤2 decimals with grouping. */
export function formatMetricValue(n?: number): string {
  if (n == null || !Number.isFinite(n)) return '—';
  return (Math.round(n * 100) / 100).toLocaleString(undefined, { maximumFractionDigits: 2 });
}

/**
 * One-line scope label for a monitor row — the metric (with agg) for metric
 * monitors / SLOs, the target URL for synthetic checks.
 */
export function monitorScope(m: MonitorAlertView): string {
  if (m.kind === 'synthetic') return m.targetUrl ?? '—';
  if (!m.metricName) return '—';
  return m.agg ? `${m.agg}(${m.metricName})` : m.metricName;
}
