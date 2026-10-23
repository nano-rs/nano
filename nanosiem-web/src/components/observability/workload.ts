// SPDX-License-Identifier: AGPL-3.0-or-later

/** Legacy services have no workload metadata. Match complete role tokens,
 * never substrings such as jobs-api or scheduler-api (interactive services). */
export function isBackgroundService(service: string): boolean {
  return /(?:^|[-_.])(jobs?|schedulers?)(?:[-_.]\d+)?$/i.test(service);
}

export function isBackgroundOperation(service: string, operation: string): boolean {
  return isBackgroundService(service) || /^(?:scheduler[._]|evaluate_metric_monitor$|list_repos_for_auto_sync$)/.test(operation);
}

/** Background latency has no implicit objective. Error health stays active. */
export function latencyClass(service: string, percentile: 'p95' | 'p99', ms: number, operation = ''): string {
  if (isBackgroundOperation(service, operation)) return 'text-fg-2';
  return percentile === 'p99' ? (ms >= 1800 ? 'text-danger' : 'text-fg-2') : (ms >= 600 ? 'text-warn' : 'text-fg');
}

export function backgroundHealth(errorRate: number): 'danger' | 'warn' | 'neutral' {
  return errorRate >= 0.05 ? 'danger' : errorRate >= 0.01 ? 'warn' : 'neutral';
}
