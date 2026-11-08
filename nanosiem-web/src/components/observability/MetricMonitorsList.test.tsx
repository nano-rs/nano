// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MetricMonitorsList } from './MetricMonitorsList';
const list = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ api: { observability: { listMetricMonitors: list } } }));
vi.mock('./MetricMonitorDialog', () => ({ MetricMonitorDialog: () => null }));
vi.mock('@/components/ui/confirm-dialog', () => ({ ConfirmDialog: () => null }));
const monitor = { id: 'mon_1', name: 'API errors', metric_name: 'errors', filters: [], agg: 'sum', comparator: 'gt', threshold: 1, enabled: true, window_secs: 300, eval_interval_secs: 60 };
afterEach(() => { cleanup(); vi.clearAllMocks(); });
it('distinguishes a saved monitor without recent evaluations from a healthy result', async () => {
  list.mockResolvedValue({ monitors: [monitor], evaluation_summaries: [], evaluations: [] });
  render(<MetricMonitorsList />);
  expect(await screen.findByText('Awaiting evaluation')).toBeTruthy();
  expect(screen.getByText(/No recent monitor evaluations/)).toBeTruthy();
  expect(screen.queryByText('Within threshold')).toBeNull();
});
it('does not show missing metric samples as a zero or successful evaluation', async () => {
  list.mockResolvedValue({ monitors: [monitor], evaluation_summaries: [{ monitor_id: monitor.id, evaluated_at: '2026-10-16T12:00:00Z', series: 1, breaching: 0, no_data: 1, truncated: false }], evaluations: [{ monitor_id: monitor.id, series_key: 'all', value: null, no_data: true, breaching: false, evaluated_at: '2026-10-16T12:00:00Z' }] });
  render(<MetricMonitorsList />);
  expect(await screen.findByText('No data')).toBeTruthy();
  expect(screen.queryByText('Within threshold')).toBeNull();
});
it('derives status from the complete summary, not the bounded series sample', async () => {
  // The sample holds 100 healthy rows; the summary says one of 10 051 breaches.
  const sample = Array.from({ length: 100 }, (_, i) => ({ monitor_id: monitor.id, series_key: `node-${i}`, value: 0.1, no_data: false, breaching: false, evaluated_at: '2026-10-16T12:00:00Z' }));
  list.mockResolvedValue({ monitors: [monitor], evaluation_summaries: [{ monitor_id: monitor.id, evaluated_at: '2026-10-16T12:00:00Z', series: 10051, breaching: 1, no_data: 0, truncated: true }], evaluations: sample });
  render(<MetricMonitorsList />);
  expect(await screen.findByText('Breaching')).toBeTruthy();
  expect(screen.getByText(/1\/10051 series/)).toBeTruthy();
  expect(screen.queryByText('Within threshold')).toBeNull();
});
