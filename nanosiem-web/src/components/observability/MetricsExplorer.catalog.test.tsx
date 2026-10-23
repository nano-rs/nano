// @vitest-environment jsdom
// NAN-4098: the metric picker stays usable whatever the catalog is doing, and
// no dropdown is silently empty.
import type { ReactNode } from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MetricsExplorer, type MetricCatalogStatus } from './MetricsExplorer';
const { tags, series } = vi.hoisted(() => ({ tags: vi.fn(), series: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { observability: { listMetricTags: tags, queryMetricsV2: series } } }));
vi.mock('./MetricViz', () => ({ MetricViz: () => null }));
vi.mock('./MetricMonitorDialog', () => ({ MetricMonitorDialog: () => null }));
vi.mock('./AddMetricToDashboardDialog', () => ({ AddMetricToDashboardDialog: () => null }));
vi.mock('@/components/search/CachedNotice', () => ({ CachedNotice: () => null }));
vi.mock('@/components/search/footer-reporter', () => ({ useReportPhase2Status: () => {} }));
vi.mock('@/components/search/live-run-context', () => ({ useIsLiveRun: () => true }));
vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuItem: ({ children, onClick }: { children: ReactNode; onClick?: () => void }) =>
    <button onClick={onClick}>{children}</button>,
}));
const range = { start: '2026-10-18T00:45:00Z', end: '2026-10-18T01:00:00Z' };
const view = (names: string[], catalog: MetricCatalogStatus, initialMetric?: string) => (
  <MetricsExplorer metricNames={names} catalog={catalog} apiTimeRange={range} initialMetric={initialMetric} />
);
beforeEach(() => {
  tags.mockResolvedValue({ tag_keys: [] });
  series.mockResolvedValue({ series: [] });
});
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it('charts a typed metric name while the catalog is still loading', async () => {
  render(view([], { status: 'loading' }));
  expect(screen.getByRole('status').textContent).toContain('Loading metric catalog');
  const input = screen.getByRole('textbox', { name: 'Metric name' });
  fireEvent.change(input, { target: { value: 'axum_http_requests_total' } });
  fireEvent.keyDown(input, { key: 'Enter' });
  await waitFor(() => expect(series).toHaveBeenCalledWith(
    expect.objectContaining({ metric_name: 'axum_http_requests_total' }), expect.anything()));
});

it('shows the catalog error with retry and still accepts a typed name', async () => {
  const onRetry = vi.fn();
  render(view([], { status: 'error', message: 'Request timeout', onRetry }));
  expect(screen.getByRole('alert').textContent).toContain('Request timeout');
  expect(screen.getByText(/Metric catalog unavailable/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: /Retry/ }));
  expect(onRetry).toHaveBeenCalledTimes(1);
  fireEvent.change(screen.getByRole('textbox', { name: 'Metric name' }), { target: { value: 'go_goroutines' } });
  fireEvent.click(screen.getByRole('button', { name: /Use\s*go_goroutines/ }));
  await waitFor(() => expect(series).toHaveBeenCalledWith(
    expect.objectContaining({ metric_name: 'go_goroutines' }), expect.anything()));
});

it('filters the catalog by typed text and explains an empty catalog', () => {
  const first = render(view(['cpu_seconds', 'mem_bytes'], { status: 'ready' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Metric name' }), { target: { value: 'mem' } });
  expect(screen.getByRole('button', { name: 'mem_bytes' })).toBeTruthy();
  // Only the picker trigger (the selected metric) still names cpu_seconds.
  expect(screen.getAllByRole('button', { name: 'cpu_seconds' })).toHaveLength(1);
  first.unmount();
  render(view([], { status: 'ready' }));
  expect(screen.getByText(/No metrics in the catalog window/)).toBeTruthy();
});

it('honors a requested metric the catalog does not list', async () => {
  render(view([], { status: 'error', message: 'Request timeout' }, 'node_load1'));
  await waitFor(() => expect(series).toHaveBeenCalledWith(
    expect.objectContaining({ metric_name: 'node_load1' }), expect.anything()));
});

it('says why the group-by list is empty when tag discovery fails', async () => {
  tags.mockRejectedValue(new Error('boom'));
  render(view(['cpu'], { status: 'ready' }));
  expect(await screen.findByText('Could not load tags for this metric.')).toBeTruthy();
});
