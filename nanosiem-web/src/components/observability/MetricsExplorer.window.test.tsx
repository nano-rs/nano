// @vitest-environment jsdom
import type { ReactNode } from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MetricsExplorer } from './MetricsExplorer';
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
  DropdownMenuItem: ({ children, onClick, onSelect }: { children: ReactNode; onClick?: () => void; onSelect?: (event: { preventDefault(): void }) => void }) =>
    <button onClick={() => { onSelect?.({ preventDefault() {} }); onClick?.(); }}>{children}</button>,
}));
const first = { start: '2026-10-18T00:45:00Z', end: '2026-10-18T01:00:00Z' };
const next = { start: '2026-10-18T01:00:00Z', end: '2026-10-18T01:15:00Z' };
const view = (range = first) => <MetricsExplorer metricNames={['cpu']} apiTimeRange={range} />;
const filterKey = (key = 'host') => screen.getAllByRole('button', { name: key }).at(-1)!;
beforeEach(() => {
  tags.mockImplementation(async (_metric: string, key?: string) => key ? { tag_values: ['node-a'] } : { tag_keys: ['host'] });
  series.mockResolvedValue({ series: [] });
});
afterEach(() => { cleanup(); vi.resetAllMocks(); });
it('uses the chart window for both key and value discovery', async () => {
  render(view());
  await waitFor(() => expect(tags).toHaveBeenCalledWith('cpu', undefined, first));
  await screen.findAllByRole('button', { name: 'host' });
  fireEvent.click(filterKey());
  await screen.findByRole('button', { name: 'node-a' });
  expect(tags).toHaveBeenCalledWith('cpu', 'host', first);
});
it('refreshes tags on a range change while retaining the chosen group and filters', async () => {
  const root = render(view());
  await screen.findAllByRole('button', { name: 'host' });
  fireEvent.click(screen.getAllByRole('button', { name: 'host' })[0]);
  fireEvent.click(filterKey());
  fireEvent.click(await screen.findByRole('button', { name: 'node-a' }));
  root.rerender(view(next));
  await waitFor(() => expect(tags).toHaveBeenCalledWith('cpu', undefined, next));
  await waitFor(() => expect(series).toHaveBeenLastCalledWith(expect.objectContaining({
    time_range: next, group_by: 'host', filters: [{ key: 'host', value: 'node-a' }],
  }), expect.anything()));
  await screen.findAllByRole('button', { name: 'host' });
  fireEvent.click(filterKey());
  await waitFor(() => expect(tags).toHaveBeenCalledWith('cpu', 'host', next));
});
it('discards tag keys returned late for a previous chart window', async () => {
  let resolve!: (value: { tag_keys: string[] }) => void;
  tags.mockReturnValueOnce(new Promise(r => { resolve = r; })).mockResolvedValue({ tag_keys: ['new-key'] });
  const root = render(view());
  root.rerender(view(next));
  await screen.findAllByRole('button', { name: 'new-key' });
  await act(async () => resolve({ tag_keys: ['old-key'] }));
  expect(screen.queryByRole('button', { name: 'old-key' })).toBeNull();
});
it('discards late values after the range changes and a new request completes', async () => {
  let resolve!: (value: { tag_values: string[] }) => void;
  tags.mockImplementation((_metric: string, key: string | undefined, range: typeof first) => {
    if (!key) return Promise.resolve({ tag_keys: ['host'] });
    if (range.start === first.start) return new Promise(r => { resolve = r; });
    return Promise.resolve({ tag_values: ['new-value'] });
  });
  const root = render(view());
  await screen.findAllByRole('button', { name: 'host' });
  fireEvent.click(filterKey());
  root.rerender(view(next));
  await screen.findAllByRole('button', { name: 'host' });
  fireEvent.click(filterKey());
  await screen.findByRole('button', { name: 'new-value' });
  await act(async () => resolve({ tag_values: ['old-value'] }));
  expect(screen.queryByRole('button', { name: 'old-value' })).toBeNull();
  expect(screen.getByRole('button', { name: 'new-value' })).toBeTruthy();
});
it('does not transfer a previous tenant explorer response into a new instance', async () => {
  let resolve!: (value: { tag_keys: string[] }) => void;
  tags.mockReturnValueOnce(new Promise(r => { resolve = r; })).mockResolvedValue({ tag_keys: ['current-tenant-key'] });
  const previous = render(view());
  previous.unmount();
  render(view());
  await screen.findAllByRole('button', { name: 'current-tenant-key' });
  await act(async () => resolve({ tag_keys: ['previous-tenant-key'] }));
  expect(screen.queryByRole('button', { name: 'previous-tenant-key' })).toBeNull();
});
