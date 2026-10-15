// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
import { act, cleanup, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, expect, it, vi } from 'vitest';
import type { SearchStreamCallbacks } from '@/lib/api/types';
import { LateralView } from './index';
import { SearchFooterProvider } from '../footer-reporter';
const mocks = vi.hoisted(() => ({ stream: vi.fn(), queue: vi.fn(), artifact: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { searchStreamSSE: mocks.stream, searchAsync: mocks.queue, getSchemaFields: async () => ({ schema: 'ocsf' }) } }));
vi.mock('../durable-product-job', () => ({ waitForDurableProductArtifact: mocks.artifact }));
vi.mock('./LateralGraph', () => ({ LateralGraph: ({ nodes, edges }: { nodes: unknown[]; edges: unknown[] }) => <div data-testid="graph">{nodes.length} nodes / {edges.length} edges</div> }));
vi.mock('./LateralTopStrip', () => ({ LateralTopStrip: () => null }));
vi.mock('./LateralReasoningBand', () => ({ LateralReasoningBand: () => null }));
vi.mock('./LateralLegend', () => ({ LateralLegend: () => null }));
const range = { start: '2026-09-30T00:00:00Z', end: '2026-09-30T01:00:00Z' };
const marker = [{ id: 'marker', timestamp: new Date(), source: '', fields: { _display_type: 'lateral', _lateral_pending: true, _lateral_time_range: range } }];
function snapshot(count: number) {
  return [{ _display_type: 'lateral', _lateral_graph: {
    nodes: Array.from({ length: count + 1 }, (_, i) => ({ id: `n${i}`, type: 'host', label: `h${i}`, hop: i })),
    edges: Array.from({ length: count }, (_, i) => ({ from: `n${i}`, to: `n${i + 1}`, method: 'auth-rdp', count: 1 })),
    summary: { seed: { id: 'n0', kind: 'host' }, maxHops: 4 },
  } }];
}
afterEach(() => { cleanup(); vi.clearAllMocks(); });
it('paints first hop independently and grows the cumulative graph', () => {
  let callbacks!: SearchStreamCallbacks;
  const controller = new AbortController();
  mocks.stream.mockImplementation((_request, captured) => { callbacks = captured; return controller; });
  const mounted = render(<QueryClientProvider client={new QueryClient()}><LateralView results={marker} query='device.hostname="h0" | lateral' /></QueryClientProvider>);
  expect(screen.getByRole('status').textContent).toContain('first hop');
  act(() => callbacks.onViewUpdate?.({ view: 'lateral', rows: snapshot(1), completed_hops: 1, complete: false }));
  expect(screen.getByTestId('graph').textContent).toContain('2 nodes / 1 edges');
  expect(screen.getByRole('status').textContent).toContain('1 hops');
  act(() => callbacks.onViewUpdate?.({ view: 'lateral', rows: snapshot(2), completed_hops: 2, complete: false }));
  expect(screen.getByTestId('graph').textContent).toContain('3 nodes / 2 edges');
  act(() => callbacks.onViewUpdate?.({ view: 'lateral', rows: snapshot(2), completed_hops: 2, complete: true }));
  expect(screen.queryByRole('status')).toBeNull();
  mounted.unmount();
  expect(controller.signal.aborted).toBe(true);
});
it('aborts the old pivot and ignores its late update without aborting the new one', () => {
  const callbacks: SearchStreamCallbacks[] = [];
  const controllers: AbortController[] = [];
  mocks.stream.mockImplementation((_request, captured) => {
    callbacks.push(captured); const controller = new AbortController(); controllers.push(controller); return controller;
  });
  const client = new QueryClient();
  const panel = (query: string) => <QueryClientProvider client={client}><LateralView results={marker} query={query} /></QueryClientProvider>;
  const mounted = render(panel('device.hostname="old" | lateral'));
  mounted.rerender(panel('device.hostname="new" | lateral'));
  expect(controllers[0].signal.aborted).toBe(true);
  expect(controllers[1].signal.aborted).toBe(false);
  act(() => callbacks[0].onViewUpdate?.({ view: 'lateral', rows: snapshot(2), completed_hops: 2, complete: false }));
  expect(screen.queryByTestId('graph')).toBeNull();
});

it('reports loading until completion and the real final edge count', () => {
  let callbacks!: SearchStreamCallbacks;
  mocks.stream.mockImplementation((_request, captured) => { callbacks = captured; return new AbortController(); });
  const report = vi.fn();
  render(<QueryClientProvider client={new QueryClient()}><SearchFooterProvider value={report}><LateralView results={marker} query='device.hostname="h0" | lateral' /></SearchFooterProvider></QueryClientProvider>);
  expect(report).toHaveBeenLastCalledWith({ loading: true });
  const rows = snapshot(2).map(row => ({ ...row, _lateral_config: { total_edges: 7 } }));
  act(() => callbacks.onViewUpdate?.({ view: 'lateral', rows, completed_hops: 2, complete: true }));
  expect(report).toHaveBeenLastCalledWith({ loading: true });
  act(() => callbacks.onCompleted?.({} as never));
  expect(report).toHaveBeenLastCalledWith(expect.objectContaining({ loading: false, totalCount: 7 }));
});

it('keeps the partial graph while a durable trace finishes and queues only once', async () => {
  let callbacks!: SearchStreamCallbacks;
  let finish!: (value: unknown) => void;
  mocks.queue.mockResolvedValue({ job_id: 'trace-1' });
  mocks.artifact.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  mocks.stream.mockImplementation((_request, captured) => { callbacks = captured; return new AbortController(); });
  render(<QueryClientProvider client={new QueryClient()}><LateralView results={marker} query='device.hostname="h0" | lateral' /></QueryClientProvider>);
  act(() => callbacks.onViewUpdate?.({ view: 'lateral', rows: snapshot(1), completed_hops: 1, complete: false }));
  await act(async () => { callbacks.onCompleted?.({} as never); callbacks.onError?.({} as never); });
  expect(mocks.queue).toHaveBeenCalledTimes(1);
  expect(screen.getByTestId('graph').textContent).toContain('2 nodes / 1 edges');
  await act(async () => finish({ row: { operation: 'lateral', response: { results: snapshot(3) } } }));
  expect(screen.getByTestId('graph').textContent).toContain('4 nodes / 3 edges');
  expect(screen.queryByRole('status')).toBeNull();
});

it('reports a failed durable trace as incomplete while preserving its partial graph', async () => {
  let callbacks!: SearchStreamCallbacks;
  mocks.queue.mockResolvedValue({ job_id: 'trace-failed' });
  mocks.artifact.mockRejectedValue(new Error('identity coverage is incomplete'));
  mocks.stream.mockImplementation((_request, captured) => { callbacks = captured; return new AbortController(); });
  render(<QueryClientProvider client={new QueryClient()}><LateralView results={marker} query='device.hostname="h0" | lateral' /></QueryClientProvider>);
  act(() => callbacks.onViewUpdate?.({ view: 'lateral', rows: snapshot(1), completed_hops: 1, complete: false }));
  await act(async () => callbacks.onCompleted?.({} as never));
  expect(screen.getByTestId('graph').textContent).toContain('2 nodes / 1 edges');
  expect(screen.getByText(/Traversal is incomplete: identity coverage/)).toBeTruthy();
});

it('aborts a superseded job poll and ignores its late artifact', async () => {
  const callbacks: SearchStreamCallbacks[] = [];
  let finish!: (value: unknown) => void;
  mocks.queue.mockResolvedValue({ job_id: 'old-trace' });
  mocks.artifact.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  mocks.stream.mockImplementation((_request, captured) => { callbacks.push(captured); return new AbortController(); });
  const client = new QueryClient();
  const panel = (query: string) => <QueryClientProvider client={client}><LateralView results={marker} query={query} /></QueryClientProvider>;
  const mounted = render(panel('device.hostname="old" | lateral'));
  await act(async () => callbacks[0].onCompleted?.({} as never));
  const signal = mocks.artifact.mock.calls[0][4] as AbortSignal;
  mounted.rerender(panel('device.hostname="new" | lateral'));
  expect(signal.aborted).toBe(true);
  await act(async () => finish({ row: { operation: 'lateral', response: { results: snapshot(3) } } }));
  expect(screen.queryByTestId('graph')).toBeNull();
});
