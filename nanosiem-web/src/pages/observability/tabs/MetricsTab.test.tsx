// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MetricsTab, MAX_METRIC_PANELS } from './MetricsTab';
import type { MetricCatalogStatus } from '@/components/observability/MetricsExplorer';
const mocks = vi.hoisted(() => ({ names: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { observability: { listMetricNames: mocks.names } } }));
vi.mock('@/components/observability/MetricsExplorer', () => ({
  MetricsExplorer: ({ metricNames, catalog, onRemove }: { metricNames: string[]; catalog: MetricCatalogStatus; onRemove?: () => void }) => (
    <div data-testid="explorer">
      Explorer {metricNames.join(',')} [{catalog.status}]
      {onRemove && <button onClick={onRemove}>Remove panel</button>}
    </div>
  ),
}));
vi.mock('@/components/observability/MetricMonitorsList', () => ({ MetricMonitorsList: () => <div>Monitors</div> }));
vi.mock('@/components/observability/TelemetrySetupHint', () => ({ TelemetrySetupHint: () => null }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });
const range = { start: '2026-10-16T20:00:00Z', end: '2026-10-16T20:15:00Z' };
function view(client: QueryClient) {
 return <QueryClientProvider client={client}><MetricsTab apiTimeRange={range} timeRange={{ type: 'preset', preset: '15m' }} onOpenService={() => {}} onOpenTrace={() => {}} /></QueryClientProvider>;
}
it('renders one explorer and monitors while a slow catalog is pending', () => {
 mocks.names.mockReturnValue(new Promise(() => {}));
 render(view(new QueryClient()));
 expect(screen.getByText('Monitors')).toBeTruthy();
 expect(screen.getAllByTestId('explorer')).toHaveLength(1);
 expect(screen.getByTestId('explorer').textContent).toContain('[loading]');
 expect(screen.getByRole('status').textContent).toContain('Loading metric catalog');
 expect(screen.getByRole('button', { name: /Add panel/ })).toBeTruthy();
});
// NAN-4098: the explorer and the monitors list once shared a React key, so each
// catalog transition left a stale explorer mounted (three panels on ops).
it('keeps exactly one panel through the catalog pending -> ready transition', async () => {
 let resolve!: (v: unknown) => void;
 mocks.names.mockReturnValue(new Promise((r) => { resolve = r; }));
 render(view(new QueryClient()));
 expect(screen.getAllByTestId('explorer')).toHaveLength(1);
 await act(async () => resolve({ names: [{ metric_name: 'cpu' }], count: 1 }));
 await screen.findByText(/Explorer cpu \[ready\]/);
 expect(screen.getAllByTestId('explorer')).toHaveLength(1);
 expect(screen.getAllByText('Monitors')).toHaveLength(1);
});
it('adds and removes panels, never below one or above the cap', async () => {
 mocks.names.mockResolvedValue({ names: [{ metric_name: 'cpu' }], count: 1 });
 render(view(new QueryClient()));
 await screen.findByText(/Explorer cpu/);
 expect(screen.queryByRole('button', { name: 'Remove panel' })).toBeNull();
 const add = screen.getByRole('button', { name: /Add panel/ });
 fireEvent.click(add);
 expect(screen.getAllByTestId('explorer')).toHaveLength(2);
 fireEvent.click(screen.getAllByRole('button', { name: 'Remove panel' })[0]);
 expect(screen.getAllByTestId('explorer')).toHaveLength(1);
 for (let i = 0; i < MAX_METRIC_PANELS + 2; i++) fireEvent.click(add);
 expect(screen.getAllByTestId('explorer')).toHaveLength(MAX_METRIC_PANELS);
 expect((add as HTMLButtonElement).disabled).toBe(true);
});
it('reuses a fresh catalog on remount', async () => {
 mocks.names.mockResolvedValue({ names: [{ metric_name: 'ops_metric' }], count: 1 });
 const client = new QueryClient();
 const first = render(view(client));
 await screen.findByText(/Explorer ops_metric/);
 first.unmount();
 render(view(client));
 expect(screen.getByText(/Explorer ops_metric/)).toBeTruthy();
 expect(mocks.names).toHaveBeenCalledTimes(1);
 client.clear();
});
it('shows the catalog error with a retry and keeps the explorer usable', async () => {
 mocks.names.mockRejectedValueOnce(new Error('Request timeout'));
 render(view(new QueryClient()));
 const alert = await screen.findByRole('alert');
 expect(alert.textContent).toContain('Request timeout');
 expect(screen.getByText('Monitors')).toBeTruthy();
 expect(screen.getByTestId('explorer').textContent).toContain('[error]');
 mocks.names.mockResolvedValueOnce({ names: [{ metric_name: 'cpu' }], count: 1 });
 fireEvent.click(screen.getByRole('button', { name: /Retry/ }));
 await screen.findByText(/Explorer cpu \[ready\]/);
 expect(mocks.names).toHaveBeenCalledTimes(2);
 expect(screen.queryByRole('alert')).toBeNull();
});
it('describes a capped catalog as capped, not warming', async () => {
 mocks.names.mockResolvedValue({ names: [{ metric_name: 'cpu' }], count: 1, partial: true, window_start: '2026-10-18T22:00:00Z' });
 render(view(new QueryClient()));
 expect(await screen.findByText(/catalog is capped/)).toBeTruthy();
 expect(screen.getByText(/Type a name in the picker/)).toBeTruthy();
 expect(screen.queryByText(/fills in shortly/)).toBeNull();
});
it('names the empty catalog instead of an empty dropdown', async () => {
 mocks.names.mockResolvedValue({ names: [], count: 0 });
 render(view(new QueryClient()));
 expect(await screen.findByText(/No metrics ingested in the last 24 h/)).toBeTruthy();
 expect(screen.getAllByTestId('explorer')).toHaveLength(1);
});
