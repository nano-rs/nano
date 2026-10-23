// @vitest-environment jsdom
import { afterEach, beforeAll, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { InfraTab } from './InfraTab';
const mocks = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { observability: { getInfraHosts: mocks.get } } }));
const range = { type: 'preset' as const, preset: '15m' as const };
const node = { host: 'cluster/node-a', node_name: 'node-a', kind: 'node', group: 'cluster/region/lake-cells', instance_type: 'compute1-30', cpu_pct: null, mem_pct: null, load: null, net_bytes_per_sec: null, status: 'unknown' };
const pod = { host: 'cluster/runtime/api-abc', kind: 'pod', pod_name: 'api-abc', namespace: 'runtime', workload: 'api', node_name: 'node-a', cluster: 'cluster', region: 'region', group: 'cluster/region/runtime/api', phase: 'Running', status: 'warn', cpu_cores: 0, mem_bytes: 10485760, restarts: 3, cpu_pct: null, mem_pct: null, load: null, net_bytes_per_sec: null };
afterEach(() => { cleanup(); vi.clearAllMocks(); });
beforeAll(() => { Element.prototype.scrollIntoView = vi.fn(); });
function view() { return render(<MemoryRouter><InfraTab timeRange={range} apiTimeRange={{ start: '', end: '' }} onOpenService={() => {}} onOpenTrace={() => {}} /></MemoryRouter>); }
it('uses the app loader while inventory is pending', () => {
  mocks.get.mockReturnValue(new Promise(() => {}));
  const { container } = view();
  expect(container.querySelector('.nano-loading-icon')).toBeTruthy();
  expect(container.querySelector('.animate-spin')).toBeNull();
});
it('separates nodes and pods, shows missing samples, and shares environment/health filters', async () => {
  mocks.get.mockResolvedValue({ hosts: [node, pod], total: 2, has_more: false });
  const { container } = view();
  expect(await screen.findByText('1 hosts · no CPU samples in range')).toBeTruthy();
  expect(container.querySelector('select:not([aria-hidden="true"])')).toBeNull();
  expect(screen.queryByText('api-abc')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Degraded' }));
  await waitFor(() => expect(mocks.get.mock.lastCall?.[1].status).toBe('warn'));
  fireEvent.change(screen.getByLabelText('Filter by deployment environment'), { target: { value: 'production' } });
  await waitFor(() => expect(mocks.get.mock.lastCall?.[1].env).toBe('production'));
  fireEvent.keyDown(screen.getByRole('combobox', { name: 'Infrastructure view' }), { key: 'Enter' });
  fireEvent.click(await screen.findByRole('option', { name: 'Pods / workloads' }));
  expect(await screen.findByText('api-abc')).toBeTruthy();
  expect(screen.getByText('0.000')).toBeTruthy();
  expect(screen.getByText('10.0 MiB')).toBeTruthy();
  expect(screen.getByText('Running · Degraded')).toBeTruthy();
  expect(mocks.get.mock.lastCall?.[1]).toMatchObject({ env: 'production', status: 'warn' });
});
