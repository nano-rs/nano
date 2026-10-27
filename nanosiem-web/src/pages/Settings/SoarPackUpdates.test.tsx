// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { browserTenantRuntime } from '@/lib/tenant-runtime';
const mock = vi.hoisted(() => ({ view: true, manage: true, get: vi.fn(), one: vi.fn(), all: vi.fn() }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: (p: string) => p === 'soar:view' ? mock.view : p === 'soar:manage' && mock.manage }) }));
vi.mock('@/lib/api', () => ({ api: { soar: { getUpstreamUpdates: mock.get, applyUpstreamUpdate: mock.one, applyAllUpstreamUpdates: mock.all } } }));
import { SoarPackUpdates } from './SoarPackUpdates';
const update = { pack_name: 'okta', display_name: 'Okta', installed_version: '1.0.0', upstream_version: '2.0.0', change_summary: 'Verified update' };
function mount(enabled = true) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><SoarPackUpdates enabled={enabled} /></QueryClientProvider>);
  return { client, ...view };
}
beforeEach(() => {
  mock.view = true; mock.manage = true;
  mock.get.mockReset().mockResolvedValue({ updates: [update], total_count: 1 });
  mock.one.mockReset().mockResolvedValue({ packs: [], upstream_changed_count: 0 });
  mock.all.mockReset();
});
afterEach(cleanup);
async function confirmOne() {
  await screen.findByText('1 imported pack has upstream updates');
  fireEvent.click(screen.getByRole('button', { name: 'Review' }));
  fireEvent.click(screen.getByRole('button', { name: 'Apply Update' }));
  expect(mock.one).not.toHaveBeenCalled();
  const dialog = screen.getByRole('alertdialog');
  expect(within(dialog).getByText(/Active runs using older versions/)).toBeTruthy();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Apply Update' }));
}

test('disabled and unauthorized surfaces do not read the tenant catalog', () => {
  const first = mount(false); expect(mock.get).not.toHaveBeenCalled(); first.unmount();
  mock.view = false; mount(); expect(mock.get).not.toHaveBeenCalled(); expect(screen.queryByText('Pack updates')).toBeNull();
});
test('viewers get the upstream count and Review list without apply controls', async () => {
  mock.manage = false; const { client } = mount();
  await screen.findByText('1 imported pack has upstream updates');
  fireEvent.click(screen.getByRole('button', { name: 'Review' }));
  expect(screen.getByText('1.0.0 → 2.0.0')).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Apply Update' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Apply All Updates' })).toBeNull();
  expect(client.getQueryData(['soar-upstream-updates', browserTenantRuntime.current().key])).toEqual({ updates: [update], total_count: 1 });
});
test('apply-one waits for confirmation and sends the displayed signed version', async () => {
  mount(); await confirmOne();
  await waitFor(() => expect(mock.one).toHaveBeenCalledWith('okta', '2.0.0'));
  expect(mock.all).not.toHaveBeenCalled();
  await screen.findByText('1 updated · 0 failed');
  await waitFor(() => expect(mock.get.mock.calls.length).toBeGreaterThan(1));
});
test('apply-all reports individual refusals and refreshes remaining updates', async () => {
  mock.all.mockResolvedValue({ updated: 1, failed: 1, results: [
    { pack_name: 'okta', updated: true, version: '2.0.0', message: 'Update applied' },
    { pack_name: 'other', updated: false, version: null, message: 'Existing credentials are incompatible' },
  ] });
  mount(); await screen.findByText('1 imported pack has upstream updates');
  fireEvent.click(screen.getByRole('button', { name: 'Apply All Updates' }));
  expect(mock.all).not.toHaveBeenCalled();
  fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Apply All Updates' }));
  await screen.findByText('1 updated · 1 failed');
  expect(screen.getByText('other: Existing credentials are incompatible')).toBeTruthy();
  expect(mock.one).not.toHaveBeenCalled();
});
test('stale catalog refuses discovery without claiming there are no updates', async () => {
  mock.get.mockRejectedValue(Object.assign(new Error('Signed catalog is not current'), { status: 409 }));
  mount(); await screen.findByText('Signed catalog is not current');
  expect(screen.queryByText('No upstream updates')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Apply All Updates' })).toBeNull();
});
test('apply conflicts are surfaced and refetched without an automatic retry', async () => {
  mock.one.mockRejectedValue(Object.assign(new Error('Signed version changed; refresh'), { status: 409 }));
  mount(); await confirmOne();
  await screen.findByText('Signed version changed; refresh');
  expect(mock.one).toHaveBeenCalledTimes(1);
  await waitFor(() => expect(mock.get.mock.calls.length).toBeGreaterThan(1));
});

test('a stale refetch hides apply controls even when older update data is cached', async () => {
  const { client } = mount();
  await screen.findByText('1 imported pack has upstream updates');
  mock.get.mockRejectedValue(Object.assign(new Error('Signed catalog expired'), { status: 409 }));
  await client.invalidateQueries({ queryKey: ['soar-upstream-updates', browserTenantRuntime.current().key] });
  await screen.findByText('Signed catalog expired');
  expect(screen.queryByRole('button', { name: 'Apply All Updates' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Review' })).toBeNull();
});
