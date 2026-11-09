// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { UpdateStatusResponse } from '../lib/api';

const mock = vi.hoisted(() => ({
  status: null as UpdateStatusResponse | null,
  edition: 'enterprise' as 'enterprise' | 'open',
  permissions: ['settings:system'] as string[],
  calls: 0,
}));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ edition: mock.edition, version: '2.0.0', capabilities: {} }),
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => mock.permissions.includes(p) }),
}));
vi.mock('../lib/api', async (importOriginal) => {
  const original = await importOriginal<typeof import('../lib/api')>();
  return { ...original, api: { ...original.api, getUpdateStatus: async () => { mock.calls += 1; return mock.status; } } };
});

import { UpdateAvailableBanner } from './UpdateAvailableBanner';
import { UPDATE_BANNER_DISMISSED_KEY, shouldShowUpdateBanner } from '../lib/update-banner';

const update = (over: Partial<UpdateStatusResponse> = {}): UpdateStatusResponse => ({
  current_version: '2.0.0', update_available: true, latest_version: '2.0.1', security_release: false,
  release_notes_url: 'https://nano.rs/docs/releases/v2-0-1', upgrade_url: 'https://nano.rs/docs/releases/upgrading', ...over,
});

function renderBanner() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><UpdateAvailableBanner /></QueryClientProvider>);
}

beforeEach(() => {
  mock.status = null; mock.edition = 'enterprise'; mock.permissions = ['settings:system']; mock.calls = 0;
  window.localStorage.clear();
});
afterEach(cleanup);

test('banner logic: newer release with links, not dismissed for that version', () => {
  expect(shouldShowUpdateBanner(update(), null)).toBe(true);
  expect(shouldShowUpdateBanner(update(), '2.0.1')).toBe(false);
  expect(shouldShowUpdateBanner(update(), '2.0.0')).toBe(true); // an older dismissal does not hide a newer release
  expect(shouldShowUpdateBanner(update({ update_available: false }), null)).toBe(false);
  expect(shouldShowUpdateBanner(update({ latest_version: null }), null)).toBe(false);
  expect(shouldShowUpdateBanner(update({ upgrade_url: null }), null)).toBe(false);
  expect(shouldShowUpdateBanner(null, null)).toBe(false);
});

test('shows the update with release notes and upgrade links', async () => {
  mock.status = update();
  renderBanner();
  expect(await screen.findByText('v2.0.1')).toBeTruthy();
  expect(screen.getByText('Release notes').getAttribute('href')).toBe('https://nano.rs/docs/releases/v2-0-1');
  expect(screen.getByText('How to upgrade').getAttribute('href')).toBe('https://nano.rs/docs/releases/upgrading');
  expect(screen.queryByText(/security fixes/)).toBeNull();
});

test('a security release says so', async () => {
  mock.status = update({ security_release: true });
  renderBanner();
  expect(await screen.findByText('Includes security fixes, upgrade recommended.')).toBeTruthy();
});

test('dismissal is remembered per version', async () => {
  mock.status = update();
  const first = renderBanner();
  fireEvent.click(await screen.findByLabelText('Dismiss update v2.0.1'));
  expect(screen.queryByText('v2.0.1')).toBeNull();
  expect(window.localStorage.getItem(UPDATE_BANNER_DISMISSED_KEY)).toBe('2.0.1');
  first.unmount();

  renderBanner();
  await waitFor(() => expect(mock.calls).toBeGreaterThan(1));
  expect(screen.queryByText('v2.0.1')).toBeNull();
  cleanup();

  mock.status = update({ latest_version: '2.0.2', release_notes_url: 'https://nano.rs/docs/releases/v2-0-2' });
  renderBanner();
  expect(await screen.findByText('v2.0.2')).toBeTruthy();
});

test('never polls or renders for non-admins or the open edition', async () => {
  mock.status = update();
  mock.permissions = [];
  renderBanner();
  cleanup();
  mock.permissions = ['settings:system'];
  mock.edition = 'open';
  renderBanner();
  await new Promise((r) => setTimeout(r, 20));
  expect(mock.calls).toBe(0);
  expect(screen.queryByText('v2.0.1')).toBeNull();
});
