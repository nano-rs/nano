// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { TierWarning } from '../lib/api';

const mock = vi.hoisted(() => ({
  warnings: [] as TierWarning[],
  permissions: ['settings:system'] as string[],
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => mock.permissions.includes(p) }),
}));
vi.mock('../lib/api', async (importOriginal) => {
  const original = await importOriginal<typeof import('../lib/api')>();
  const tier = { getStatus: async () => ({ warnings: mock.warnings }) };
  return { ...original, api: { ...original.api, tier } };
});

import { CapacityWarningBanner } from './CapacityWarningBanner';

function renderBanner() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><CapacityWarningBanner /></QueryClientProvider>);
}

const volume = (percent: number): TierWarning => ({
  resource: 'daily_volume',
  current: 0,
  limit: 100,
  percent_used: percent,
  message: `Today's ingest is 38.5 GB against 1.0 GB/day (${percent.toLocaleString('en-US')}% of contracted capacity). Ingest is never blocked.`,
});

beforeEach(() => { mock.warnings = []; mock.permissions = ['settings:system']; });
afterEach(cleanup);

test('shows the true, uncapped percentage', async () => {
  mock.warnings = [volume(3846)];
  renderBanner();
  expect(await screen.findByText('3,846%')).toBeTruthy();
  expect(screen.getByText(/never blocked/)).toBeTruthy();
});

test('renders nothing without a daily volume warning or for non-admins', async () => {
  mock.warnings = [];
  const { container } = renderBanner();
  await new Promise((r) => setTimeout(r, 10));
  expect(container.textContent).toBe('');
  cleanup();
  mock.warnings = [volume(120)];
  mock.permissions = [];
  const second = renderBanner();
  await new Promise((r) => setTimeout(r, 10));
  expect(second.container.textContent).toBe('');
});
