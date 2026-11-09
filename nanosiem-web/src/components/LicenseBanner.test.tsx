// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { LicenseStatusResponse } from '../lib/api';

const mock = vi.hoisted(() => ({ status: null as LicenseStatusResponse | null }));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ edition: 'enterprise', version: 'test', capabilities: {} }),
}));
vi.mock('../lib/api', async (importOriginal) => {
  const original = await importOriginal<typeof import('../lib/api')>();
  return { ...original, api: { ...original.api, getLicenseStatus: async () => mock.status } };
});

import { LicenseBanner } from './LicenseBanner';

function trialStatus(state: 'active' | 'grace_period' | 'locked', days: number, warningDays?: 14 | 7 | 1 | 0 | null): LicenseStatusResponse {
  return {
    state,
    valid: state === 'active',
    locked_reason: state === 'locked' ? 'Trial grace period ended.' : undefined,
    enforcement_enabled: true,
    mode: 'hosted',
    recovery_epoch: 0,
    recovery_required: false,
    components: [],
    entitlement: {
      license_id: 'lic_trial',
      edition: 'licensed',
      operator: 'self-run',
      offering: 'self-run',
      kind: 'trial',
      capacity_gb_per_day: null,
      starts_at: '2026-01-01T00:00:00Z',
      expires_at: '2026-04-01T00:00:00Z',
      grace_ends_at: '2026-04-08T00:00:00Z',
      revision: 1,
      days_remaining: days,
      warning_days: warningDays,
    },
  };
}

beforeEach(() => { mock.status = null; });
afterEach(cleanup);

test('shows the exact trial countdown and warning boundary', async () => {
  mock.status = trialStatus('active', 14, 14);
  render(<MemoryRouter><LicenseBanner /></MemoryRouter>);
  expect(await screen.findByText('Trial — 14 days left')).toBeTruthy();
  expect(screen.getByText(/14-day expiry warning/)).toBeTruthy();
});

test('expired trial keeps core access instead of rendering the paid lockout overlay', async () => {
  mock.status = trialStatus('locked', 0, 0);
  render(<MemoryRouter><LicenseBanner /></MemoryRouter>);
  expect(await screen.findByText('Trial — 0 days left')).toBeTruthy();
  expect(screen.getByText(/search, ingest, and all stored data remain available/)).toBeTruthy();
  await waitFor(() => expect(screen.queryByText('Subscription Expired')).toBeNull());
});

test.each([undefined, null] as const)('an active trial with more than 14 days left shows no warning (warning_days=%s)', async (warningDays) => {
  mock.status = trialStatus('active', 60, warningDays);
  const { container } = render(<MemoryRouter><LicenseBanner /></MemoryRouter>);
  await waitFor(() => expect(screen.queryByText(/expiry warning/)).toBeNull());
  expect(screen.queryByText(/Trial — 60 days left/)).toBeNull();
  expect(container.textContent ?? '').not.toContain('null-day');
});
