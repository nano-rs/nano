// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { LicenseStatusResponse } from '../lib/api';

const mock = vi.hoisted(() => ({ status: null as LicenseStatusResponse | null, permissions: ['settings:system'] as string[] }));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ edition: 'enterprise', version: 'test', capabilities: {} }),
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => mock.permissions.includes(p) }),
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

beforeEach(() => { mock.status = null; mock.permissions = ['settings:system']; });
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

const rejected = (): LicenseStatusResponse => ({
  state: 'active',
  valid: true,
  enforcement_enabled: true,
  mode: 'hosted',
  recovery_epoch: 0,
  recovery_required: false,
  components: [],
  token_rejected: {
    http_status: 401,
    first_rejected_at: '2026-11-09T12:00:00Z',
    last_rejected_at: '2026-11-09T12:00:00Z',
    locks_at: '2026-11-15T09:00:00Z',
    message: 'License token was rejected by app.nano.rs. Update LICENSE_TOKEN in .env and re-run ./install.sh. This install locks on 2026-11-15 09:00 UTC (14 days after the last successful check-in).',
  },
});

test('NAN-5194: a rejected license token shows the fix and lock date to admins', async () => {
  mock.status = rejected();
  render(<MemoryRouter><LicenseBanner /></MemoryRouter>);
  expect(await screen.findByText('License token rejected')).toBeTruthy();
  expect(screen.getByText(/Update LICENSE_TOKEN in .env and re-run .\/install.sh/)).toBeTruthy();
  expect(screen.getByText(/locks on 2026-11-15 09:00 UTC/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: /dismiss/i })).toBeNull();
});

test('NAN-5194: non-admins never see the token banner; an active status without it shows nothing', async () => {
  mock.status = rejected();
  mock.permissions = [];
  const { container, unmount } = render(<MemoryRouter><LicenseBanner /></MemoryRouter>);
  await waitFor(() => expect(container.textContent ?? '').toBe(''));
  unmount();
  mock.permissions = ['settings:system'];
  mock.status = { ...rejected(), token_rejected: undefined };
  const second = render(<MemoryRouter><LicenseBanner /></MemoryRouter>);
  await waitFor(() => expect(second.container.textContent ?? '').toBe(''));
});
