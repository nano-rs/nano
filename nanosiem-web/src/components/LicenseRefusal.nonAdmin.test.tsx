// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-5310: license refusals name the feature and offer a license CTA only to
// roles that can manage the license; everyone else is told to ask an admin.
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, test, vi } from 'vitest';
import type { LicenseStatusResponse } from '@/lib/api';

const perms = vi.hoisted(() => ({ value: new Set<string>() }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => perms.value.has(p) }),
}));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ edition: 'enterprise', capabilities: {} }),
}));

import { ASK_ADMIN, LicenseHardStopBanner } from './LicenseBanner';
import { LicensedFeatureUnavailable } from './LicensedFeatureUnavailable';
import { SETTINGS_SECTIONS, isSectionVisible } from './layout/settings/sections';
import type { Capabilities } from '@/hooks/use-capabilities';

afterEach(cleanup);

const locked = {
  state: 'locked',
  mode: 'offline',
  enforcement_enabled: true,
  locked_reason: 'No license is installed.',
} as unknown as LicenseStatusResponse;

test('hard-stop banner: non-admins get "ask your administrator", no Import CTA', () => {
  render(<MemoryRouter><LicenseHardStopBanner status={locked} canManageLicense={false} /></MemoryRouter>);
  expect(screen.queryByText('Import license')).toBeNull();
  expect(screen.getByText(new RegExp(ASK_ADMIN))).toBeTruthy();
  expect(screen.queryByText(/C05/)).toBeNull();
});

test('hard-stop banner: license managers keep the Import CTA', () => {
  render(<MemoryRouter><LicenseHardStopBanner status={locked} canManageLicense /></MemoryRouter>);
  expect(screen.getByText('Import license').closest('a')?.getAttribute('href')).toBe('/settings/license');
});

test('refusal page names the feature; only settings:system gets the License link', () => {
  perms.value = new Set();
  render(<MemoryRouter><LicensedFeatureUnavailable capability="cases" /></MemoryRouter>);
  expect(screen.getByRole('heading').textContent).toBe('Cases is not licensed');
  expect(screen.queryByText(/Settings > License/)).toBeNull();
  expect(screen.getByText(/Ask your administrator/)).toBeTruthy();
  cleanup();

  perms.value = new Set(['settings:system']);
  render(<MemoryRouter><LicensedFeatureUnavailable capability="soar" /></MemoryRouter>);
  expect(screen.getByRole('heading').textContent).toBe('SOAR automation is not licensed');
  expect(screen.getByText(/Settings > License/).closest('a')?.getAttribute('href')).toBe('/settings/license');
});

test('License is in the Settings nav on an unlicensed, non-air-gapped enterprise build', () => {
  const license = SETTINGS_SECTIONS.find(s => s.id === 'license')!;
  expect(license.label).toBe('License');
  const ctx = {
    capabilities: {} as Capabilities,
    isDemoUser: false,
    isAirGap: false,
    hasPermission: (p: string) => p === 'settings:system',
    hasAnyPermission: () => false,
  };
  expect(isSectionVisible(license, { ...ctx, edition: 'enterprise' })).toBe(true);
  expect(isSectionVisible(license, { ...ctx, edition: 'open' })).toBe(false);
  expect(isSectionVisible(license, { ...ctx, edition: 'enterprise', hasPermission: () => false })).toBe(false);
});
