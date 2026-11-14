// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-5382: the compliance-export Settings entry and route follow the license
// (`complianceExport`) and the `compliance:export` permission. Without either,
// no nav entry, landing card or button leads to the page.
import { readFileSync } from 'node:fs';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, test, vi } from 'vitest';
import type { BuildEdition, Capabilities } from '@/hooks/use-capabilities';

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: () => false }),
}));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ edition: 'enterprise', capabilities: {} }),
}));

import { LicensedFeatureUnavailable } from '@/components/LicensedFeatureUnavailable';
import { SETTINGS_SECTIONS, isSectionVisible } from './sections';

afterEach(cleanup);

const section = SETTINGS_SECTIONS.find(s => s.href === '/settings/compliance/evidence-pack')!;

function visible({
  licensed,
  permitted,
  edition = 'enterprise',
}: { licensed: boolean | undefined; permitted: boolean; edition?: BuildEdition }) {
  return isSectionVisible(section, {
    capabilities: { complianceExport: licensed } as Capabilities,
    edition,
    isDemoUser: false,
    isAirGap: false,
    hasPermission: p => permitted && p === 'compliance:export',
    hasAnyPermission: ps => permitted && ps.includes('compliance:export'),
  });
}

describe('compliance-export Settings entry', () => {
  test('is gated on the complianceExport capability and compliance:export', () => {
    expect(section.capability).toBe('complianceExport');
    expect(section.permissions).toBe('compliance:export');
  });

  test('capability off: hidden even for an admin holding compliance:export', () => {
    expect(visible({ licensed: false, permitted: true })).toBe(false);
    // Older APIs omit the flag; absent means off.
    expect(visible({ licensed: undefined, permitted: true })).toBe(false);
    // Open build: the API answers false, so the entry never appears.
    expect(visible({ licensed: false, permitted: true, edition: 'open' })).toBe(false);
  });

  test('permission off: hidden on a licensed install', () => {
    expect(visible({ licensed: true, permitted: false })).toBe(false);
  });

  test('both on: visible', () => {
    expect(visible({ licensed: true, permitted: true })).toBe(true);
  });
});

describe('compliance-export route', () => {
  test('carries both the permission and the license capability guard', () => {
    const app = readFileSync('src/App.tsx', 'utf8');
    const route = app.match(/<Route path="\/settings\/compliance\/evidence-pack"[\s\S]*?<PermissionRoute ([^>]*?) element=/);
    expect(route?.[1]).toContain('permission="compliance:export"');
    expect(route?.[1]).toContain('capability="complianceExport"');
  });

  test('capability off: the route renders the shared not-licensed page, naming the surface', () => {
    render(<MemoryRouter><LicensedFeatureUnavailable capability="complianceExport" /></MemoryRouter>);
    expect(screen.getByTestId('licensed-feature-unavailable')).toBeTruthy();
    expect(screen.getByRole('heading').textContent).toBe('Compliance export is not licensed');
  });
});
