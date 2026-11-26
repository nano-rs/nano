// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-5880: at the license hard stop the Agent Lane settings route renders the
// page (its Paused state keeps revoke and switch-off available) instead of the
// generic "not licensed" panel; the open edition and the boot fallback still
// get the panel.
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, test, vi } from 'vitest';
import type { BuildEdition, Capabilities } from '@/hooks/use-capabilities';
import app from '../App.tsx?raw';
import { SETTINGS_SECTIONS, isSectionVisible } from './layout/settings/sections';

const caps = vi.hoisted(() => ({
  value: { edition: 'enterprise', fallback: false, capabilities: {} } as {
    edition: BuildEdition;
    fallback: boolean;
    capabilities: Partial<Capabilities>;
  },
}));
vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => caps.value }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true }) }));

import { CapabilityRoute } from './CapabilityRoute';

afterEach(cleanup);

function renderRoute(edition: BuildEdition, fallback: boolean, agentLane: boolean, openWhenLicensePaused: boolean) {
  caps.value = { edition, fallback, capabilities: { agentLane } };
  render(
    <MemoryRouter>
      <CapabilityRoute capability="agentLane" openWhenLicensePaused={openWhenLicensePaused}>
        <p>agent lane page</p>
      </CapabilityRoute>
    </MemoryRouter>,
  );
}

describe('CapabilityRoute', () => {
  test('licensed: the page', () => {
    renderRoute('enterprise', false, true, false);
    expect(screen.getByText('agent lane page')).toBeTruthy();
  });

  test('enterprise build at the hard stop: the page when the route opts in', () => {
    renderRoute('enterprise', false, false, true);
    expect(screen.getByText('agent lane page')).toBeTruthy();
    expect(screen.queryByTestId('licensed-feature-unavailable')).toBeNull();
  });

  test('without the opt-in the hard stop still shows the unavailable panel', () => {
    renderRoute('enterprise', false, false, false);
    expect(screen.queryByText('agent lane page')).toBeNull();
    expect(screen.getByTestId('licensed-feature-unavailable')).toBeTruthy();
  });

  test.each([
    ['open edition', 'open' as const, false],
    ['boot fallback (verdict unknown)', 'enterprise' as const, true],
  ])('%s: never the page', (_name, edition, fallback) => {
    renderRoute(edition, fallback, false, true);
    expect(screen.queryByText('agent lane page')).toBeNull();
    expect(screen.getByTestId('licensed-feature-unavailable')).toBeTruthy();
  });
});

describe('Agent Lane route and Settings entry (NAN-5880)', () => {
  test('the route opts in to the paused-license page', () => {
    const route = app.slice(app.indexOf('<Route path="/settings/agentlane"'));
    expect(route.slice(0, 300)).toMatch(
      /<PermissionRoute permission="agentlane:manage" capability="agentLane" openWhenLicensePaused element=/,
    );
  });

  const section = SETTINGS_SECTIONS.find((s) => s.id === 'agentlane')!;
  const visible = (edition: BuildEdition, agentLane: boolean, perms: string[]) =>
    isSectionVisible(section, {
      capabilities: { agentLane } as unknown as Capabilities,
      edition,
      isDemoUser: false,
      isAirGap: false,
      hasPermission: (p) => perms.includes(p),
      hasAnyPermission: (ps) => ps.some((p) => perms.includes(p)),
    });

  test('the Settings entry stays reachable at the hard stop, never in the open edition', () => {
    expect(visible('enterprise', true, ['agentlane:manage'])).toBe(true);
    expect(visible('enterprise', false, ['agentlane:manage'])).toBe(true);
    expect(visible('open', false, ['agentlane:manage'])).toBe(false);
    expect(visible('enterprise', false, ['settings:system'])).toBe(false);
  });
});
