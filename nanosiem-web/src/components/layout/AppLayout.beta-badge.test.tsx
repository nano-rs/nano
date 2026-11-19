// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-5654: Hunts and Automation are early access, so their rail entries carry
// the BETA badge (beside the label when expanded, in the Automation flyout when
// collapsed). Everything else in the rail stays unbadged, and with the hunts
// capability off and automation disabled (the open-core shape) no badge renders.
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { Workflow, List } from 'lucide-react';

const { Nothing } = vi.hoisted(() => ({ Nothing: () => null }));
const mock = vi.hoisted(() => ({
  hunts: true,
  automationItems: [] as Array<{ name: string; href: string; icon: unknown }>,
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 'u1', name: 'Test Analyst', roles: ['analyst'] },
    logout: vi.fn(),
    hasPermission: () => true,
    hasAnyPermission: () => true,
    isDemoUser: false,
  }),
}));
vi.mock('@/hooks/use-api', () => ({ useOnboardingProgress: () => ({ data: null }) }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    edition: 'enterprise',
    version: 'test',
    capabilities: new Proxy({}, { get: (_t, k) => (k === 'hunts' ? mock.hunts : false) }),
  }),
}));
vi.mock('@/enterprise/contexts/NotebookContext', () => ({ useNotebookOptional: () => null }));
vi.mock('@/enterprise/hooks/use-pivt-state', () => ({
  usePivtState: () => ({ mode: 'hidden', isOpen: false, toggle: vi.fn(), open: vi.fn(), close: vi.fn(), setMode: vi.fn() }),
}));
vi.mock('@/enterprise/pages/Automation/automation-nav', () => ({
  AUTOMATION_SECTION_ICON: Workflow,
  useAutomationNav: () => ({ items: mock.automationItems, pendingApprovals: null }),
}));
vi.mock('@/enterprise/pages/Automation/ApprovalsBell', () => ({ ApprovalsBell: Nothing }));
vi.mock('@/enterprise/components/pivt/PivtSummon', () => ({ PivtSummon: Nothing }));
vi.mock('@/enterprise/components/pivt/PivtShellOverlay', () => ({ PivtShellOverlay: Nothing }));
vi.mock('@/components/NotificationBell', () => ({ NotificationBell: Nothing }));
vi.mock('@/components/support/HelpMenu', () => ({ HelpMenu: Nothing }));
vi.mock('@/components/VersionBadge', () => ({ VersionBadge: Nothing }));
vi.mock('@/components/DemoBanner', () => ({ DemoBanner: Nothing }));
vi.mock('@/components/LicenseBanner', () => ({ LicenseBanner: Nothing }));
vi.mock('@/components/UpdateAvailableBanner', () => ({ UpdateAvailableBanner: Nothing }));
vi.mock('@/components/BackupStatusBanner', () => ({ BackupStatusBanner: Nothing }));
vi.mock('@/components/DiskSpaceBanner', () => ({ DiskSpaceBanner: Nothing }));
vi.mock('@/components/CapacityWarningBanner', () => ({ CapacityWarningBanner: Nothing }));
vi.mock('@/components/layout/AppBreadcrumbs', () => ({ AppBreadcrumbs: Nothing, useCurrentPageTitle: () => 'Hunts' }));
vi.mock('@/components/layout/settings/SettingsLayout', () => ({ SettingsLayout: Nothing }));
vi.mock('@/components/shared/CommandPalette', () => ({ CommandPalette: Nothing }));
vi.mock('./StatusBar', () => ({ StatusBar: Nothing }));
vi.mock('./ThemeMenu', () => ({ ThemeMenu: Nothing }));

import { AppLayout } from './AppLayout';
import { BETA_BADGE_DESCRIPTION } from '@/components/ui/beta-badge';

function renderShell(path = '/') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AppLayout><div>page</div></AppLayout>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  localStorage.clear();
  mock.hunts = true;
  mock.automationItems = [
    { name: 'Runs', href: '/automation/runs', icon: List },
    { name: 'Flows', href: '/automation/flows', icon: List },
  ];
});
afterEach(cleanup);

describe('BETA badge in the left rail (NAN-5654)', () => {
  test('expanded rail: Hunts link and Automation header carry the badge, nothing else does', () => {
    renderShell();
    const hunts = screen.getByRole('link', { name: 'Hunts (beta)' });
    expect(within(hunts).getByTestId('beta-badge')).toBeTruthy();
    expect(within(hunts).getByTestId('beta-badge').textContent).toContain('BETA');

    const automation = screen.getByTestId('nav-automation');
    expect(within(automation).getAllByTestId('beta-badge')).toHaveLength(1);

    // Exactly two badges in the rail: Hunts + the Automation section head.
    expect(screen.getAllByTestId('beta-badge')).toHaveLength(2);
    // Neighbors stay plain.
    const notebooks = screen.queryByRole('link', { name: 'Notebooks' });
    if (notebooks) expect(within(notebooks).queryByTestId('beta-badge')).toBeNull();
  });

  test('badge exposes the full phrase to assistive tech and as a tooltip', () => {
    renderShell();
    const badge = within(screen.getByTestId('nav-automation')).getByTestId('beta-badge');
    expect(badge.getAttribute('aria-label')).toBe(BETA_BADGE_DESCRIPTION);
    expect(badge.getAttribute('title')).toBe(BETA_BADGE_DESCRIPTION);
    // The phrase lives only in the note's label; the visible word is hidden from AT.
    expect(badge.querySelector('[aria-hidden="true"]')?.textContent).toBe('BETA');
    expect(badge.textContent).toBe('BETA');
    // The section control keeps a short name instead of absorbing the phrase.
    expect(screen.getByRole('button', { name: 'Automation (beta)' })).toBeTruthy();
  });

  test('collapsed rail: Hunts tooltip says beta, Automation flyout header shows the badge', () => {
    localStorage.setItem('nanosiem-sidebar-collapsed', 'true');
    renderShell();
    const hunts = screen.getByRole('link', { name: 'Hunts (beta)' });
    expect(hunts.getAttribute('title')).toBe('Hunts (beta)');
    // Collapsed: no inline badges in the rail itself.
    expect(screen.queryAllByTestId('beta-badge')).toHaveLength(0);

    const trigger = screen.getByTestId('nav-automation').firstElementChild as HTMLElement;
    fireEvent.mouseEnter(trigger);
    const flyoutBadge = screen.getByTestId('beta-badge');
    expect(flyoutBadge.parentElement?.textContent).toContain('Automation');
  });

  test('open-core shape (hunts off, automation disabled): no badge, no dead entry', () => {
    mock.hunts = false;
    mock.automationItems = [];
    renderShell();
    expect(screen.queryByRole('link', { name: /Hunts/ })).toBeNull();
    expect(screen.queryByTestId('nav-automation')).toBeNull();
    expect(screen.queryAllByTestId('beta-badge')).toHaveLength(0);
  });
});
