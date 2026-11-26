// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-5844: Hunts is a rail group like Rules: Hunts, Findings, Escalations,
// Actors (Campaigns before NAN-5859) and (NAN-5850) Knowledge, in the expanded rail and the collapsed
// flyout, with the right entry lit for nested routes (detail pages, the
// Decisions tab) and the Findings / Escalations counts the old top tabs
// carried. NAN-5850: "Hunt settings" is gone; Rule ideas sits in Rules.
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { Workflow } from 'lucide-react';

const { Nothing } = vi.hoisted(() => ({ Nothing: () => null }));
const mock = vi.hoisted(() => ({
  hunts: true,
  perms: null as Set<string> | null,
  counts: {} as Record<string, string>,
  countsEnabled: [] as boolean[],
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 'u1', name: 'Test Analyst', roles: ['analyst'] },
    logout: vi.fn(),
    hasPermission: (p: string) => !mock.perms || mock.perms.has(p),
    hasAnyPermission: (ps: string[]) => !mock.perms || ps.some((p) => mock.perms!.has(p)),
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
  useAutomationNav: () => ({ items: [], pendingApprovals: null }),
}));
vi.mock('@/enterprise/hooks/use-hunts-nav-counts', () => ({
  useHuntsNavCounts: (enabled: boolean) => {
    mock.countsEnabled.push(enabled);
    return enabled ? mock.counts : {};
  },
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
vi.mock('./RailThemeSwitcher', () => ({ RailThemeStrip: Nothing, RailThemeFlyout: Nothing }));

import { AppLayout } from './AppLayout';

const ENTRIES = ['Hunts', 'Findings', 'Escalations', 'Actors', 'Knowledge'];
const HREFS = ['/hunts', '/hunts/leads', '/hunts/escalations', '/hunts/actors', '/hunts/knowledge'];

function renderShell(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AppLayout><div>page</div></AppLayout>
    </MemoryRouter>,
  );
}

/** The expanded rail's Hunts sub-items, by accessible name. */
function railItems() {
  return within(screen.getByTestId('nav-hunts-items'));
}

function activeEntries(container: ReturnType<typeof within>, role: 'link' | 'menuitem' = 'link'): string[] {
  return ENTRIES.filter((n) => container.getByRole(role, { name: new RegExp(`^${n}`) }).getAttribute('aria-current') === 'page');
}

/** The open collapsed-rail flyout (a menu). */
function flyout() {
  return within(screen.getByTestId('nav-hunts-trigger-flyout'));
}

beforeEach(() => {
  localStorage.clear();
  mock.hunts = true;
  mock.perms = null;
  mock.counts = { '/hunts/leads': '7', '/hunts/escalations': '2' };
  mock.countsEnabled = [];
});
afterEach(cleanup);

describe('Hunts rail group (NAN-5844)', () => {
  test('expanded: the group lists the five entries in order, Knowledge last', () => {
    renderShell('/hunts');
    const links = railItems().getAllByRole('link');
    expect(links.map((l) => l.textContent?.replace(/\d+$/, ''))).toEqual(ENTRIES);
    expect(links.map((l) => l.getAttribute('href'))).toEqual(HREFS);
    expect(screen.queryByRole('link', { name: /Hunt settings/ })).toBeNull();
  });

  test('counts render beside Findings and Escalations only', () => {
    renderShell('/hunts');
    const items = railItems();
    expect(items.getByRole('link', { name: /^Findings/ }).textContent).toBe('Findings7');
    expect(items.getByRole('link', { name: /^Escalations/ }).textContent).toBe('Escalations2');
    expect(items.getByRole('link', { name: /^Actors/ }).textContent).toBe('Actors');
    expect(mock.countsEnabled.every(Boolean)).toBe(true);
  });

  test.each([
    ['/hunts', 'Hunts'],
    ['/hunts/pb_01hunt', 'Hunts'],
    ['/hunts/leads', 'Findings'],
    ['/hunts/leads/lead_01a', 'Findings'],
    ['/hunts/escalations', 'Escalations'],
    ['/hunts/actors', 'Actors'],
    ['/hunts/actors/review', 'Actors'],
    ['/hunts/actors/hcmp_01a', 'Actors'],
    ['/hunts/campaigns', 'Actors'],
    ['/hunts/leads/decisions', 'Findings'],
    ['/hunts/knowledge', 'Knowledge'],
    // Profile has no entry of its own until it folds into MITRE Coverage.
    ['/hunts/profile', 'Hunts'],
    // Redirect-only legacy routes light their new home for the one render.
    ['/hunts/memory', 'Knowledge'],
    ['/hunts/suppressions', 'Knowledge'],
    ['/hunts/rulings', 'Findings'],
  ])('expanded: %s lights exactly %s, and the group opens on its own', (path, entry) => {
    renderShell(path);
    expect(screen.getByRole('button', { name: 'Hunts (beta)' }).getAttribute('aria-expanded')).toBe('true');
    expect(activeEntries(railItems())).toEqual([entry]);
  });

  test.each(['/hunts/runners', '/hunts/rule-ideas'])('expanded: %s (moved out of Hunts) lights no Hunts entry', (path) => {
    renderShell(path);
    expect(activeEntries(railItems())).toEqual([]);
  });

  test('expanded: the header toggles the group, and stays closed off hunts routes', () => {
    renderShell('/search');
    const header = screen.getByRole('button', { name: 'Hunts (beta)' });
    expect(screen.queryByTestId('nav-hunts-items')).toBeNull();
    fireEvent.click(header);
    expect(railItems().getAllByRole('link')).toHaveLength(5);
    expect(activeEntries(railItems())).toEqual([]);
    fireEvent.click(header);
    expect(screen.queryByTestId('nav-hunts-items')).toBeNull();
  });

  test('collapsed: the hover flyout lists the same entries, counts and active state', () => {
    localStorage.setItem('nanosiem-sidebar-collapsed', 'true');
    renderShell('/hunts/leads/lead_01a');
    expect(screen.queryByTestId('nav-hunts-items')).toBeNull();
    expect(screen.queryByTestId('nav-hunts-trigger-flyout')).toBeNull();
    fireEvent.mouseEnter(screen.getByTestId('nav-hunts-trigger'));
    const menu = flyout();
    expect(menu.getAllByRole('menuitem').map((l) => l.getAttribute('href'))).toEqual(HREFS);
    expect(menu.getByRole('menuitem', { name: /^Findings/ }).textContent).toBe('Findings7');
    expect(activeEntries(menu, 'menuitem')).toEqual(['Findings']);
  });

  test('collapsed: Knowledge lights Knowledge in the flyout', () => {
    localStorage.setItem('nanosiem-sidebar-collapsed', 'true');
    renderShell('/hunts/knowledge');
    fireEvent.mouseEnter(screen.getByTestId('nav-hunts-trigger'));
    expect(activeEntries(flyout(), 'menuitem')).toEqual(['Knowledge']);
  });

  test('collapsed: clicking a flyout entry closes the flyout', () => {
    localStorage.setItem('nanosiem-sidebar-collapsed', 'true');
    renderShell('/hunts');
    fireEvent.mouseEnter(screen.getByTestId('nav-hunts-trigger'));
    fireEvent.click(flyout().getByRole('menuitem', { name: /^Actors/ }));
    expect(screen.queryByTestId('nav-hunts-trigger-flyout')).toBeNull();
  });

  test('off hunts routes with the group closed, the counts are not fetched; opening the group fetches them', () => {
    renderShell('/search');
    expect(mock.countsEnabled.length).toBeGreaterThan(0);
    expect(mock.countsEnabled.some(Boolean)).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Hunts (beta)' }));
    expect(mock.countsEnabled.at(-1)).toBe(true);
  });

  test('collapsed, off hunts routes: opening the flyout fetches the counts, closing it stops', () => {
    localStorage.setItem('nanosiem-sidebar-collapsed', 'true');
    renderShell('/search');
    expect(mock.countsEnabled.some(Boolean)).toBe(false);
    fireEvent.mouseEnter(screen.getByTestId('nav-hunts-trigger'));
    expect(mock.countsEnabled.at(-1)).toBe(true);
    expect(flyout().getByRole('menuitem', { name: /^Findings/ }).textContent).toBe('Findings7');
    expect(flyout().getByRole('menuitem', { name: /^Escalations/ }).textContent).toBe('Escalations2');
    fireEvent.keyDown(flyout().getByRole('menuitem', { name: /^Hunts/ }), { key: 'Escape' });
    expect(screen.queryByTestId('nav-hunts-trigger-flyout')).toBeNull();
    expect(mock.countsEnabled.at(-1)).toBe(false);
  });

  test('without hunts:view there is no group and the counts are never requested', () => {
    mock.perms = new Set(['search:view']);
    renderShell('/');
    expect(screen.queryByTestId('nav-hunts')).toBeNull();
    expect(mock.countsEnabled.length).toBeGreaterThan(0);
    expect(mock.countsEnabled.some(Boolean)).toBe(false);
  });

  test('open-core shape (hunts capability off): no group, no counts request', () => {
    mock.hunts = false;
    renderShell('/');
    expect(screen.queryByTestId('nav-hunts')).toBeNull();
    expect(screen.queryByRole('link', { name: /^(Findings|Escalations|Actors|Knowledge|Rule ideas)/ })).toBeNull();
    expect(mock.countsEnabled.some(Boolean)).toBe(false);
  });
});

describe('Settings link for hunts-only roles (NAN-5850 review)', () => {
  test('a hunts:view role with no settings permission still gets the Settings link', () => {
    mock.perms = new Set(['hunts:view']);
    renderShell('/hunts');
    // The landing needs a settings permission, so the link enters at Hunting.
    expect(screen.getByRole('link', { name: 'Settings' }).getAttribute('href')).toBe('/settings/hunts');
  });

  test('a role that can open the landing still links to /settings', () => {
    mock.perms = new Set(['hunts:view', 'settings:view']);
    renderShell('/hunts');
    expect(screen.getByRole('link', { name: 'Settings' }).getAttribute('href')).toBe('/settings');
  });

  test('with the hunts capability off, hunts:view alone shows no Settings link', () => {
    mock.hunts = false;
    mock.perms = new Set(['hunts:view']);
    renderShell('/');
    expect(screen.queryByRole('link', { name: 'Settings' })).toBeNull();
  });

  test('without hunts:view or any settings permission there is no Settings link', () => {
    mock.perms = new Set(['search:view']);
    renderShell('/');
    expect(screen.queryByRole('link', { name: 'Settings' })).toBeNull();
  });
});

describe('Rules > Rule ideas (NAN-5850)', () => {
  /** The expanded Rules group's links, by name. */
  const rulesLinks = () => screen.getAllByRole('link').filter((l) => l.getAttribute('href')?.startsWith('/rules'));

  test('Rule ideas is the last Rules entry, lit on /rules/ideas, with the ready count', () => {
    mock.counts = { '/rules/ideas': '6' };
    renderShell('/rules/ideas');
    const links = rulesLinks();
    const last = links.at(-1)!;
    expect(last.getAttribute('href')).toBe('/rules/ideas');
    expect(last.textContent).toBe('Rule ideas6');
    expect(last.className).toContain('bg-primary/10');
    expect(mock.countsEnabled.at(-1)).toBe(true);
  });

  test('without hunts:view there is no Rule ideas entry and no counts request from Rules', () => {
    mock.perms = new Set(['detections:view', 'detections:create']);
    renderShell('/rules');
    expect(screen.queryByRole('link', { name: /^Rule ideas/ })).toBeNull();
    expect(mock.countsEnabled.some(Boolean)).toBe(false);
  });

  test('open-core shape (hunts capability off): no Rule ideas entry', () => {
    mock.hunts = false;
    renderShell('/rules');
    expect(screen.queryByRole('link', { name: /^Rule ideas/ })).toBeNull();
  });

  test('collapsed: the Rules flyout carries the Rule ideas badge and fetches while open', () => {
    localStorage.setItem('nanosiem-sidebar-collapsed', 'true');
    mock.counts = { '/rules/ideas': '3' };
    renderShell('/search');
    expect(mock.countsEnabled.some(Boolean)).toBe(false);
    fireEvent.mouseEnter(screen.getByRole('button', { name: 'Rules' }).parentElement!);
    expect(mock.countsEnabled.at(-1)).toBe(true);
    expect(screen.getByRole('menuitem', { name: /^Rule ideas/ }).textContent).toBe('Rule ideas3');
  });
});

describe('collapsed rail flyouts are keyboard and screen-reader menus (NAN-5844)', () => {
  beforeEach(() => localStorage.setItem('nanosiem-sidebar-collapsed', 'true'));

  test('the trigger is a labelled menu button, closed until opened', () => {
    renderShell('/search');
    const trigger = screen.getByRole('button', { name: 'Hunts (beta)' });
    expect(trigger.getAttribute('aria-haspopup')).toBe('menu');
    expect(trigger.getAttribute('aria-expanded')).toBe('false');
    expect(screen.queryByRole('menu')).toBeNull();
    // Every collapsed section uses the same component, so every one is a menu button.
    for (const name of ['Rules']) {
      expect(screen.getByRole('button', { name }).getAttribute('aria-haspopup')).toBe('menu');
    }
  });

  test.each(['Enter', ' ', 'ArrowDown', 'ArrowRight'])('%j opens the menu and focuses its first item', (key) => {
    renderShell('/search');
    const trigger = screen.getByRole('button', { name: 'Hunts (beta)' });
    trigger.focus();
    fireEvent.keyDown(trigger, { key });
    const menu = screen.getByRole('menu', { name: 'Hunts (beta)' });
    expect(trigger.getAttribute('aria-expanded')).toBe('true');
    expect(trigger.getAttribute('aria-controls')).toBe(menu.id);
    expect(document.activeElement?.textContent).toBe('Hunts');
  });

  test('arrow keys, Home and End move through the items; Escape closes and returns focus', () => {
    renderShell('/search');
    const trigger = screen.getByRole('button', { name: 'Hunts (beta)' });
    trigger.focus();
    fireEvent.keyDown(trigger, { key: 'Enter' });
    const menu = screen.getByRole('menu');
    const names = () => document.activeElement?.textContent?.replace(/\d+$/, '');
    fireEvent.keyDown(menu, { key: 'ArrowDown' });
    expect(names()).toBe('Findings');
    fireEvent.keyDown(menu, { key: 'End' });
    expect(names()).toBe('Knowledge');
    fireEvent.keyDown(menu, { key: 'ArrowDown' });
    expect(names()).toBe('Hunts');
    fireEvent.keyDown(menu, { key: 'ArrowUp' });
    expect(names()).toBe('Knowledge');
    fireEvent.keyDown(menu, { key: 'Home' });
    expect(names()).toBe('Hunts');
    fireEvent.keyDown(menu, { key: 'Escape' });
    expect(screen.queryByRole('menu')).toBeNull();
    expect(document.activeElement).toBe(trigger);
    expect(trigger.getAttribute('aria-expanded')).toBe('false');
  });

  test('focus leaving the trigger and the menu closes it', () => {
    renderShell('/search');
    const trigger = screen.getByRole('button', { name: 'Hunts (beta)' });
    fireEvent.keyDown(trigger, { key: 'Enter' });
    const item = screen.getAllByRole('menuitem')[0];
    const elsewhere = screen.getByRole('button', { name: 'Toggle sidebar' });
    fireEvent.blur(item, { relatedTarget: elsewhere });
    expect(screen.queryByRole('menu')).toBeNull();
  });

  test('click toggles the menu too', () => {
    renderShell('/search');
    const trigger = screen.getByRole('button', { name: 'Hunts (beta)' });
    fireEvent.click(trigger);
    expect(screen.getByRole('menu')).toBeTruthy();
    fireEvent.click(trigger);
    expect(screen.queryByRole('menu')).toBeNull();
  });
});
