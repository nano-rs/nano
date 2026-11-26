// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-5864: the command palette offers only commands whose page this build
// ships (open core has no Cases, Notebooks or Risk), shows no shortcut hints
// that nothing implements, and "Create New Case" lands on the Signal Inbox
// with the state that opens its New investigation flyout (/cases is a redirect
// that drops navigation state).
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

const mock = vi.hoisted(() => ({ enterprise: false, perms: new Set<string>() }));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => mock.perms.has(p) }),
}));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    edition: mock.enterprise ? 'enterprise' : 'open',
    capabilities: new Proxy({}, { get: () => mock.enterprise }),
  }),
}));

import { CommandPalette } from './CommandPalette';

const ALL_PERMS = [
  'cases:view', 'cases:create', 'search:view', 'detections:view', 'detections:create', 'alerts:view',
  'risk:view', 'prevalence:view', 'notebooks:view', 'notebooks:create', 'log_sources:view',
  'settings:system', 'users:view', 'settings:retention',
];

let landed: { pathname: string; state: unknown } | null = null;
function Probe() {
  const loc = useLocation();
  landed = { pathname: loc.pathname, state: loc.state };
  return null;
}

function openPalette() {
  render(
    <MemoryRouter initialEntries={['/rules/coverage']}>
      <CommandPalette />
      <Routes><Route path="*" element={<Probe />} /></Routes>
    </MemoryRouter>,
  );
  act(() => {
    fireEvent.keyDown(document, { key: 'k', ctrlKey: true });
  });
}

const labels = () => screen.getAllByRole('option').map((o) => o.textContent?.trim());

beforeEach(() => {
  mock.perms = new Set(ALL_PERMS);
  landed = null;
  // cmdk measures with ResizeObserver and scrolls the active item into view.
  globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as unknown as typeof ResizeObserver;
  Element.prototype.scrollIntoView ??= () => {};
});
afterEach(cleanup);

describe('CommandPalette (NAN-5864)', () => {
  test('open core offers no command for a page it does not ship', () => {
    mock.enterprise = false;
    openPalette();
    const shown = labels();
    for (const gone of ['Go to Cases', 'Go to Risk Scoring', 'Go to Notebooks', 'Create New Case', 'Create New Notebook', 'Case Settings']) {
      expect(shown).not.toContain(gone);
    }
    expect(shown).toEqual(expect.arrayContaining(['Go to Search', 'Go to Rules', 'Create New Rule', 'Storage Settings']));
  });

  test('enterprise offers them, without shortcut hints nothing implements', () => {
    mock.enterprise = true;
    openPalette();
    expect(labels()).toEqual(expect.arrayContaining(['Go to Cases', 'Go to Notebooks', 'Create New Case', 'Case Settings']));
    expect(screen.queryByText('G C')).toBeNull();
    expect(screen.queryByText('G S')).toBeNull();
  });

  test('permissions still filter', () => {
    mock.enterprise = true;
    mock.perms = new Set(['search:view']);
    openPalette();
    expect(labels()).toEqual(['Go to Dashboard', 'Go to Search']);
  });

  test('a create command also needs the view permission of the page it lands on', () => {
    mock.enterprise = true;
    mock.perms = new Set(['cases:create', 'notebooks:create']);
    openPalette();
    expect(labels()).toEqual(['Go to Dashboard']);
    cleanup();
    mock.perms = new Set(['cases:view', 'cases:create', 'notebooks:view', 'notebooks:create']);
    openPalette();
    expect(labels()).toEqual(expect.arrayContaining(['Create New Case', 'Create New Notebook']));
  });

  test('Create New Case opens the inbox with the New investigation state', () => {
    mock.enterprise = true;
    openPalette();
    act(() => {
      fireEvent.click(screen.getByRole('option', { name: 'Create New Case' }));
    });
    expect(landed).toEqual({ pathname: '/inbox', state: { openNewCase: true } });
  });
});
