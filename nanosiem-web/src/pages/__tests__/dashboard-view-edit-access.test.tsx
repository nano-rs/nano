// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-5637: the dashboard page offers Edit only to users the server lets save
// it (PUT /api/dashboards/:id: `dashboards:edit`, and the owner or
// `settings:system`). A non-owner sees no Edit, no "Edit dashboard", no
// Settings, and `?edit=true` does not open the editor for them. The decision
// uses the dashboard fetched for the CURRENT route, never the previous one the
// reused page instance still holds after /dashboards/:id navigation.
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation, useNavigate, type NavigateFunction } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { Dashboard } from '@/lib/api/types';

const mock = vi.hoisted(() => ({
  perms: new Set<string>(),
  /** id → the dashboard getDashboard resolves (or a pending promise). */
  dashboards: {} as Record<string, unknown>,
  getDashboard: null as unknown as (id: string) => Promise<unknown>,
  /** Every render of the (stubbed) editor, by dashboard name. */
  editorRenders: [] as string[],
}));

// Any API surface the page touches resolves empty; getDashboard is explicit.
function autoApi(overrides: Record<string, unknown>): unknown {
  const make = (path: string): unknown =>
    new Proxy(() => Promise.resolve(null), {
      get(_t, prop) {
        if (prop === 'then') return undefined;
        const key = path ? `${path}.${String(prop)}` : String(prop);
        if (key in overrides) return overrides[key];
        return make(key);
      },
      apply() {
        return Promise.resolve(null);
      },
    });
  return make('');
}

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, api: autoApi({ getDashboard: (id: string) => mock.getDashboard(id) }) };
});
vi.mock('@/hooks/use-api', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const idle = () => ({ data: undefined, loading: false, isLoading: false, error: null, refetch: vi.fn(), mutate: vi.fn() });
  const stubs: Record<string, unknown> = {};
  for (const key of Object.keys(actual)) {
    stubs[key] = typeof actual[key] === 'function' && key.startsWith('use') ? idle : actual[key];
  }
  // The real hook: it keeps the previous id's data until the next fetch lands.
  return { ...stubs, useDashboard: actual.useDashboard };
});
vi.mock('@/components/dashboard', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  DashboardEditor: ({ dashboard }: { dashboard: Dashboard }) => {
    mock.editorRenders.push(dashboard.name);
    return <div data-testid="editor">editing {dashboard.name}</div>;
  },
}));
vi.mock('@/hooks/useRecentlyViewedDashboards', () => ({
  useRecentlyViewedDashboards: () => ({ recentDashboardIds: [], addRecentDashboard: vi.fn(), removeRecentDashboard: vi.fn() }),
}));
vi.mock('@/hooks/useRecentActivity', () => ({ useRecordActivity: () => ({ recordView: vi.fn() }) }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    hasPermission: (p: string) => mock.perms.has(p),
    hasAnyPermission: (ps: string[]) => ps.some((p) => mock.perms.has(p)),
    hasAllPermissions: (ps: string[]) => ps.every((p) => mock.perms.has(p)),
    user: { id: 'me', name: 'Analyst' },
  }),
}));

import { BreadcrumbProvider } from '@/contexts/BreadcrumbContext';
import { DashboardView } from '@/pages/DashboardView';

const ANALYST = ['dashboards:view', 'dashboards:edit', 'search:execute'];

function dash(id: string, name: string, isOwner: boolean): Dashboard {
  return {
    id,
    name,
    description: null,
    layout: { columns: 12, rowHeight: 80, items: [] },
    panels: [],
    visibility: 'public',
    is_owner: isOwner,
    owner_name: isOwner ? 'Analyst' : 'Admin',
    created_at: '2026-11-17T10:00:00Z',
    updated_at: '2026-11-17T10:00:00Z',
  } as unknown as Dashboard;
}
const SHARED = dash('dash_a', 'Shared SOC', false);
const MINE = dash('dash_b', 'My hunts', true);

let where = '';
let go: NavigateFunction = () => {};
function Where() {
  const loc = useLocation();
  go = useNavigate();
  where = `${loc.pathname}${loc.search}`;
  return null;
}

function renderAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <BreadcrumbProvider>
          <Where />
          <Routes>
            <Route path="/dashboards/:id" element={<DashboardView />} />
          </Routes>
        </BreadcrumbProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function openMore() {
  const more = screen.getByRole('button', { name: 'More actions' });
  fireEvent.pointerDown(more, { button: 0, ctrlKey: false });
  await screen.findByRole('menu');
}

/** A getDashboard for `id` that resolves only when released. */
function held(id: string) {
  let release: () => void = () => {};
  const gate = new Promise<void>((r) => { release = r; });
  const prev = mock.getDashboard;
  mock.getDashboard = async (want) => {
    if (want !== id) return prev(want);
    await gate;
    return mock.dashboards[want];
  };
  return () => act(() => release());
}

beforeEach(() => {
  mock.dashboards = { dash_a: SHARED, dash_b: MINE };
  mock.getDashboard = async (id) => mock.dashboards[id];
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: false, media: query, onchange: null,
    addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {},
    dispatchEvent: () => false,
  }));
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal('IntersectionObserver', class { observe() {} unobserve() {} disconnect() {} takeRecords() { return []; } });
  Element.prototype.scrollIntoView = () => {};
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('dashboard Edit follows who the server lets save it (NAN-5637)', () => {
  test('a non-owner with dashboards:edit sees no Edit, Edit dashboard or Settings', async () => {
    mock.perms = new Set(ANALYST);
    renderAt('/dashboards/dash_a');
    await screen.findByText('Shared SOC');
    expect(screen.queryByRole('button', { name: /^Edit$/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /Edit dashboard/ })).toBeNull();
    expect(screen.getByText('Only its owner or an admin can add panels to this dashboard.')).toBeTruthy();
    await openMore();
    expect(screen.queryByRole('menuitem', { name: /Edit dashboard/ })).toBeNull();
    expect(screen.queryByRole('menuitem', { name: /Settings/ })).toBeNull();
    expect(screen.getByRole('menuitem', { name: /Export as JSON/ })).toBeTruthy();
  });

  test('?edit=true does not open the editor for a non-owner', async () => {
    mock.perms = new Set(ANALYST);
    renderAt('/dashboards/dash_a?edit=true');
    await waitFor(() => expect(where).toBe('/dashboards/dash_a'));
    await screen.findByText('Shared SOC');
    expect(screen.queryByTestId('editor')).toBeNull();
  });

  test('the owner sees Edit, Edit dashboard and Settings, and ?edit=true opens the editor', async () => {
    mock.perms = new Set(ANALYST);
    renderAt('/dashboards/dash_b');
    expect(await screen.findByRole('button', { name: /^Edit$/ })).toBeTruthy();
    expect(screen.getByRole('button', { name: /Edit dashboard/ })).toBeTruthy();
    await openMore();
    expect(screen.getByRole('menuitem', { name: /Edit dashboard/ })).toBeTruthy();
    expect(screen.getByRole('menuitem', { name: /Settings/ })).toBeTruthy();
    cleanup();
    renderAt('/dashboards/dash_b?edit=true');
    expect((await screen.findByTestId('editor')).textContent).toBe('editing My hunts');
    expect(where).toBe('/dashboards/dash_b?edit=true');
  });

  test('an admin (settings:system) who does not own it sees Edit', async () => {
    mock.perms = new Set([...ANALYST, 'settings:system']);
    renderAt('/dashboards/dash_a');
    expect(await screen.findByRole('button', { name: /^Edit$/ })).toBeTruthy();
  });

  test('the owner without dashboards:edit sees no Edit', async () => {
    mock.perms = new Set(['dashboards:view']);
    renderAt('/dashboards/dash_b');
    await screen.findByText('My hunts');
    expect(screen.queryByRole('button', { name: /^Edit$/ })).toBeNull();
  });

  test("navigating from a shared dashboard to my own ?edit=true keeps edit mode (stale dashboard)", async () => {
    mock.perms = new Set(ANALYST);
    renderAt('/dashboards/dash_a');
    await screen.findByText('Shared SOC');
    const release = held('dash_b');
    act(() => go('/dashboards/dash_b?edit=true'));
    // While dash_b loads, the page still holds dash_a (not mine): ?edit=true stays.
    await new Promise((r) => setTimeout(r, 20));
    expect(where).toBe('/dashboards/dash_b?edit=true');
    await release();
    expect((await screen.findByTestId('editor')).textContent).toBe('editing My hunts');
    expect(where).toBe('/dashboards/dash_b?edit=true');
  });

  test("navigating from my own dashboard to a shared ?edit=true never shows an editor", async () => {
    mock.perms = new Set(ANALYST);
    renderAt('/dashboards/dash_b');
    await screen.findByRole('button', { name: /^Edit$/ });
    const release = held('dash_a');
    mock.editorRenders = [];
    act(() => go('/dashboards/dash_a?edit=true'));
    expect(screen.queryByTestId('editor')).toBeNull();
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByTestId('editor')).toBeNull();
    await release();
    await waitFor(() => expect(where).toBe('/dashboards/dash_a'));
    await screen.findByText('Shared SOC');
    expect(screen.queryByTestId('editor')).toBeNull();
    expect(mock.editorRenders, 'no editor, not even for one render with the previous dashboard').toEqual([]);
  });
});
