// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5903: Pull feeds is the one place a feed is set up. A Marketplace
 * collector card hops there (`Set up in Pull`, the connector preselected)
 * instead of embedding its own form, and a start refused because a lane's log
 * source is missing offers `Fix setup` on Pull feeds.
 */
import { afterEach, beforeAll, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ConnectorFeed, ConnectorSpecInfo } from '@/lib/api/connector-feeds';

const calls = vi.hoisted(() => ({ setEnabled: vi.fn(), create: vi.fn(), adoptSpec: vi.fn() }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true }) }));
vi.mock('@/lib/api', () => {
  class ApiClientError extends Error {
    constructor(message: string, public code: string, public details?: unknown) { super(message); }
  }
  return {
    ApiClientError,
    api: { connectorFeeds: { setEnabled: calls.setEnabled, create: calls.create, adoptSpec: calls.adoptSpec }, listCredentials: async () => ({ credentials: [] }) },
  };
});
import { ApiClientError } from '@/lib/api';
import { CollectorCard } from './CollectorCard';

const permissions = { installExisting: true, installNew: true, toggle: true, remove: true, rotate: true };
const okta = {
  name: 'okta_system_log', display_name: 'Okta System Log', kind: 'collector', credential_provider: 'okta', source_type: 'okta',
  schedule: '*/2 * * * *', config_fields: ['OKTA_DOMAIN'], optional_config_fields: [], credential_fields: ['API_TOKEN'],
} as unknown as ConnectorSpecInfo;
const pausedFeed = {
  id: 'cfeed_7', name: 'Okta prod', connector: 'okta_system_log', kind: 'collector', source_type: 'okta', enabled: false,
  running: false, schedule: null, effective_schedule: '*/2 * * * *', config: { OKTA_DOMAIN: 'acme.okta.com' }, credential_id: null,
  max_run_secs: null, next_run_at: '', consecutive_failures: 0, last_run_at: null, last_status: null, last_error: null,
  last_success_at: null, created_at: '',
} as ConnectorFeed;

beforeAll(() => {
  globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as unknown as typeof ResizeObserver;
  if (!window.matchMedia) {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: (query: string) => ({
        matches: false, media: query, onchange: null, addEventListener: () => {}, removeEventListener: () => {},
        addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false,
      }),
    });
  }
});
afterEach(() => { cleanup(); vi.clearAllMocks(); });

function Where() {
  const loc = useLocation();
  return <div data-testid="where">{loc.pathname + loc.search}</div>;
}

function renderCard(feeds: ConnectorFeed[]) {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/marketplace']}>
        <Routes>
          <Route path="/marketplace" element={<CollectorCard spec={okta} feeds={feeds} feedStatus={{ isError: false, isPending: false }} permissions={permissions} />} />
          <Route path="*" element={<Where />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

it('an uninstalled collector hops to Pull feeds with the connector preselected, with no form of its own', () => {
  renderCard([]);
  expect(screen.queryByRole('dialog')).toBeNull();
  fireEvent.click(screen.getByText('Set up in Pull'));
  expect(screen.getByTestId('where').textContent).toBe('/ingestion/log-sources/pull-feeds?new=okta_system_log');
  expect(calls.create).not.toHaveBeenCalled();
});

it('enabling a feed whose log sources are missing offers Fix setup on Pull feeds', async () => {
  calls.setEnabled.mockRejectedValue(
    new ApiClientError('Some log sources this feed needs are missing, so its events to `okta` would be dropped.', 'LOG_SOURCES_MISSING', { missing_lanes: ['okta'] }),
  );
  renderCard([pausedFeed]);
  fireEvent.click(screen.getByText(/Installed/));
  fireEvent.click(await screen.findByRole('button', { name: 'Enable' }));
  await vi.waitFor(() => expect(calls.setEnabled).toHaveBeenCalledWith('cfeed_7', true));
  expect((await screen.findByRole('alert')).textContent).toContain('Some log sources this feed needs are missing');
  const fix = await screen.findByRole('link', { name: 'Fix setup' });
  expect(fix.getAttribute('href')).toBe('/ingestion/log-sources/pull-feeds?fix=cfeed_7&action=resume');
});

it('the manage sheet sets up another feed on Pull feeds too', async () => {
  renderCard([{ ...pausedFeed, enabled: true }]);
  fireEvent.click(screen.getByText(/Installed/));
  const link = await screen.findByRole('link', { name: 'Set up in Pull' });
  expect(link.getAttribute('href')).toBe('/ingestion/log-sources/pull-feeds?new=okta_system_log');
});

it('a refused adopt links Fix setup with the adopt action, so Pull feeds repeats the adopt', async () => {
  calls.adoptSpec.mockRejectedValue(new ApiClientError('Some log sources this feed needs are missing.', 'LOG_SOURCES_MISSING'));
  renderCard([{ ...pausedFeed, enabled: true, spec_update_available: true }]);
  fireEvent.click(screen.getByText(/Installed/));
  fireEvent.click(await screen.findByRole('button', { name: /Adopt spec update for/ }));
  fireEvent.click(await screen.findByRole('button', { name: 'Adopt' }));
  const fix = await screen.findByRole('link', { name: 'Fix setup' });
  expect(fix.getAttribute('href')).toBe('/ingestion/log-sources/pull-feeds?fix=cfeed_7&action=adopt');
});
