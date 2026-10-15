// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-3767: open-core pull feeds — identity (directory sync) feeds take no ingest token or parser. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ConnectorFeed, ConnectorSpec } from '@/lib/api/connector-feeds';
import { ConnectorFeeds } from './ConnectorFeeds';

const mocks = vi.hoisted(() => ({
  specs: vi.fn(),
  list: vi.fn(),
  create: vi.fn(),
  setEnabled: vi.fn(),
  remove: vi.fn(),
}));

vi.mock('@/hooks/use-shared-tenant', () => ({ useSharedTenant: () => false }));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: () => undefined }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'u' }, hasPermission: () => true }),
}));
vi.mock('@/lib/api', () => ({
  api: {
    connectorFeeds: {
      specs: mocks.specs, list: mocks.list, create: mocks.create, setEnabled: mocks.setEnabled, delete: mocks.remove,
    },
  },
}));

const SPECS: ConnectorSpec[] = [
  { name: 'okta_system_log', kind: 'collector', source_slug: 'okta', config_fields: ['OKTA_DOMAIN'], credential_fields: ['API_TOKEN'] },
  { name: 'okta_users', kind: 'identity', source_slug: 'okta_users', config_fields: ['OKTA_DOMAIN'], credential_fields: ['API_TOKEN'] },
];

const FEEDS: ConnectorFeed[] = [
  {
    id: 'f1', name: 'Okta directory', connector: 'okta_users', kind: 'identity', enabled: true,
    last_status: 'error', last_error: 'identity_coordinator_unconfigured: no coordinator URL', last_success_at: null,
  },
  {
    id: 'f2', name: 'Okta audit', connector: 'okta_system_log', kind: 'collector', enabled: false,
    last_status: null, last_error: null, last_success_at: null,
  },
];

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter><ConnectorFeeds /></MemoryRouter>
    </QueryClientProvider>,
  );
}

async function openForm(connector: string) {
  renderPage();
  await screen.findByText('Okta directory');
  fireEvent.click(screen.getByRole('button', { name: 'Create feed' }));
  fireEvent.change(await screen.findByRole('combobox'), { target: { value: connector } });
}

describe('ConnectorFeeds', () => {
  beforeEach(() => {
    mocks.specs.mockResolvedValue(SPECS);
    mocks.list.mockResolvedValue(FEEDS);
    mocks.create.mockResolvedValue({ id: 'new' });
  });
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it('lists each feed kind and the last run error', async () => {
    renderPage();
    await screen.findByText('Okta directory');
    expect(screen.getByText('identity')).toBeTruthy();
    expect(screen.getByText('collector')).toBeTruthy();
    expect(screen.getByText(/identity_coordinator_unconfigured/)).toBeTruthy();
  });

  it('identity feeds hide the ingest token and parser prerequisite and never send a token', async () => {
    await openForm('okta_users');
    expect(screen.queryByText('Local HEC ingest token')).toBeNull();
    expect(screen.queryByText(/Deploy an enabled HEC parser/)).toBeNull();
    expect(screen.getAllByText(/Directory sync \(identity\)/).length).toBeGreaterThan(0);
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Okta directory 2' } });
    fireEvent.change(screen.getByLabelText('OKTA_DOMAIN'), { target: { value: 'acme.okta.com' } });
    fireEvent.change(screen.getByLabelText('API_TOKEN'), { target: { value: 'secret' } });
    // The sheet's submit is the last "Create feed" button (the page header has one too).
    fireEvent.click(screen.getAllByRole('button', { name: 'Create feed' }).at(-1)!);
    await waitFor(() => expect(mocks.create).toHaveBeenCalledTimes(1));
    const input = mocks.create.mock.calls[0][0];
    expect(input.connector).toBe('okta_users');
    expect('ingest_token' in input).toBe(false);
  });

  it('collector feeds still ask for the ingest token and the parser lane', async () => {
    await openForm('okta_system_log');
    expect(screen.getByText('Local HEC ingest token')).toBeTruthy();
    expect(screen.getByText(/Deploy an enabled HEC parser/)).toBeTruthy();
    expect(screen.queryByText(/Directory sync \(identity\)/)).toBeNull();
  });
});
