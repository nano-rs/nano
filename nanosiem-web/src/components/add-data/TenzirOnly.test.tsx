// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-3844: Vector-dependent surfaces on an `install.sh --tenzir` install (no Vector). */
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const calls = vi.hoisted(() => ({
  landingList: vi.fn(),
  landingFiles: vi.fn(),
  feedsList: vi.fn(),
  feedsSpecs: vi.fn(),
  listSourceConfigs: vi.fn(),
  toggleSourceConfig: vi.fn(),
}));
vi.mock('@/lib/api', () => ({
  api: {
    listSourceConfigs: calls.listSourceConfigs,
    toggleSourceConfig: calls.toggleSourceConfig,
    landingSources: { list: calls.landingList, files: calls.landingFiles },
    connectorFeeds: {
      list: calls.feedsList,
      specs: calls.feedsSpecs,
      create: vi.fn(),
      setEnabled: vi.fn(),
      delete: vi.fn(),
    },
  },
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { deployment_mode: 'self-hosted' }, hasPermission: () => true }),
}));
vi.mock('@/hooks/use-shared-tenant', () => ({ useSharedTenant: () => false }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));

import { CapabilitiesContext, type CapabilitiesContextValue, type IngestModeState } from '@/hooks/use-capabilities';
import { TENZIR_ONLY_NOTE } from './TenzirOnlyNote';
import { VectorRequiredRoute } from './VectorRequiredRoute';
import { TENZIR_ADD_SOURCE_COMMAND, TenzirBucketDropLead } from './TenzirBucketDropLead';
import { ConnectorFeeds } from '@/pages/ConnectorFeeds';
import SourceConfigurations from '@/pages/SourceConfigurations';

function caps(ingestMode?: IngestModeState): CapabilitiesContextValue {
  return {
    edition: 'open',
    version: 'test',
    ingestMode,
    capabilities: {} as CapabilitiesContextValue['capabilities'],
  };
}

function renderWith(ui: ReactNode, ingestMode?: IngestModeState) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <CapabilitiesContext.Provider value={caps(ingestMode)}>
        <MemoryRouter>{ui}</MemoryRouter>
      </CapabilitiesContext.Provider>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  // FormSheet (ConnectorFeeds) reads the mobile breakpoint.
  window.matchMedia = vi.fn().mockReturnValue({
    matches: false,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }) as unknown as typeof window.matchMedia;
  calls.landingList.mockResolvedValue({ sources: [] });
  calls.feedsList.mockResolvedValue([
    { id: 'f1', name: 'okta-events', connector: 'okta', kind: 'events', enabled: false, last_status: null, last_error: null, last_success_at: null },
  ]);
  calls.feedsSpecs.mockResolvedValue([]);
  calls.listSourceConfigs.mockResolvedValue([
    { id: 'sc_off', name: 'edge-hec', config_type: 'splunk_hec', connection_config: {}, enabled: false, deployed: false, created_at: '2026-10-14T00:00:00Z', updated_at: '2026-10-14T00:00:00Z' },
    { id: 'sc_on', name: 'edge-http', config_type: 'http_server', connection_config: {}, enabled: true, deployed: true, created_at: '2026-10-14T00:00:00Z', updated_at: '2026-10-14T00:00:00Z' },
  ]);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('TenzirOnlyNote wording', () => {
  it('names the fix and never says Splunk', () => {
    expect(TENZIR_ONLY_NOTE).toBe('This install ingests via Tenzir; re-run install.sh --add-vector to enable');
    expect(TENZIR_ONLY_NOTE).not.toMatch(/splunk/i);
  });
});

describe('VectorRequiredRoute', () => {
  it('renders the page on a Vector install', () => {
    renderWith(<VectorRequiredRoute title="Add data"><div>wizard</div></VectorRequiredRoute>, 'vector');
    expect(screen.getByText('wizard')).toBeTruthy();
    expect(screen.queryByTestId('tenzir-only-note')).toBeNull();
  });

  it('treats a missing ingestMode (older API) as Vector', () => {
    renderWith(<VectorRequiredRoute title="Add data"><div>wizard</div></VectorRequiredRoute>);
    expect(screen.getByText('wizard')).toBeTruthy();
  });

  it('shows neither the page nor the note while capabilities load', () => {
    renderWith(<VectorRequiredRoute title="Add data"><div>wizard</div></VectorRequiredRoute>, 'unknown');
    expect(screen.queryByText('wizard')).toBeNull();
    expect(screen.queryByTestId('tenzir-only-note')).toBeNull();
    expect(screen.getByTestId('vector-required-pending')).toBeTruthy();
  });

  it('replaces the page with the note on a Tenzir-only install', () => {
    renderWith(<VectorRequiredRoute title="Add data"><div>wizard</div></VectorRequiredRoute>, 'tenzir_only');
    expect(screen.queryByText('wizard')).toBeNull();
    expect(screen.getByRole('heading', { name: 'Add data' })).toBeTruthy();
    expect(screen.getByTestId('tenzir-only-note').textContent).toBe(TENZIR_ONLY_NOTE);
    expect(screen.getByRole('link').getAttribute('href')).toBe('/ingestion/log-sources');
  });
});

describe('TenzirBucketDropLead', () => {
  it('leads with the source-key command and the bucket drop status', async () => {
    renderWith(<TenzirBucketDropLead />, 'tenzir_only');
    expect(screen.getByText(TENZIR_ADD_SOURCE_COMMAND)).toBeTruthy();
    expect(screen.getByTestId('landing-sources-panel')).toBeTruthy();
    await waitFor(() => expect(calls.landingList).toHaveBeenCalled());
  });
});

describe('ConnectorFeeds (pull connectors)', () => {
  it('offers Create and Resume on a Vector install', async () => {
    renderWith(<ConnectorFeeds />, 'vector');
    expect(await screen.findByText('okta-events', { selector: 'td' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Create feed' })).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Resume' }) as HTMLButtonElement).disabled).toBe(false);
    expect(screen.queryByTestId('tenzir-only-note')).toBeNull();
  });

  it('hides Create, disables Resume and keeps Delete on a Tenzir-only install', async () => {
    renderWith(<ConnectorFeeds />, 'tenzir_only');
    expect(await screen.findByText('okta-events', { selector: 'td' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Create feed' })).toBeNull();
    expect((screen.getByRole('button', { name: 'Resume' }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole('button', { name: 'Delete' })).toBeTruthy();
    expect(screen.getByTestId('tenzir-only-note').textContent).toBe(TENZIR_ONLY_NOTE);
  });
});

describe('ingest mode still loading', () => {
  it('keeps pull-feed Create and Resume off without claiming Tenzir', async () => {
    renderWith(<ConnectorFeeds />, 'unknown');
    expect(await screen.findByText('okta-events', { selector: 'td' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Create feed' })).toBeNull();
    expect((screen.getByRole('button', { name: 'Resume' }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByTestId('tenzir-only-note')).toBeNull();
  });
});

describe('SourceConfigurations enable switch', () => {
  function switches() {
    return screen.getAllByRole('button', { pressed: false }).concat(screen.getAllByRole('button', { pressed: true }));
  }

  it('is live on a Vector install', async () => {
    renderWith(<SourceConfigurations />, 'vector');
    expect(await screen.findByText('edge-hec')).toBeTruthy();
    const off = screen.getByRole('button', { pressed: false }) as HTMLButtonElement;
    expect(off.disabled).toBe(false);
    expect(screen.queryByTestId('tenzir-only-note')).toBeNull();
  });

  it('cannot turn a listener on in tenzir_only, can still turn one off, and shows the note', async () => {
    renderWith(<SourceConfigurations />, 'tenzir_only');
    expect(await screen.findByText('edge-hec')).toBeTruthy();
    const off = screen.getByRole('button', { pressed: false }) as HTMLButtonElement;
    const on = screen.getByRole('button', { pressed: true }) as HTMLButtonElement;
    expect(off.disabled).toBe(true);
    expect(off.title).toBe(TENZIR_ONLY_NOTE);
    expect(on.disabled).toBe(false);
    expect(switches()).toHaveLength(2);
    expect(screen.getByTestId('tenzir-only-note').textContent).toBe(TENZIR_ONLY_NOTE);
  });

  it('cannot turn a listener on while capabilities load', async () => {
    renderWith(<SourceConfigurations />, 'unknown');
    expect(await screen.findByText('edge-hec')).toBeTruthy();
    expect((screen.getByRole('button', { pressed: false }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByTestId('tenzir-only-note')).toBeNull();
  });
});
