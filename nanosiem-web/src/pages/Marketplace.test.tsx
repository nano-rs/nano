// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4946: the inventory Marketplace on dedicated APIs. One grid holds catalog
 * items, connector pull collectors (Identity group, pull badge, Pull filter),
 * the Cloud pull entry and custom providers; the open edition shows no
 * enterprise-only action.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { CapabilitiesContext, type Capabilities } from '@/hooks/use-capabilities';

const bundle: { value: unknown } = { value: null };
const caps = { value: { customEnrichment: true, agentEnrichment: true } as Capabilities, edition: 'enterprise' as 'enterprise' | 'open' };
const listCustomEnrichments = vi.fn(async () => [
  { id: 'c9', namespace_id: 'n', name: 'Asset CMDB', description: 'CMDB owners', enrichment_type: 'data', enabled: true, status: 'active', last_run_at: null, last_run_status: 'success', created_at: '' },
]);

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'u1' }, hasPermission: () => true, hasAllPermissions: () => true }),
  useOptionalAuth: () => ({ user: { id: 'u1' }, hasPermission: () => true }),
}));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: () => {} }));
vi.mock('@/hooks/useBreadcrumbTitle', () => ({ useBreadcrumbTitle: () => {} }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: () => {} }) }));
vi.mock('@/enterprise/components/threat-intel/ThreatIntelProviders', () => ({ ThreatIntelProvidersSection: () => null }));
vi.mock('@/enterprise/components/threat-intel/use-threat-intel', () => ({ useThreatIntelEnabled: () => false, useThreatIntelProviders: () => ({ data: undefined }) }));

const entries = [
  { id: '1', slug: 'abuseipdb', name: 'AbuseIPDB', description: 'IP reputation', category: 'agent', tags: [], source_type: 'repository', repository_id: 'r1', manifest_version: 1, execution_backend: 'deno', installed: false, requires_credential: 'required', credential_fields: [{ name: 'api_key', label: 'API key', field_type: 'password', required: true }], has_credentials: false, allowed_domains: [], config: {}, enabled: false, record_count: 0, created_at: '', updated_at: '' },
  { id: '2', slug: 'tor-exit-nodes', name: 'Tor exit nodes', category: 'data', tags: [], source_type: 'repository', repository_id: 'r1', manifest_version: 1, execution_backend: 'native', installed: true, requires_credential: 'none', credential_fields: [], has_credentials: false, allowed_domains: [], config: {}, enabled: true, last_sync_at: '2026-11-03T00:00:00Z', record_count: 1200, created_at: '', updated_at: '' },
  { id: '3', slug: 'acme-intel', name: 'Acme intel', category: 'data', tags: [], source_type: 'repository', repository_id: 'r2', manifest_version: 1, execution_backend: 'native', installed: false, requires_credential: 'none', credential_fields: [], has_credentials: false, allowed_domains: [], config: {}, enabled: false, record_count: 0, created_at: '', updated_at: '' },
];

vi.mock('@/lib/api', () => ({
  api: {
    marketplace: {
      listCatalog: async () => ({ entries, total: entries.length, stats: {} }),
      listRepos: async () => [
        { id: 'r1', name: 'nano Enrichments', slug: 'nano-enrichments', url: 'https://github.com/nano-rs/nano-enrichments', branch: 'main', enrichments_path: 'enrichments/', auto_sync_enabled: true, sync_interval_hours: 12, enrichment_count: 2, enabled: true, created_at: '', updated_at: '' },
        { id: 'r2', name: 'Acme', slug: 'acme', url: 'https://github.com/acme/marketplace', branch: 'main', enrichments_path: 'enrichments/', auto_sync_enabled: true, sync_interval_hours: 12, enrichment_count: 1, enabled: true, created_at: '', updated_at: '' },
      ],
      getCoverage: async () => ({ artifacts: [], computed_at: '' }),
      installEnrichment: vi.fn(),
    },
    listCustomEnrichments: () => listCustomEnrichments(),
    getSystemConfig: async () => ({ air_gap: false }),
    getPlatformFeeds: async () => { if (!bundle.value) throw new Error('404'); return bundle.value; },
    listSourceConfigs: async () => [
      { id: 's1', name: 'CloudTrail', config_type: 'aws_s3', enabled: true, deployed: true },
      { id: 's2', name: 'HEC', config_type: 'splunk_hec', enabled: true, deployed: true },
    ],
    connectorFeeds: {
      listSpecs: async () => [
        { name: 'okta_system_log', display_name: 'Okta System Log', credential_provider: 'okta', source_type: 'okta', schedule: '*/2 * * * *', config_fields: ['OKTA_DOMAIN'], optional_config_fields: [], credential_fields: ['API_TOKEN'] },
        { name: 'slack', display_name: 'Slack', credential_provider: 'slack', source_type: 'slack_access_log', schedule: '0 * * * *', config_fields: ['TEAM_ID'], optional_config_fields: [], credential_fields: ['USER_TOKEN'] },
      ],
      list: async () => [
        { id: 'cfeed_1', name: 'Okta prod', connector: 'okta_system_log', source_type: 'okta', enabled: true, running: false, schedule: null, effective_schedule: '*/2 * * * *', config: {}, credential_id: 'cred_1', max_run_secs: null, next_run_at: '2026-11-03T00:02:00Z', consecutive_failures: 0, last_run_at: null, last_status: 'success', last_error: null, last_success_at: '2026-11-03T00:00:00Z', created_at: '', spec_update_available: true },
      ],
    },
  },
}));

import { Marketplace } from './Marketplace';

window.matchMedia ??= ((query: string) => ({ matches: false, media: query, onchange: null, addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false })) as unknown as typeof window.matchMedia;
globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as unknown as typeof ResizeObserver;

function mount(path = '/marketplace') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <CapabilitiesContext.Provider value={{ edition: caps.edition, version: 'test', capabilities: caps.value }}>
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[path]}><Marketplace /></MemoryRouter>
      </QueryClientProvider>
    </CapabilitiesContext.Provider>,
  );
}
const card = (id: string) => document.querySelector(`[data-mp-slug="${id}"]`) as HTMLElement | null;

beforeEach(() => {
  caps.value = { customEnrichment: true, agentEnrichment: true } as Capabilities;
  caps.edition = 'enterprise';
  listCustomEnrichments.mockClear();
  bundle.value = null;
});
afterEach(cleanup);

describe('Marketplace inventory', () => {
  it('groups catalog, collectors, cloud pull and custom providers in one grid', async () => {
    mount();
    await screen.findByText('AbuseIPDB');
    expect(screen.getByText('Popular integrations')).toBeTruthy();
    expect(within(card('collector:okta_system_log')!).getByText('Installed · On')).toBeTruthy();
    expect(within(card('collector:okta_system_log')!).getByText('update available')).toBeTruthy();
    expect(within(card('collector:slack')!).queryByText('update available')).toBeNull();
    expect(screen.getByText('Identity')).toBeTruthy();
    expect(within(card('cloud-pull')!).getByText('1 source · Manage')).toBeTruthy();
    expect(within(card('custom:c9')!).getByText('Disable')).toBeTruthy();
    expect(within(card('acme-intel')!).getByText(/custom/)).toBeTruthy();
    expect(within(card('abuseipdb')!).getByText('Install')).toBeTruthy();
  });

  it('filters by chip and search', async () => {
    mount('/marketplace?category=pull');
    await waitFor(() => expect(card('collector:slack')).toBeTruthy());
    expect(card('abuseipdb')).toBeNull();
    expect(card('cloud-pull')).toBeTruthy();
    cleanup();
    mount();
    await screen.findByText('AbuseIPDB');
    fireEvent.change(document.getElementById('marketplace-search')!, { target: { value: 'tor' } });
    await waitFor(() => expect(card('abuseipdb')).toBeNull());
    expect(card('tor-exit-nodes')).toBeTruthy();
  });

  it('opens an item deep link in the inventory drawer', async () => {
    mount('/marketplace?slug=tor-exit-nodes');
    const details = await screen.findByTestId('inventory-details');
    expect(within(details).getByText('tor-exit-nodes')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Disable' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Uninstall' })).toBeTruthy();
  });

  it('open edition: enterprise backends carry an entitlement panel and no install action', async () => {
    caps.value = { customEnrichment: false, agentEnrichment: false } as Capabilities;
    caps.edition = 'open';
    mount('/marketplace?item=abuseipdb');
    const panel = await screen.findByRole('region', { name: 'Entitlement' });
    expect(within(panel).getByText('Requires the Enterprise edition')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Install' })).toBeNull();
    expect(listCustomEnrichments).not.toHaveBeenCalled();
    expect(card('custom:c9')).toBeNull();
  });

  it('marks cards nano\'s feed bundle provides, and shows the platform feeds panel', async () => {
    bundle.value = {
      available: true, installed: true, bundle_sha256: 'ab'.repeat(32), source: 'online', installed_at: '2026-11-03T00:00:00Z', stale_after_days: 7, notice: null,
      feeds: [{ feed_id: 'tor_exit_nodes', name: 'Tor exit nodes', revision: 4, produced_at: '2026-11-03T00:00:00Z', hard_expiry: '2026-11-10T00:00:00Z', age_seconds: 60, state: 'fresh', license_id: null, terms_revision: null, records: 1200, active: true, loaded: 1200 }],
    };
    mount();
    await waitFor(() => expect(within(card('tor-exit-nodes')!).getByText('Feed bundle')).toBeTruthy());
    expect(within(card('tor-exit-nodes')!).getByText('nano feed bundle')).toBeTruthy();
    expect(screen.getByTestId('platform-feeds-card')).toBeTruthy();
    expect(within(card('acme-intel')!).queryByText('Feed bundle')).toBeNull();
  });
});
