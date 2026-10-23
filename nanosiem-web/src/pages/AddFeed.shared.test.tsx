// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-2593: AddFeed is the hosted-shared "Add data" flow. Step 1 asks how data
 * arrives and which source (never a source configuration), an existing source
 * goes straight to the Issue step, and dedicated deployments keep the original
 * transport picker.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { TenantIngestEndpoint } from '@/lib/api/types';
import { addDataLink } from '@/lib/add-data-sources';
import { AddFeed } from './AddFeed';

const TENANT = 'b464ceb9-28a6-4249-8e29-3489627ac5f6';
const HOST = `${TENANT}.ingest.nano.rs`;

const mocks = vi.hoisted(() => ({
  mode: 'enterprise_shared' as string,
  getIngestEndpoint: vi.fn(),
  listLogSources: vi.fn(),
  listSourceConfigs: vi.fn(),
  listParserRollouts: vi.fn(),
  getParserRollout: vi.fn(),
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 'user_me', deployment_mode: mocks.mode },
    hasPermission: () => true,
  }),
}));
vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ capabilities: {} }) }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/enterprise/hooks/use-melod-job', () => ({ useMelodJob: () => ({ start: vi.fn(), loading: false }) }));
vi.mock('@/components/editor/VrlEditor', () => ({ VrlEditor: () => null }));
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error {},
  api: {
    getSchemaFields: async () => ({ schema: 'ocsf', fields: [] }),
    getIngestEndpoint: mocks.getIngestEndpoint,
    listLogSources: mocks.listLogSources,
    listSourceConfigs: mocks.listSourceConfigs,
    listParserRollouts: mocks.listParserRollouts,
    getParserRollout: mocks.getParserRollout,
    listRoutingRules: async () => [],
    getSenderTemplates: async () => ({ version: 1, placeholders: [], templates: [] }),
    sourceScopes: { listRestricted: async () => ({ restricted: [] }) },
    precheckIngestCredential: async () => ({ verdict: null, allowed: true, needs_acknowledgement: false, blocked: false }),
  },
}));

const endpoint: TenantIngestEndpoint = {
  hostname: HOST, base_url: `https://${HOST}`, hec_url: `https://${HOST}/services/collector/event`,
  otlp_logs_url: `https://${HOST}/v1/logs`, otlp_traces_url: `https://${HOST}/v1/traces`, otlp_metrics_url: `https://${HOST}/v1/metrics`,
  otlp_telemetry_ingested: false, nano_https_url: `https://${HOST}/ingest`, hec_health_url: '', endpoint_state: 'ready',
  sources: [
    { credential_id: 'c1', route_id: 'r1', protocol: 'hec', label: 'route template: palo_alto_traffic', source_slug: 'palo_alto_traffic',
      credential_state: 'active', route_state: 'active', route_revision: 1, cell_name: 'cell', cell_state: 'ready', created_at: '' },
    { credential_id: 'c2', route_id: 'r2', protocol: 'hec', label: 'route template: okta', source_slug: 'okta',
      credential_state: 'active', route_state: 'active', route_revision: 1, cell_name: 'cell', cell_state: 'ready', created_at: '' },
  ],
  credential_issuance: { managed_by_platform: false, reason: '', detail: '' },
  ingress_contract: { version: 1, credential_kinds: ['source'], collector_credentials: false, source_declarations: [] },
};

function renderAddFeed(entry = '/ingestion/log-sources/wizard') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <AddFeed />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  mocks.mode = 'enterprise_shared';
  mocks.getIngestEndpoint.mockReset().mockResolvedValue(endpoint);
  mocks.listLogSources.mockReset().mockResolvedValue([
    { id: 'feed_pa', name: 'Palo Alto traffic', match_values: ['palo_alto_traffic'], deployed: true, enabled: true, lifecycle_status: 'active' },
  ]);
  mocks.listParserRollouts.mockReset().mockResolvedValue([]);
  mocks.getParserRollout.mockReset();
  mocks.listSourceConfigs.mockReset().mockResolvedValue([
    { id: 'sc_http', name: 'HTTP ingest', config_type: 'http', connection_config: {}, enabled: true },
  ]);
});
afterEach(cleanup);

describe('AddFeed → Add data (NAN-2593)', () => {
  it('shared Step 1 asks how data arrives, shows the real endpoint and lists enrolled sources', async () => {
    renderAddFeed();
    expect(screen.getByText('Add data')).toBeTruthy();
    expect(screen.getByText('How will this data arrive?')).toBeTruthy();
    const card = await screen.findByTestId('ingest-endpoint-card');
    expect(card.textContent).toContain(HOST);
    expect(card.textContent).not.toContain('{your-ingest-host}');
    expect(screen.queryByText('Ingestion source')).toBeNull();
    expect(mocks.listSourceConfigs).not.toHaveBeenCalled();

    const list = await screen.findByRole('radiogroup', { name: 'Existing source' });
    const rows = within(list).getAllByRole('radio');
    expect(rows.map((r) => r.textContent)).toEqual([
      expect.stringContaining('okta'),
      expect.stringContaining('palo_alto_traffic'),
    ]);
    expect(rows[1].textContent).toContain('Palo Alto traffic');
    // Collector stays hidden until the tenant's Worker accepts it (NAN-2597).
    expect(screen.queryByRole('radio', { name: /collector/i })).toBeNull();
  });

  it('an existing source goes straight to the Issue step', async () => {
    renderAddFeed();
    const list = await screen.findByRole('radiogroup', { name: 'Existing source' });
    const next = screen.getByRole('button', { name: /continue · issue credential/i }) as HTMLButtonElement;
    expect(next.disabled).toBe(true);
    fireEvent.click(within(list).getByText('palo_alto_traffic'));
    expect(next.disabled).toBe(false);
    fireEvent.click(next);
    const panel = await screen.findByTestId('issue-credential-panel');
    expect(panel.textContent).toContain('palo_alto_traffic');
    expect((within(panel).getByLabelText('Label') as HTMLInputElement).value).toBe('palo_alto_traffic-hec');
    // The parser steps are not part of this path.
    expect(screen.queryByText('Sample & parse')).toBeNull();
  });

  it('?source=<slug> preselects that source and opens the Issue step (NAN-2946)', async () => {
    renderAddFeed(addDataLink('okta'));
    const panel = await screen.findByTestId('issue-credential-panel');
    expect(panel.textContent).toContain('okta');
    expect((within(panel).getByLabelText('Label') as HTMLInputElement).value).toBe('okta-hec');
    expect(screen.queryByText('Sample & parse')).toBeNull();
  });

  it('an unknown ?source= slug leaves the wizard on Step 1 (NAN-2946)', async () => {
    renderAddFeed(addDataLink('not_enrolled_anywhere'));
    const list = await screen.findByRole('radiogroup', { name: 'Existing source' });
    expect(within(list).getAllByRole('radio').every((r) => r.getAttribute('aria-checked') !== 'true')).toBe(true);
    expect(screen.queryByTestId('issue-credential-panel')).toBeNull();
  });

  it('a custom source keeps the open-core parser steps and names it with a feed id', async () => {
    renderAddFeed();
    await screen.findByTestId('ingest-endpoint-card');
    fireEvent.click(screen.getByRole('tab', { name: 'New custom source' }));
    expect(screen.getByPlaceholderText('aws_cloudtrail')).toBeTruthy();
    expect(screen.getByRole('button', { name: /continue · sample & parse/i })).toBeTruthy();
    expect(screen.getAllByText('Review & activate').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Issue a credential').length).toBe(1);
  });

  it('collector arrival (NAN-2597): one token for several sources, straight to the collector Issue step', async () => {
    mocks.getIngestEndpoint.mockResolvedValue({
      ...endpoint,
      ingress_contract: {
        version: 2, credential_kinds: ['source', 'collector'], collector_credentials: true,
        source_declarations: ['hec:event.sourcetype', 'otlp_http:resource.nano.source'],
      },
    });
    renderAddFeed();
    fireEvent.click(await screen.findByRole('radio', { name: 'Collector' }));
    const group = await screen.findByRole('group', { name: 'Collector sources' });
    expect(screen.queryByRole('tab', { name: 'New custom source' })).toBeNull();
    const next = screen.getByRole('button', { name: /continue · issue collector/i }) as HTMLButtonElement;
    expect(next.disabled).toBe(true);
    fireEvent.click(within(group).getByRole('checkbox', { name: 'palo_alto_traffic' }));
    fireEvent.click(within(group).getByRole('checkbox', { name: 'okta' }));
    expect(screen.getByTestId('collector-selected-count').textContent).toBe('2 selected');
    expect(next.disabled).toBe(false);
    fireEvent.click(next);
    const panel = await screen.findByTestId('issue-credential-panel');
    expect(within(panel).getByTestId('collector-source-count').textContent).toBe('2');
    expect((within(panel).getByLabelText('Label') as HTMLInputElement).value).toBe('collector-hec');
    // Vendor sourcetype conventions are prefilled as removable aliases.
    expect(within(panel).getByTestId('collector-source-palo_alto_traffic').textContent).toContain('pan:traffic');
    expect(within(panel).getByTestId('collector-source-okta').textContent).toContain('OktaIM2:log');
    expect(within(panel).getByTestId('collector-unknown-note').textContent).toMatch(/land as unknown/);
    expect(screen.getAllByText('Issue a collector credential').length).toBe(1);
    expect(screen.queryByText('Sample & parse')).toBeNull();
  });

  it('a source still rolling out shows its rollout on the Issue step (NAN-2607)', async () => {
    const rollout = {
      id: '99999999-9999-4999-8999-999999999999', kind: 'publish', state: 'building', log_source_id: 'feed_acme',
      log_source_version_ids: [], base_offer_id: null, requested_by: 'user_me', requested_at: '2026-09-22T12:00:00Z',
      request_reason: null, state_revision: 2, roll_id: null, bundle_revision: null, content_sha256: null, report_sha256: null,
      failure_reason: null, failure_component: null, failure_stage: null, stage_timings: null, updated_at: '2026-09-22T12:00:00Z',
      completed_at: null, terminal: false,
    };
    mocks.listLogSources.mockResolvedValue([
      { id: 'feed_acme', name: 'Acme app', match_values: ['acme_app'], deployed: true, enabled: true, lifecycle_status: 'active' },
    ]);
    mocks.listParserRollouts.mockResolvedValue([rollout]);
    mocks.getParserRollout.mockResolvedValue(rollout);
    renderAddFeed();
    const list = await screen.findByRole('radiogroup', { name: 'Existing source' });
    fireEvent.click(within(list).getByText('acme_app'));
    fireEvent.click(screen.getByRole('button', { name: /continue · issue credential/i }));
    const strip = await screen.findByTestId('issue-rollout');
    expect(within(strip).getByTestId('rollout-state').textContent).toBe('Building');
    const panel = await screen.findByTestId('issue-credential-panel');
    expect(panel.textContent).toContain('held at the edge');
  });

  it('dedicated deployments keep the original transport picker', async () => {
    mocks.mode = 'dedicated';
    renderAddFeed();
    expect(screen.getByText('Add a new feed')).toBeTruthy();
    // NAN-4132: no AI capability → the hero copy does not promise pivt drafting.
    expect(screen.queryByText(/pivt/)).toBeNull();
    expect(screen.getByText('Ingestion source')).toBeTruthy();
    expect(await screen.findByText('HTTP ingest')).toBeTruthy();
    expect(mocks.getIngestEndpoint).not.toHaveBeenCalled();
    expect(screen.queryByTestId('issue-credential-panel')).toBeNull();
  });
});
