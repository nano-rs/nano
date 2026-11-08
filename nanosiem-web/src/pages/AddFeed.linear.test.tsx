// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4922 (main's AddFeed.shared tests, re-backed on the ClickHouse product):
 * "Add source" is one linear flow. Source → Details → Transport → Connect →
 * Parse → Review. A custom source is created as a draft at Transport →
 * Continue and receives a token at once; a repository source is imported
 * linked and deployed, so Connect can finish without parsing; an existing
 * source in the catalog opens its detail page to add a credential; and
 * `?source=` resumes an existing source on Connect.
 */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('@/lib/clipboard', () => ({ copyText: vi.fn().mockResolvedValue(true) }));

const mocks = vi.hoisted(() => ({
  createLogSource: vi.fn(), updateLogSource: vi.fn(), deployLogSource: vi.fn(), importParser: vi.fn(),
  getLogSource: vi.fn(), createToken: vi.fn(), getStatus: vi.fn(), listLogSources: vi.fn(), listStatus: vi.fn(),
}));
const access = vi.hoisted(() => ({ melod: false, permissions: new Set<string>() }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'u' }, hasPermission: (permission: string) => access.permissions.has(permission) }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }), toast: vi.fn() }));
vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ capabilities: { melod: access.melod } }) }));
vi.mock('@/enterprise/hooks/use-melod-job', async (original) => ({
  ...(await original<typeof import('@/enterprise/hooks/use-melod-job')>()),
  useMelodJob: () => ({ start: vi.fn(), loading: false }),
}));
vi.mock('@/components/editor/VrlEditor', () => ({
  VrlEditor: ({ value, onChange }: { value: string; onChange: (v: string) => void }) => (
    <textarea aria-label="VRL" value={value} onChange={(e) => onChange(e.target.value)} />
  ),
}));
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error {},
  api: {
    getSchemaFields: async () => ({ schema: 'ocsf', fields: [] }),
    getIngestEndpoint: async () => ({ base_url: 'http://siem.local', hostname: 'siem.local', scheme: 'http', hec_url: 'http://siem.local:8088',
      hec_event_url: 'http://siem.local:8088/services/collector/event', hec_health_url: '', nano_https_url: 'http://siem.local/ingest',
      otlp_logs_url: 'http://siem.local/otlp/v1/logs', otlp_traces_url: '', otlp_metrics_url: '', configured: true }),
    listLogSources: mocks.listLogSources,
    logSourceConnect: { listStatus: mocks.listStatus, getStatus: mocks.getStatus },
    listSourceConfigs: async () => [],
    listRoutingRules: async () => [],
    getLogSource: mocks.getLogSource,
    createLogSource: mocks.createLogSource,
    updateLogSource: mocks.updateLogSource,
    deployLogSource: mocks.deployLogSource,
    validateNamespace: async () => ({ valid: true }),
    validateLogSourceVrl: async () => ({ valid: true, errors: [], diagnostics: [] }),
    testLogSourceVrl: async () => ({ success: true, output: {} }),
    search: async () => ({ results: [] }),
    getSourceTypes: async () => [],
    ingestTokens: { create: mocks.createToken },
    parserRepositories: {
      importParser: mocks.importParser,
      listRepositories: async () => ({ repositories: [{ id: 'repo', name: 'nano-rs/parsers', enabled: true }] }),
      listParsers: async () => ['okta', 'unknown', 'otlp_log'].map((name) => ({ id: name, name, display_name: name === 'okta' ? 'Okta' : name,
        file_path: `${name}.yaml`, repository_id: 'repo', parser_vrl: '. = .', vendor: 'Okta', product: 'System log', category: 'identity' })),
    },
  },
}));

import { AddFeed } from './AddFeed';

function LocationProbe() {
  const location = useLocation();
  return <span data-testid="location">{`${location.pathname}${location.search}`}</span>;
}
function renderAddFeed(entry = '/ingestion/log-sources/new') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <AddFeed />
        <LocationProbe />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  access.melod = false;
  access.permissions = new Set(['settings:system', 'melod:parser']);
  Element.prototype.scrollIntoView ??= () => {};
  globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as unknown as typeof ResizeObserver;
  mocks.listLogSources.mockReset().mockResolvedValue([
    { id: 'lsrc_pa', name: 'Palo Alto traffic', match_values: ['palo_alto_traffic'], deployed: true, enabled: true, lifecycle_status: 'active', source_type: 'routed' },
  ]);
  mocks.listStatus.mockReset().mockResolvedValue([
    { source_id: 'lsrc_pa', route_key: 'palo_alto_traffic', state: 'receiving', deployed: true, lifecycle_status: 'active', push_capable: true, events_24h: 9, active_tokens: 1 },
  ]);
  mocks.getStatus.mockReset().mockResolvedValue({ source_id: 'lsrc_new', route_key: 'vercel', state: 'awaiting_data', deployed: false,
    lifecycle_status: 'draft', push_capable: true, events_24h: 0, active_tokens: 0, tokens: [] });
  mocks.createLogSource.mockReset().mockResolvedValue({ id: 'lsrc_new' });
  mocks.updateLogSource.mockReset().mockResolvedValue({ id: 'lsrc_new' });
  mocks.deployLogSource.mockReset().mockResolvedValue({ success: true });
  mocks.importParser.mockReset().mockResolvedValue({ log_source_id: 'lsrc_okta', import_type: 'linked' });
  mocks.createToken.mockReset().mockResolvedValue({ token: 'nit_TOKENVALUE', credential: { credential_id: 'cred-1', name: 'vercel-hec',
    token_prefix: 'nit_TOKENVA', state: 'active', route_key: 'vercel', created_at: '', revocable: true } });
  mocks.getLogSource.mockReset();
});
afterEach(cleanup);

async function reachCustomParser() {
  renderAddFeed();
  fireEvent.change(screen.getByLabelText('Source name'), { target: { value: 'Vercel' } });
  fireEvent.click(screen.getByTestId('source-continue'));
  await screen.findByTestId('feed-identifier');
  fireEvent.click(screen.getByTestId('details-continue'));
  fireEvent.click(within(await screen.findByTestId('transport-hec')).getByRole('radio'));
  fireEvent.click(screen.getByTestId('transport-continue'));
  await waitFor(() => expect(mocks.createLogSource).toHaveBeenCalled());
  fireEvent.click(await screen.findByRole('button', { name: /Issue token/ }));
  await waitFor(() => expect(mocks.createToken).toHaveBeenCalled());
  fireEvent.click(screen.getByRole('button', { name: 'Copy token' }));
  fireEvent.click(screen.getByTestId('connect-continue'));
  expect(await screen.findByTestId('parse-panes')).toBeTruthy();
}

it('walks a custom source Source → Details → Transport → Connect and binds the token to the new draft', async () => {
  renderAddFeed();
  expect(screen.getByTestId('add-feed-linear')).toBeTruthy();
  fireEvent.change(screen.getByLabelText('Source name'), { target: { value: 'Vercel' } });
  fireEvent.click(screen.getByTestId('source-continue'));
  const identifier = await screen.findByTestId('feed-identifier');
  expect((identifier as HTMLInputElement).value).toBe('vercel');
  // OCSF: the identifier is shown as the field Search scopes by.
  expect(screen.getByTestId('source-details').textContent).toContain('metadata.log_source =');
  fireEvent.click(screen.getByTestId('details-continue'));
  fireEvent.click(within(await screen.findByTestId('transport-hec')).getByRole('radio'));
  // No draft from a half-typed name: it is created at Transport → Continue.
  expect(mocks.createLogSource).not.toHaveBeenCalled();
  fireEvent.click(screen.getByTestId('transport-continue'));
  await waitFor(() => expect(mocks.createLogSource).toHaveBeenCalledWith(expect.objectContaining({ lifecycle_status: 'draft', match_values: ['vercel'], source_type: 'routed' })));
  fireEvent.click(await screen.findByRole('button', { name: /Issue token/ }));
  await waitFor(() => expect(mocks.createToken).toHaveBeenCalledWith('vercel-hec', 'lsrc_new'));
  expect(await screen.findByTestId('sender-snippet-body')).toBeTruthy();
  expect(screen.getByTestId('sender-snippet-body').textContent).toContain('http://siem.local:8088/services/collector/event');
  // Resumable address on Connect.
  await waitFor(() => expect(screen.getByTestId('location').textContent).toContain('source_id=lsrc_new'));
  expect(screen.getByTestId('location').textContent).toContain('stage=connect');
  // A custom source still needs its parser: Finish waits for the copy, Continue · sample & parse exists.
  expect(screen.getByTestId('connect-continue')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Copy token' }));
  fireEvent.click(screen.getByTestId('connect-continue'));
  expect(await screen.findByTestId('parse-panes')).toBeTruthy();
  expect(screen.queryByRole('button', { name: /Generate with pivt|Regenerate/ })).toBeNull();
  expect(screen.queryByRole('button', { name: 'pivt' })).toBeNull();
});

it('hides every parser AI affordance when melod exists but melod:parser is denied', async () => {
  access.melod = true;
  access.permissions = new Set(['settings:system']);
  await reachCustomParser();
  expect(screen.queryByRole('button', { name: /Generate with pivt|Regenerate/ })).toBeNull();
  expect(screen.queryByRole('button', { name: 'pivt' })).toBeNull();
  expect(screen.getByText('Recommended · validate against samples')).toBeTruthy();
});

it('shows parser AI affordances only when melod and melod:parser are both present', async () => {
  access.melod = true;
  access.permissions = new Set(['settings:system', 'melod:parser']);
  await reachCustomParser();
  expect(screen.getByRole('button', { name: 'Generate with pivt' })).toBeTruthy();
  expect(screen.getByRole('button', { name: 'pivt' })).toBeTruthy();
  expect(screen.getByText('Recommended · pivt drafts the parser')).toBeTruthy();
});

it('lists repository parsers without system slugs, and imports + deploys a repository source so Connect can finish', async () => {
  renderAddFeed();
  const catalog = await screen.findByTestId('source-catalog');
  await waitFor(() => expect(within(catalog).getByText('Okta')).toBeTruthy());
  expect(within(catalog).queryByText('unknown')).toBeNull();
  expect(within(catalog).queryByText('otlp_log')).toBeNull();
  fireEvent.click(within(catalog).getByText('Okta'));
  expect((screen.getByLabelText('Source name') as HTMLInputElement).value).toBe('Okta');
  fireEvent.click(screen.getByTestId('source-continue'));
  fireEvent.click(await screen.findByTestId('details-continue'));
  fireEvent.click(await screen.findByTestId('transport-continue'));
  await waitFor(() => expect(mocks.importParser).toHaveBeenCalledWith('repo', 'okta.yaml', expect.objectContaining({ import_type: 'linked', source_type: 'okta' })));
  await waitFor(() => expect(mocks.deployLogSource).toHaveBeenCalledWith('lsrc_okta'));
  expect(mocks.createLogSource).not.toHaveBeenCalled();
  expect(await screen.findByTestId('connect-finish')).toBeTruthy();
  expect(screen.queryByTestId('connect-continue')).toBeNull();
});

it('sends an existing source in the catalog to its detail page to add a credential', async () => {
  renderAddFeed();
  const catalog = await screen.findByTestId('source-catalog');
  fireEvent.click(await within(catalog).findByText('Palo Alto traffic'));
  await waitFor(() => expect(screen.getByTestId('location').textContent).toBe('/ingestion/log-sources/lsrc_pa?action=add-credential'));
});

it('resumes ?source=<route key> on Connect for that source', async () => {
  mocks.getLogSource.mockResolvedValue({ id: 'lsrc_pa', name: 'Palo Alto traffic', match_values: ['palo_alto_traffic'], namespace: 'default', parser_vrl: '', source_type: 'routed' });
  renderAddFeed('/ingestion/log-sources/new?source=palo_alto_traffic');
  await waitFor(() => expect(screen.getByTestId('location').textContent).toContain('source_id=lsrc_pa'));
  await waitFor(() => expect(mocks.getLogSource).toHaveBeenCalledWith('lsrc_pa'));
  expect(await screen.findByRole('button', { name: /Issue token/ })).toBeTruthy();
});
