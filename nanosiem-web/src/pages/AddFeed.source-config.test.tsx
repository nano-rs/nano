// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-6036: Add source → "Source configuration" with a library parser sent
 * `ingestion_method: 'routed'` for every configuration, so a Vector (or any
 * non-HTTP) configuration failed with "incompatible with parser
 * ingestion_method 'routed'". These cover the method sent per configuration,
 * the disabled configurations and their reasons, and the forward paths
 * (continue / skip) after a step fails, without going back.
 *
 * The API mock mirrors AddFeed.linear.test.tsx.
 */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('@/lib/clipboard', () => ({ copyText: vi.fn().mockResolvedValue(true) }));

const mocks = vi.hoisted(() => ({
  createLogSource: vi.fn(), updateLogSource: vi.fn(), deployLogSource: vi.fn(), importParser: vi.fn(),
  getLogSource: vi.fn(), createToken: vi.fn(), getStatus: vi.fn(), listLogSources: vi.fn(), listStatus: vi.fn(),
  validateLogSourceVrl: vi.fn(), listSourceConfigs: vi.fn(), deploySourceConfig: vi.fn(), createRoutingRule: vi.fn(),
}));
const access = vi.hoisted(() => ({ melod: false, permissions: new Set<string>() }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'u' }, hasPermission: (permission: string) => access.permissions.has(permission) }),
}));
const toastSpy = vi.hoisted(() => vi.fn());
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: toastSpy }), toast: toastSpy }));
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
    listSourceConfigs: mocks.listSourceConfigs,
    deploySourceConfig: mocks.deploySourceConfig,
    createRoutingRule: mocks.createRoutingRule,
    checkRoutingRuleReachability: async () => ({ reachable: true, source_config_enabled: true, source_config_deployed: true }),
    listRoutingRules: async () => [],
    getLogSource: mocks.getLogSource,
    createLogSource: mocks.createLogSource,
    updateLogSource: mocks.updateLogSource,
    deployLogSource: mocks.deployLogSource,
    validateNamespace: async () => ({ valid: true }),
    validateLogSourceVrl: mocks.validateLogSourceVrl,
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

const CONFIGS = [
  { id: 'sc_http', name: 'HTTP Ingestion', config_type: 'http', enabled: true, deployed: true },
  { id: 'sc_otlp', name: 'OpenTelemetry (OTLP)', config_type: 'otlp', enabled: true, deployed: true },
  { id: 'sc_vector', name: 'Vector Ingestion', config_type: 'vector', enabled: true, deployed: true },
  { id: 'sc_kafka', name: 'Prod Kafka', config_type: 'kafka', enabled: true, deployed: true },
  { id: 'sc_s3', name: 'CloudTrail bucket', config_type: 'aws_s3', enabled: true, deployed: false },
];


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
  access.permissions = new Set(['settings:system', 'melod:parser', 'source_configs:edit', 'source_configs:deploy', 'credentials:use']);
  mocks.listSourceConfigs.mockReset().mockResolvedValue(CONFIGS);
  mocks.deploySourceConfig.mockReset().mockResolvedValue({ success: true });
  mocks.createRoutingRule.mockReset().mockResolvedValue({ id: 'rule' });
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
  mocks.validateLogSourceVrl.mockReset().mockResolvedValue({ valid: true, errors: [], diagnostics: [] });
  localStorage.removeItem('add-feed-side-pane-collapsed');
});
afterEach(cleanup);

async function reachTransport(catalogName?: string) {
  renderAddFeed();
  if (catalogName) {
    const catalog = await screen.findByTestId('source-catalog');
    await waitFor(() => expect(within(catalog).getByText(catalogName)).toBeTruthy());
    fireEvent.click(within(catalog).getByText(catalogName));
  } else {
    fireEvent.change(screen.getByLabelText('Source name'), { target: { value: 'Vercel' } });
  }
  fireEvent.click(screen.getByTestId('source-continue'));
  fireEvent.click(await screen.findByTestId('details-continue'));
  fireEvent.click(within(await screen.findByTestId('transport-pull')).getByRole('radio'));
  await screen.findByTestId('source-config-sc_vector');
}

const card = (id: string) => screen.getByTestId(`source-config-${id}`) as HTMLButtonElement;

it('the reported bug: a library parser on the Vector configuration imports with ingestion_method vector', async () => {
  await reachTransport('Okta');
  fireEvent.click(card('sc_vector'));
  fireEvent.click(screen.getByTestId('transport-continue'));
  await waitFor(() => expect(mocks.importParser).toHaveBeenCalledWith('repo', 'okta.yaml', expect.objectContaining({
    import_type: 'linked', source_type: 'okta', ingestion_method: 'vector', dispatch_source_config_id: 'sc_vector',
  })));
  await waitFor(() => expect(mocks.deployLogSource).toHaveBeenCalledWith('lsrc_okta', { ocsf: { unattestedSystemInstall: true } }));
  expect(await screen.findByText('Review & publish')).toBeTruthy();
  expect(screen.queryByTestId('transport-error')).toBeNull();
  // neon P1-2: the wizard never deploys a source configuration at Transport
  // (Vector has no route of its own; deploying it can evict HTTP's route).
  expect(mocks.deploySourceConfig).not.toHaveBeenCalled();
  // Vector events reach the router directly: no config deploy is needed.
  expect(screen.queryByTestId('config-deploy-needed')).toBeNull();
});

it.each([
  ['sc_http', 'routed'],
  ['sc_kafka', 'kafka'],
])('a library parser on %s imports with %s', async (configId, method) => {
  await reachTransport('Okta');
  fireEvent.click(card(configId));
  fireEvent.click(screen.getByTestId('transport-continue'));
  await waitFor(() => expect(mocks.importParser).toHaveBeenCalledWith('repo', 'okta.yaml', expect.objectContaining({
    ingestion_method: method, dispatch_source_config_id: configId,
  })));
});

it('a library parser cannot pick a pull configuration that is not running, and says why', async () => {
  await reachTransport('Okta');
  expect(card('sc_s3').disabled).toBe(true);
  expect(screen.getByTestId('source-config-sc_s3-reason').textContent).toMatch(/not running yet/);
  // Deployed pull and always-on listeners stay usable.
  expect(card('sc_kafka').disabled).toBe(false);
  expect(card('sc_vector').disabled).toBe(false);
  fireEvent.click(card('sc_s3'));
  expect((screen.getByTestId('transport-continue') as HTMLButtonElement).disabled).toBe(true);
  expect(mocks.importParser).not.toHaveBeenCalled();
});

it('without source_configs:edit every configuration is disabled with a plain reason, and push still works', async () => {
  access.permissions = new Set(['settings:system', 'melod:parser']);
  await reachTransport('Okta');
  for (const c of CONFIGS) {
    expect(card(c.id).disabled).toBe(true);
    expect(screen.getByTestId(`source-config-${c.id}-reason`).textContent).toMatch(/permission to edit source configurations/);
  }
  fireEvent.click(within(screen.getByTestId('transport-hec')).getByRole('radio'));
  fireEvent.click(screen.getByTestId('transport-continue'));
  await waitFor(() => expect(mocks.importParser).toHaveBeenCalledWith('repo', 'okta.yaml', expect.objectContaining({ ingestion_method: 'routed', dispatch_source_config_id: undefined })));
});

it('a custom source on a source configuration is still saved as routed, bound to that configuration', async () => {
  await reachTransport();
  // Custom sources may use an undeployed configuration: Review warns about it.
  expect(card('sc_s3').disabled).toBe(false);
  fireEvent.click(card('sc_vector'));
  fireEvent.click(screen.getByTestId('transport-continue'));
  await waitFor(() => expect(mocks.createLogSource).toHaveBeenCalledWith(expect.objectContaining({
    source_type: 'routed', dispatch_source_config_id: 'sc_vector', lifecycle_status: 'draft',
  })));
  expect(mocks.importParser).not.toHaveBeenCalled();
});

it('a failed import keeps the user on Transport with the choice kept, and Continue works after a retry', async () => {
  mocks.importParser.mockRejectedValueOnce(new Error('Bad request: something went wrong'));
  await reachTransport('Okta');
  fireEvent.click(card('sc_vector'));
  fireEvent.click(screen.getByTestId('transport-continue'));
  const error = await screen.findByTestId('transport-error');
  expect(error.textContent).toContain('something went wrong');
  // No source exists yet: say why the step is required, no skip.
  expect(error.textContent).toMatch(/has to be created before you can go on/);
  expect(screen.queryByTestId('transport-skip')).toBeNull();
  // Choices kept: still on Source configuration with Vector selected.
  expect(card('sc_vector').className).toContain('border-primary');
  fireEvent.click(screen.getByTestId('transport-continue'));
  await waitFor(() => expect(mocks.importParser).toHaveBeenCalledTimes(2));
  expect(await screen.findByText('Review & publish')).toBeTruthy();
  await waitFor(() => expect(screen.queryByTestId('transport-error')).toBeNull());
});

it('when the source was created but going live failed, the user can continue without going back', async () => {
  mocks.deployLogSource.mockResolvedValueOnce({ success: false, message: 'Vector reload failed' });
  await reachTransport('Okta');
  fireEvent.click(card('sc_kafka'));
  fireEvent.click(screen.getByTestId('transport-continue'));
  const error = await screen.findByTestId('transport-error');
  expect(error.textContent).toContain('Vector reload failed');
  fireEvent.click(screen.getByTestId('transport-skip'));
  expect(await screen.findByText('Review & publish')).toBeTruthy();
  expect(screen.queryByTestId('transport-error')).toBeNull();
  // Not imported twice.
  expect(mocks.importParser).toHaveBeenCalledTimes(1);
});

it('Connect offers Skip for now when no token was issued, and finishes to the list', async () => {
  await reachTransport('Okta');
  fireEvent.click(within(screen.getByTestId('transport-hec')).getByRole('radio'));
  fireEvent.click(screen.getByTestId('transport-continue'));
  const finish = (await screen.findByTestId('connect-finish')) as HTMLButtonElement;
  expect(finish.disabled).toBe(true);
  fireEvent.click(screen.getByTestId('connect-skip'));
  await waitFor(() => expect(screen.getByTestId('location').textContent).toMatch(/^\/ingestion\/log-sources\?highlight=lsrc_okta/));
});

it('Connect hides Skip once a token was issued (it is shown once) and says how to finish', async () => {
  await reachTransport('Okta');
  fireEvent.click(within(screen.getByTestId('transport-hec')).getByRole('radio'));
  fireEvent.click(screen.getByTestId('transport-continue'));
  fireEvent.click(await screen.findByRole('button', { name: /Issue token/ }));
  await waitFor(() => expect(mocks.createToken).toHaveBeenCalled());
  await waitFor(() => expect(screen.queryByTestId('connect-skip')).toBeNull());
  expect(screen.getByTestId('connect-finish-hint').textContent).toMatch(/shown only once/);
});

it('parser errors do not trap the user on Parse: Continue anyway goes to Review', async () => {
  renderAddFeed();
  fireEvent.change(screen.getByLabelText('Source name'), { target: { value: 'Vercel' } });
  fireEvent.click(screen.getByTestId('source-continue'));
  fireEvent.click(await screen.findByTestId('details-continue'));
  fireEvent.click(within(await screen.findByTestId('transport-hec')).getByRole('radio'));
  fireEvent.click(screen.getByTestId('transport-continue'));
  await waitFor(() => expect(mocks.createLogSource).toHaveBeenCalled());
  fireEvent.click(await screen.findByTestId('connect-continue'));
  await screen.findByTestId('parse-panes');
  mocks.validateLogSourceVrl.mockResolvedValue({
    valid: false,
    errors: ['error[E103]: unhandled fallible assignment'],
    diagnostics: [{ severity: 'error', message: 'error[E103]: unhandled fallible assignment' }],
  });
  fireEvent.change(screen.getByLabelText('VRL'), { target: { value: '.a = upcase(.b)' } });
  fireEvent.click(screen.getByRole('button', { name: 'Validate' }));
  expect(await screen.findByTestId('parse-continue-hint')).toBeTruthy();
  const next = screen.getByTestId('parse-continue') as HTMLButtonElement;
  expect(next.disabled).toBe(false);
  expect(next.textContent).toContain('Continue anyway');
  fireEvent.click(next);
  expect(await screen.findByText('Review & publish')).toBeTruthy();
});

it('a resumed source keeps its stored ingestion method when saved again', async () => {
  mocks.getLogSource.mockResolvedValue({ id: 'lsrc_k', name: 'Okta', match_values: ['okta'], namespace: 'default', parser_vrl: '. = .',
    source_type: 'kafka', dispatch_source_config_id: 'sc_kafka', timezone: 'UTC' });
  renderAddFeed('/ingestion/log-sources/new?source_id=lsrc_k&stage=transport');
  await waitFor(() => expect(mocks.getLogSource).toHaveBeenCalledWith('lsrc_k'));
  await screen.findByTestId('source-config-sc_kafka', undefined, { timeout: 3000 });
  await waitFor(() => expect(card('sc_kafka').className).toContain('border-primary'));
  fireEvent.click(screen.getByTestId('transport-continue'));
  await waitFor(() => expect(mocks.updateLogSource).toHaveBeenCalledWith('lsrc_k', expect.objectContaining({
    source_type: 'kafka', dispatch_source_config_id: 'sc_kafka',
  })));
});

it('neon P1-1: a library parser cannot pick the OpenTelemetry configuration, and says why', async () => {
  await reachTransport('Okta');
  expect(card('sc_otlp').disabled).toBe(true);
  expect(screen.getByTestId('source-config-sc_otlp-reason').textContent).toMatch(/Pick OTLP above instead/);
});

it('neon P1-2: a library pull source tells the user its configuration needs a deploy, and links to it, without deploying it', async () => {
  await reachTransport('Okta');
  fireEvent.click(card('sc_kafka'));
  fireEvent.click(screen.getByTestId('transport-continue'));
  const note = await screen.findByTestId('config-deploy-needed');
  expect(note.textContent).toContain('Prod Kafka');
  expect(within(note).getByRole('link').getAttribute('href')).toBe('/ingestion/source-configurations/sc_kafka');
  expect(mocks.deploySourceConfig).not.toHaveBeenCalled();
});

it('neon P1-4: without source_configs:deploy, live configurations are disabled; without credentials:use a custom source cannot use a credential-backed one', async () => {
  access.permissions = new Set(['settings:system', 'melod:parser', 'source_configs:edit', 'credentials:use']);
  await reachTransport('Okta');
  expect(card('sc_kafka').disabled).toBe(true);
  expect(screen.getByTestId('source-config-sc_kafka-reason').textContent).toMatch(/permission to deploy source configurations/);
  cleanup();
  access.permissions = new Set(['settings:system', 'melod:parser', 'source_configs:edit', 'source_configs:deploy']);
  mocks.listSourceConfigs.mockResolvedValue([...CONFIGS, { id: 'sc_cred', name: 'Creds Kafka', config_type: 'kafka', enabled: true, deployed: true, credential_id: 'cred_1' }]);
  await reachTransport();
  expect(card('sc_cred').disabled).toBe(true);
  expect(screen.getByTestId('source-config-sc_cred-reason').textContent).toMatch(/permission to use credentials/);
  expect(card('sc_kafka').disabled).toBe(false);
});

it('neon P1-3: once a library source is imported the Transport choice is locked, so a retry cannot rebind it', async () => {
  mocks.deployLogSource.mockResolvedValueOnce({ success: false, message: 'Vector reload failed' });
  await reachTransport('Okta');
  fireEvent.click(card('sc_kafka'));
  fireEvent.click(screen.getByTestId('transport-continue'));
  await screen.findByTestId('transport-error');
  expect(screen.getByTestId('transport-locked')).toBeTruthy();
  // Other cards and the push options cannot be picked now.
  expect(card('sc_http').disabled).toBe(true);
  fireEvent.click(card('sc_http'));
  fireEvent.click(within(screen.getByTestId('transport-hec')).getByRole('radio'));
  expect(card('sc_kafka').className).toContain('border-primary');
  // Retrying goes live again on the same binding; it does not re-import.
  fireEvent.click(screen.getByTestId('transport-continue'));
  expect(await screen.findByText('Review & publish')).toBeTruthy();
  expect(mocks.importParser).toHaveBeenCalledTimes(1);
  expect(mocks.deployLogSource).toHaveBeenCalledTimes(2);
  // The retry saves the source as it is: same method, same configuration.
  expect(mocks.updateLogSource).toHaveBeenCalledWith('lsrc_okta', expect.objectContaining({ source_type: 'kafka', dispatch_source_config_id: 'sc_kafka' }));
});

it('neon P1-3: a resumed pull source is locked to its transport; a custom routed draft still can switch', async () => {
  mocks.getLogSource.mockResolvedValue({ id: 'lsrc_k', name: 'Okta', match_values: ['okta'], namespace: 'default', parser_vrl: '. = .',
    source_type: 'kafka', dispatch_source_config_id: 'sc_kafka', timezone: 'UTC' });
  renderAddFeed('/ingestion/log-sources/new?source_id=lsrc_k&stage=transport');
  await screen.findByTestId('source-config-sc_kafka', undefined, { timeout: 3000 });
  expect(screen.getByTestId('transport-locked')).toBeTruthy();
  fireEvent.click(within(screen.getByTestId('transport-hec')).getByRole('radio'));
  expect(screen.getByTestId('source-config-sc_kafka')).toBeTruthy(); // still on Source configuration
  cleanup();
  mocks.getLogSource.mockResolvedValue({ id: 'lsrc_c', name: 'Vercel', match_values: ['vercel'], namespace: 'default', parser_vrl: '',
    source_type: 'routed', dispatch_source_config_id: null, timezone: 'UTC' });
  renderAddFeed('/ingestion/log-sources/new?source_id=lsrc_c&stage=transport');
  await screen.findByTestId('transport-pull', undefined, { timeout: 3000 });
  expect(screen.queryByTestId('transport-locked')).toBeNull();
});

it('neon P2-2: Skip for now and Cancel wait while a token is being created', async () => {
  let release: (v: unknown) => void = () => {};
  mocks.createToken.mockReturnValueOnce(new Promise((r) => { release = r; }));
  await reachTransport('Okta');
  fireEvent.click(within(screen.getByTestId('transport-hec')).getByRole('radio'));
  fireEvent.click(screen.getByTestId('transport-continue'));
  expect(await screen.findByTestId('connect-skip')).toBeTruthy();
  fireEvent.click(await screen.findByRole('button', { name: /Issue token/ }));
  await waitFor(() => expect(mocks.createToken).toHaveBeenCalled());
  await waitFor(() => expect(screen.queryByTestId('connect-skip')).toBeNull());
  expect((screen.getByTestId('add-feed-cancel') as HTMLButtonElement).disabled).toBe(true);
  release({ token: 'nit_TOKENVALUE', credential: { credential_id: 'cred-1', name: 'okta-hec', token_prefix: 'nit_TOKENVA', state: 'active',
    route_key: 'okta', created_at: '', revocable: true } });
  await waitFor(() => expect((screen.getByTestId('add-feed-cancel') as HTMLButtonElement).disabled).toBe(false));
});
