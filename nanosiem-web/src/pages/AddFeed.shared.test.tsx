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
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { TenantIngestEndpoint } from '@/lib/api/types';
import { addDataLink } from '@/lib/add-data-sources';
import { AddFeed } from './AddFeed';
import { getEditableArtifact, rebaseVrlPatch, resetEditableArtifact } from '@/contexts/EditableArtifactContext';
import { startEditTurn, resetEditSessions } from '@/enterprise/components/pivt/drafts/edit-session';
import { getPivtDraftRuns, resetPivtDraftStore } from '@/enterprise/components/pivt/drafts/draft-store';
import { runCardAction, resetRunActions } from '@/enterprise/components/pivt/drafts/interactive';
import { copyText } from '@/lib/clipboard';

vi.mock('@/lib/clipboard', () => ({ copyText: vi.fn().mockResolvedValue(true) }));

const TENANT = 'b464ceb9-28a6-4249-8e29-3489627ac5f6';
const HOST = `${TENANT}.ingest.nano.rs`;

const mocks = vi.hoisted(() => ({
  mode: 'enterprise_shared' as string,
  schema: 'ocsf',
  melod: false, getLogSource: vi.fn(), search: vi.fn(), melodEditParser: vi.fn(),
  getIngestEndpoint: vi.fn(),
  listLogSources: vi.fn(),
  listSourceConfigs: vi.fn(),
  listParserRollouts: vi.fn(),
  getParserRollout: vi.fn(),
  validateLogSourceVrl: vi.fn(),
  testLogSourceVrl: vi.fn(),
  importParser: vi.fn(),
  createLogSource: vi.fn(),
  updateLogSource: vi.fn(),
  deployLogSource: vi.fn(),
  requestIngestCredential: vi.fn(),
  assignIngestSource: vi.fn(),
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 'user_me', deployment_mode: mocks.mode },
    hasPermission: () => true,
  }),
}));
vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ capabilities: {melod:mocks.melod} }) }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/enterprise/hooks/use-melod-job', async (original) => ({...(await original<typeof import('@/enterprise/hooks/use-melod-job')>()), useMelodJob: () => ({ start: vi.fn(), loading: false }) }));
vi.mock('@/components/editor/VrlEditor', () => ({
  VrlEditor: ({ value, onChange }: { value: string; onChange: (v: string) => void }) => (
    <textarea aria-label="VRL" value={value} onChange={(e) => onChange(e.target.value)} />
  ),
}));
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error {},
  api: {
    getSchemaFields: async () => ({ schema: mocks.schema, fields: [] }),
    getIngestEndpoint: mocks.getIngestEndpoint,
    getLogSource:mocks.getLogSource, search:mocks.search, melodEditParser:mocks.melodEditParser,
    listLogSources: mocks.listLogSources,
    listSourceConfigs: mocks.listSourceConfigs,
    requestIngestCredential: mocks.requestIngestCredential,
    assignIngestSource: mocks.assignIngestSource,
    listParserRollouts: mocks.listParserRollouts,
    getParserRollout: mocks.getParserRollout,
    validateLogSourceVrl: mocks.validateLogSourceVrl,
    testLogSourceVrl: mocks.testLogSourceVrl,
    validateNamespace: async () => ({ valid: true }),
    createLogSource: mocks.createLogSource,
    updateLogSource: mocks.updateLogSource,
    deployLogSource: mocks.deployLogSource,
    parserRepositories: { importParser: mocks.importParser, listRepositories: async () => ({repositories:[{id:'repo',name:'nano-rs/parsers',enabled:true},{id:'private',name:'acme/security-parsers',enabled:true}]}), listParsers: async (repositoryId:string) => repositoryId==='private'?[{id:'internal',name:'internal_sso',display_name:'Internal SSO',file_path:'sso.yaml',repository_id:'private',parser_vrl:'. = .'}]:['okta','unknown','default','otlp_log','otlp_metric','otlp_trace'].map(name=>({id:name,name,display_name:name,file_path:`${name}.yaml`,repository_id:'repo',parser_vrl:'. = .',vendor:'Okta',product:'System log',category:'identity'})) },
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

function LocationProbe() {
  const location = useLocation();
  return <span data-testid="location">{`${location.pathname}${location.search}`}</span>;
}

function renderAddFeed(entry = '/ingestion/log-sources/wizard', basename?: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter basename={basename} initialEntries={[basename ? `${basename}${entry}` : entry]}>
        <AddFeed />
        <LocationProbe />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const wizardLocation = () => screen.getByTestId('location').textContent ?? '';

beforeEach(() => {
  mocks.mode = 'enterprise_shared';
  mocks.assignIngestSource.mockReset().mockResolvedValue({ credential_id: 'credential-existing', source_slug: 'okta', label: 'Converted' });
  mocks.schema = 'ocsf';
  mocks.melod = false; resetEditableArtifact(); resetPivtDraftStore(); resetEditSessions(); resetRunActions();
  mocks.getLogSource.mockReset().mockResolvedValue({id:'feed_existing',name:'Vercel',match_values:['vercel'],parser_vrl:'.src_ip = string!(.src_ip)',vendor:'Vercel',ingest:{events_last_24h:1284}});
  mocks.search.mockReset().mockResolvedValue({results:[{raw_data:'{"message":"request"}'}],total:1284});
  mocks.melodEditParser.mockReset().mockImplementation(async(input)=>({updated_vrl:input.current_vrl.replace('string!(.src_ip)','string(.src_ip) ?? ""'),message:'Included your manual edits.'}));
  mocks.requestIngestCredential.mockReset().mockRejectedValue(new Error('Stop after recording the request'));
  mocks.getIngestEndpoint.mockReset().mockResolvedValue(endpoint);
  mocks.listLogSources.mockReset().mockResolvedValue([
    { id: 'feed_pa', name: 'Palo Alto traffic', match_values: ['palo_alto_traffic'], deployed: true, enabled: true, lifecycle_status: 'active' },
  ]);
  mocks.listParserRollouts.mockReset().mockResolvedValue([]);
  mocks.getParserRollout.mockReset();
  mocks.validateLogSourceVrl.mockReset().mockResolvedValue({ valid: true, errors: [], diagnostics: [] });
  mocks.testLogSourceVrl.mockReset().mockResolvedValue({ success: true, output: {} });
  mocks.importParser.mockReset().mockResolvedValue({log_source_id:'lsrc_repo',import_type:'linked'});
  mocks.createLogSource.mockReset().mockResolvedValue({ id: 'lsrc_vercel' });
  mocks.updateLogSource.mockReset().mockResolvedValue({ id: 'lsrc_vercel' });
  mocks.deployLogSource.mockReset().mockResolvedValue({ success: true, message: 'ok', rollout: null });
  mocks.listSourceConfigs.mockReset().mockResolvedValue([
    { id: 'sc_http', name: 'HTTP ingest', config_type: 'http', connection_config: {}, enabled: true },
  ]);
});
afterEach(cleanup);
beforeEach(() => {
  window.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
  Element.prototype.scrollIntoView = vi.fn();
});
async function continueTransport() {
  fireEvent.click(screen.getByRole('button', { name: /continue · details/i }));
  await screen.findByTestId('source-details');
  fireEvent.click(screen.getByRole('button', { name: /continue · transport/i }));
  await screen.findByRole('radio', { name: 'HTTPS JSON' });
}
async function continueConnect() {
  fireEvent.click(screen.getByRole('button', { name: /continue · connect/i }));
  return screen.findByTestId('issue-credential-panel');
}
async function customToParse(name='vercel') {
  await screen.findByTestId('source-catalog');
  fireEvent.change(screen.getByLabelText('Source name'), {target:{value:name}});
  await continueTransport(); await continueConnect();
  fireEvent.click(screen.getByRole('button',{name:/continue · sample & parse/i}));
}
async function openReview() {
  fireEvent.click(screen.getByRole('button',{name:/continue · review/i}));
  return screen.findByTestId('deploy-gate');
}


describe('AddFeed → Add data (NAN-2593)', () => {
  it('uses one catalog list with Custom visible, without system sources, endpoints or tabs in step 1', async () => {
    renderAddFeed(); await screen.findByRole('option',{name:/okta/});
    expect(screen.getByText('Add source')).toBeTruthy();
    expect(screen.getByText('Source')).toBeTruthy();
    expect(screen.getByRole('option',{name:/Custom source/})).toBeTruthy();
    for(const name of ['unknown','default','otlp_log','otlp_metric','otlp_trace']) expect(screen.queryByRole('option',{name:new RegExp(name)})).toBeNull();
    fireEvent.change(screen.getByLabelText('Search supported sources'),{target:{value:'no-match'}});
    expect(screen.getByRole('option',{name:/Custom source/})).toBeTruthy();
    expect(screen.queryByTestId('ingest-endpoint-card')).toBeNull();
    expect(screen.queryByRole('tab')).toBeNull(); expect(mocks.listSourceConfigs).not.toHaveBeenCalled();
  });
  it('collapses source into transport and then shows only the selected endpoint in Connect', async () => {
    renderAddFeed(); await screen.findByTestId('source-catalog');
    fireEvent.change(screen.getByLabelText('Source name'),{target:{value:'Vercel'}});
    await continueTransport();
    expect(screen.queryByTestId('source-catalog')).toBeNull();
    expect(screen.getByText('Source: Vercel (custom)')).toBeTruthy();
    expect(screen.queryByRole('radio',{name:'Collector'})).toBeNull();
    expect(screen.getByText('For HEC forwarders and security tools that speak HEC.')).toBeTruthy();
    await continueConnect();
    const card=screen.getByTestId('ingest-endpoint-card');
    expect(card.textContent).toContain(`https://${HOST}/ingest`);
    expect(card.textContent).not.toContain('/services/collector/event'); expect(card.textContent).not.toContain('/v1/logs');
    expect(screen.queryByRole('radiogroup',{name:'Transport'})).toBeNull();
    expect(screen.queryByText('Sample & parse')).toBeNull();
    expect(screen.queryByRole('tab')).toBeNull();
    fireEvent.click(screen.getByRole('button',{name:/continue · sample & parse/i}));
    expect(screen.getByRole('button',{name:'Connect · Edit'}).textContent).toContain('Connect: HTTPS JSON · waiting for first event');
  });
  it('repository Details are prefilled and editable, then summarized; repositories finish at Connect', async () => {
    renderAddFeed('/ingestion/log-sources/new?type=okta');
    await waitFor(()=>expect((screen.getByLabelText('Source name') as HTMLInputElement).value).toBe('okta'));
    fireEvent.click(screen.getByRole('button',{name:/continue · details/i}));
    expect((screen.getByLabelText('Feed identifier') as HTMLInputElement).value).toBe('okta');
    expect((screen.getByLabelText('Vendor') as HTMLInputElement).value).toBe('Okta');
    expect((screen.getByLabelText('Product') as HTMLInputElement).value).toBe('System log');
    fireEvent.change(screen.getByLabelText('Vendor'),{target:{value:'My vendor'}});
    expect(screen.queryByText('Network namespace')).toBeNull();
    fireEvent.click(screen.getByRole('button',{name:/continue · transport/i}));
    expect(screen.getByRole('button',{name:'Details · Edit'}).textContent).toContain('Details: okta · My vendor · System log · identity');
    await continueConnect();
    expect(mocks.importParser).toHaveBeenCalledWith('repo','okta.yaml',{import_type:'linked',source_type:'okta',ingestion_method:'routed'});
    expect(mocks.updateLogSource).toHaveBeenCalledWith('lsrc_repo',expect.objectContaining({vendor:'My vendor',match_values:['okta']}));
    expect(mocks.deployLogSource).toHaveBeenCalledWith('lsrc_repo');
    expect(mocks.createLogSource).not.toHaveBeenCalled();
    expect(screen.queryByRole('button',{name:/continue · sample & parse/i})).toBeNull();
  });
  it('Details keeps the mono identifier outside collapsed Advanced configuration and supports editing reserved names',async()=>{
    renderAddFeed();await screen.findByTestId('source-catalog');
    fireEvent.change(screen.getByLabelText('Source name'),{target:{value:'Vercel audit'}});
    fireEvent.click(screen.getByRole('button',{name:/continue · details/i}));
    expect(screen.getByTestId('feed-identifier').className).toContain('font-mono');
    expect((screen.getByLabelText('Vendor') as HTMLInputElement).value).toBe('Vercel');
    expect(screen.queryByRole('button',{name:'Edit feed identifier'})).toBeNull();
    expect(screen.getByText('metadata.log_source =')).toBeTruthy();
    const details = within(screen.getByTestId('source-details'));
    for (const label of ['Credential','Transport route','Search query']) expect(details.queryByText(label)).toBeNull();
    expect(details.getByText('Find these events with')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Feed identifier'),{target:{value:'unknown'}});
    expect((screen.getByLabelText('Feed identifier') as HTMLInputElement).value).toBe('custom_unknown');
    expect(screen.queryByText('Network namespace')).toBeNull();
  });
  it.each(['custom','okta'])('the %s identifier follows source-name edits until the identifier is manually edited',async(type)=>{
    renderAddFeed(type === 'custom' ? '/ingestion/log-sources/new' : '/ingestion/log-sources/new?type=okta');
    await screen.findByTestId('source-catalog');
    if(type==='okta')await waitFor(()=>expect((screen.getByLabelText('Source name') as HTMLInputElement).value).toBe('okta'));
    fireEvent.change(screen.getByLabelText('Source name'),{target:{value:'Jamez'}});
    fireEvent.click(screen.getByRole('button',{name:/continue · details/i}));
    expect((screen.getByLabelText('Feed identifier') as HTMLInputElement).value).toBe('jamez');
    fireEvent.click(screen.getByRole('button',{name:'Source · Edit'}));
    fireEvent.change(screen.getByLabelText('Source name'),{target:{value:'Jamez audit'}});
    fireEvent.click(screen.getByRole('button',{name:/continue · details/i}));
    expect((screen.getByLabelText('Feed identifier') as HTMLInputElement).value).toBe('jamez_audit');
    fireEvent.change(screen.getByLabelText('Feed identifier'),{target:{value:'Keep this ID'}});
    fireEvent.click(screen.getByRole('button',{name:'Source · Edit'}));
    fireEvent.change(screen.getByLabelText('Source name'),{target:{value:'Another name'}});
    fireEvent.click(screen.getByRole('button',{name:/continue · details/i}));
    expect((screen.getByLabelText('Feed identifier') as HTMLInputElement).value).toBe('keep_this_id');
    expect(screen.getByText('metadata.log_source=keep_this_id')).toBeTruthy();
    fireEvent.click(screen.getByRole('button',{name:'Copy search query'}));
    await waitFor(()=>expect(copyText).toHaveBeenLastCalledWith('metadata.log_source=keep_this_id'));
  });
  it('uses the legacy search-field prefix only for legacy tenants',async()=>{
    mocks.schema='udm';renderAddFeed();await screen.findByTestId('source-catalog');
    fireEvent.change(screen.getByLabelText('Source name'),{target:{value:'Jamez'}});
    fireEvent.click(screen.getByRole('button',{name:/continue · details/i}));
    expect(screen.getByText('source_type =')).toBeTruthy();
    expect(screen.getByText('source_type=jamez')).toBeTruthy();
    fireEvent.click(screen.getByRole('button',{name:'Copy search query'}));
    await waitFor(()=>expect(copyText).toHaveBeenLastCalledWith('source_type=jamez'));
    expect(screen.queryByText('metadata.log_source =')).toBeNull();
  });
  it('groups existing sources and repository entries and navigates to existing source credentials without creating a duplicate',async()=>{
    renderAddFeed();await screen.findByRole('option',{name:/okta/});
    expect(screen.getByText('Your sources')).toBeTruthy();expect(screen.getByText('From repositories')).toBeTruthy();expect(screen.getByText('nano-rs/parsers')).toBeTruthy();
    fireEvent.click(screen.getByRole('option',{name:/Palo Alto traffic/}));
    expect(wizardLocation()).toContain('/ingestion/log-sources/feed_pa?action=add-credential');
    expect(mocks.createLogSource).not.toHaveBeenCalled();
  });
  it('shows Installed for active repository types and searches by repository name',async()=>{
    mocks.listLogSources.mockResolvedValue([{id:'okta_active',name:'Okta installed',match_values:['okta'],deployed:true,source_parser_linked:true}]);
    renderAddFeed();await screen.findByRole('option',{name:/okta Installed/});
    expect(screen.getByText('acme/security-parsers')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Search supported sources'),{target:{value:'acme/security-parsers'}});
    await waitFor(()=>expect(screen.queryByRole('option',{name:/okta Installed/})).toBeNull());
    expect(screen.getByRole('option',{name:'Internal SSO'})).toBeTruthy();
    expect(screen.getByRole('option',{name:/Custom source/})).toBeTruthy();
  });
  it('an unknown source deep link never falls back to another source', async () => {
    renderAddFeed(addDataLink('not_enrolled_anywhere'));
    await screen.findByTestId('source-catalog');
    expect(screen.queryByTestId('issue-credential-panel')).toBeNull();
  });

  it('NAN-4792: the real sample splitter sends 16 lines until Join is clicked, then sends 8', async () => {
    const heads = Array.from({ length: 8 }, (_, i) => `<134>Oct 28 14:02:1${i} fw01 action=allow seq=${i}`);
    const tail = 'bytes_out=1832 bytes_in=48211 user=alice';
    const wrapped = heads.map((head) => `${head}\n  ${tail}`).join('\n');
    const clean = heads.map((head) => `${head} ${tail}`).join('\n');
    renderAddFeed();
    await customToParse('firewall');
    const box = screen.getByPlaceholderText(/^\{"timestamp":/) as HTMLTextAreaElement;
    fireEvent.change(box, { target: { value: wrapped } });
    fireEvent.change(await screen.findByLabelText('VRL'), { target: { value: '.action = "allow"' } });
    expect(screen.getByTestId('sample-split').textContent).toBe('16 sample lines · one event per line');
    expect(screen.getByRole('status').textContent).toContain('8 of 16 lines');
    await waitFor(() => expect(mocks.testLogSourceVrl).toHaveBeenCalledTimes(16));
    expect(box.value).toBe(wrapped);
    expect(mocks.testLogSourceVrl.mock.calls.map((call) => call[1])).toEqual(wrapped.split('\n'));

    mocks.testLogSourceVrl.mockClear();
    fireEvent.click(screen.getByRole('button', { name: 'Join wrapped lines' }));
    expect(box.value).toBe(clean);
    expect(screen.getByTestId('sample-split').textContent).toBe('8 sample lines · one event per line');
    expect(screen.queryByRole('button', { name: 'Join wrapped lines' })).toBeNull();
    await waitFor(() => expect(mocks.testLogSourceVrl).toHaveBeenCalledTimes(8));
    expect(mocks.testLogSourceVrl.mock.calls.map((call) => call[1])).toEqual(clean.split('\n'));
  });

  it('a custom source with an empty parser is blocked on the parser, not on a phantom acknowledgement (NAN-4754)', async () => {
    renderAddFeed();
    await customToParse(); await openReview();
    const gate = await screen.findByTestId('deploy-gate');
    expect(within(gate).getByTestId('gate-parser').getAttribute('data-status')).toBe('block');
    expect(gate.textContent).toContain('Parser · empty · draft or write one in step 5');
    expect(gate.textContent).not.toContain('VRL syntax · valid');
    expect(gate.textContent).not.toMatch(/acknowledge/i);
    expect(within(gate).queryByRole('checkbox')).toBeNull();
    expect((screen.getByRole('button', { name: /activate source/i }) as HTMLButtonElement).disabled).toBe(true);
  });

  // NAN-4754, the AU report: a hosted custom source with a real parser and no
  // samples yet must reach activation through one explicit acknowledgement.
  async function customSourceWithParser(vrl = '. = parse_json!(.message)') {
    renderAddFeed();
    await customToParse();
    fireEvent.change(await screen.findByLabelText('VRL'), { target: { value: vrl } });
    await openReview();
    const gate = await screen.findByTestId('deploy-gate');
    await waitFor(() => expect(within(gate).getByTestId('gate-parser').getAttribute('data-status')).toBe('ok'));
    return gate;
  }

  it('a hosted custom source with no samples activates after the acknowledgement (NAN-4754)', async () => {
    const gate = await customSourceWithParser();
    expect(within(gate).getByTestId('gate-tests').getAttribute('data-status')).toBe('warn');
    const activate = screen.getByRole('button', { name: /activate source/i }) as HTMLButtonElement;
    await waitFor(() => expect(within(gate).getByTestId('gate-namespace').getAttribute('data-status')).toBe('ok'));
    expect(activate.disabled).toBe(true);
    fireEvent.click(within(gate).getByRole('checkbox'));
    await waitFor(() => expect(activate.disabled).toBe(false));
    fireEvent.click(activate);
    await waitFor(() => expect(mocks.deployLogSource).toHaveBeenCalledWith('lsrc_vercel', [], []));
    expect(await screen.findByTestId('issue-credential-panel')).toBeTruthy();
  });

  it('the acknowledgement resets when the warnings change (NAN-4754)', async () => {
    mocks.validateLogSourceVrl.mockResolvedValue({
      valid: true, errors: [], diagnostics: [{ severity: 'warn', message: 'unused variable a' }],
    });
    const gate = await customSourceWithParser();
    await waitFor(() => expect(gate.textContent).toContain('unused variable a'));
    fireEvent.click(within(gate).getByRole('checkbox'));
    await waitFor(() => expect(within(gate).getByRole('checkbox').getAttribute('aria-checked')).toBe('true'));
    mocks.validateLogSourceVrl.mockResolvedValue({
      valid: true, errors: [], diagnostics: [{ severity: 'warn', message: 'unused variable b' }],
    });
    fireEvent.click(screen.getByRole('button', { name: 'Sample & parse · Edit' }));
    fireEvent.change(await screen.findByLabelText('VRL'), { target: { value: '. = parse_json!(.message)\nb = 1' } });
    await openReview();
    await waitFor(() => expect(screen.getByTestId('deploy-gate').textContent).toContain('unused variable b'), { timeout: 3000 });
    await waitFor(() => expect(within(screen.getByTestId('deploy-gate')).getByRole('checkbox').getAttribute('aria-checked')).toBe('false'));
  });

  it('a server preflight refusal is not announced as activated (NAN-4754)', async () => {
    mocks.deployLogSource.mockResolvedValue({ success: false, message: "'vercel' was not deployed: Sample 1 of 1 failed", rollout: null });
    const gate = await customSourceWithParser();
    await waitFor(() => expect(within(gate).getByTestId('gate-namespace').getAttribute('data-status')).toBe('ok'));
    fireEvent.click(within(gate).getByRole('checkbox'));
    const activate = screen.getByRole('button', { name: /activate source/i }) as HTMLButtonElement;
    await waitFor(() => expect(activate.disabled).toBe(false));
    fireEvent.click(activate);
    await waitFor(() => expect(mocks.deployLogSource).toHaveBeenCalled());
    await waitFor(() => expect(activate.disabled).toBe(false));
    expect(screen.getByTestId('issue-credential-panel').closest('[hidden]')).toBeTruthy();
  });

  it('offers Collector only when enabled, retaining its multi-source allowlist', async () => {
    mocks.getIngestEndpoint.mockResolvedValue({...endpoint,ingress_contract:{collector_credentials:true}});
    renderAddFeed(); await screen.findByTestId('source-catalog');
    fireEvent.change(screen.getByLabelText('Source name'),{target:{value:'Pipeline'}});
    await continueTransport(); fireEvent.click(screen.getByRole('radio',{name:'Collector'}));
    fireEvent.click(screen.getByRole('checkbox',{name:'Palo Alto traffic'}));
    fireEvent.click(screen.getByRole('checkbox',{name:'okta'}));
    const panel=await continueConnect();
    expect(within(panel).getByTestId('collector-source-palo_alto_traffic').textContent).toContain('pan:traffic');
    expect(within(panel).getByTestId('collector-source-okta').textContent).toContain('OktaIM2:log');
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
    renderAddFeed('/ingestion/log-sources/new?source=acme_app&stage=connect');
    const strip = await screen.findByTestId('issue-rollout');
    expect(within(strip).getByTestId('rollout-state').textContent).toBe('Building');
    const panel = await screen.findByTestId('issue-credential-panel');
    expect(panel.textContent).toContain('being connected to your ingest endpoint');
  });

  // NAN-4800, the AU report: after issuing at Step 2 the user clicked "Log
  // Sources → Credentials", a raw <a> that left /t/<tenant> (tenant_required →
  // login), and then had to rebuild the source from Step 1.
  describe('NAN-4800: tenant links and resuming the Issue step', () => {
    const BASE='/t/acme';
    it('keeps the tenant prefix on credential-management links',async()=>{
      renderAddFeed('/ingestion/log-sources/new?source=palo_alto_traffic&stage=connect&transport=hec',BASE);
      await screen.findByTestId('issue-credential-panel');
      const link=screen.getByRole('link',{name:'Log Sources → Credentials'});
      expect(link.getAttribute('href')).toBe('/t/acme/ingestion/log-sources/credentials'); expect(link.getAttribute('target')).toBe('_blank');
    });
    it.each([['palo_alto_traffic','feed_pa'],['okta',undefined]])('resumes %s with the same source and own registry id',async(slug,id)=>{
      renderAddFeed(`/ingestion/log-sources/new?source=${slug}&stage=connect&transport=hec`,BASE);
      const panel=await screen.findByTestId('issue-credential-panel');
      fireEvent.click(within(panel).getByRole('button',{name:'Issue credential'}));
      await waitFor(()=>expect(mocks.requestIngestCredential).toHaveBeenCalledTimes(1));
      const input=mocks.requestIngestCredential.mock.calls[0][0];
      expect(input.source_slugs).toEqual([slug]);expect(input.log_source_id).toBe(id);expect(input.protocol).toBe('hec');expect(input.reveal_public_key).toBeTruthy();
      expect(screen.queryByLabelText('VRL')).toBeNull();expect(mocks.deployLogSource).not.toHaveBeenCalled();
    });
    it('keeps the selected transport in the address for reload',async()=>{
      renderAddFeed('/ingestion/log-sources/new?source=okta');
      await screen.findByRole('radio',{name:'HEC'}); fireEvent.click(screen.getByRole('radio',{name:'HEC'}));
      await continueConnect();
      await waitFor(()=>expect(wizardLocation()).toContain('transport=hec'));
      expect(wizardLocation()).toContain('source=okta');expect(wizardLocation()).toContain('stage=connect');
    });
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

it('NAN-4847: unknown is never a pickable source; custom creation is inline', async () => {
  mocks.getIngestEndpoint.mockResolvedValue({ ...endpoint, sources: [...endpoint.sources,
    { ...endpoint.sources[0], source_slug: 'unknown', label: 'route template: unknown' }] });
  renderAddFeed();
  await screen.findByRole('option', { name: /okta/ });
  expect(screen.queryByRole('option', { name: 'unknown' })).toBeNull();
  fireEvent.click(screen.getByRole('option', { name: /Custom source/ }));
  expect(screen.getByLabelText('Source name')).toBeTruthy();
  expect(screen.queryByRole('tab')).toBeNull();
});


describe('NAN-4847 live parser page context',()=>{
  async function openExistingParser(){
    mocks.melod=true;renderAddFeed('/ingestion/log-sources/new?source_id=feed_existing&stage=parse');
    await screen.findByLabelText('VRL');
    await waitFor(()=>expect(getEditableArtifact()?.kind).toBe('parser'));
    await waitFor(()=>expect((getEditableArtifact()?.getDoc() as {samples:string[]}).samples.length).toBe(1));
  }
  it('Build parser reuses the receiving source and includes manual edits on every turn, without auto-apply; Apply and one Undo retest',async()=>{
    await openExistingParser();
    expect(screen.getByRole('button',{name:'Connect · Edit'}).textContent).toContain('Connect: HTTPS JSON · receiving');
    const manual='.src_ip = string!(.src_ip)\n# keep my manual edit';
    fireEvent.change(screen.getByLabelText('VRL'),{target:{value:manual}});
    await act(()=>startEditTurn('Fix the missing src_ip'));
    expect(mocks.melodEditParser.mock.calls[0][0].current_vrl).toBe(manual);
    const message=mocks.melodEditParser.mock.calls[0][0].message;
    expect(message).toContain('manual_diff');expect(message).toContain('keep my manual edit');expect(message).toContain('feed_existing');
    expect((screen.getByLabelText('VRL') as HTMLTextAreaElement).value).toBe(manual);
    expect(mocks.createLogSource).not.toHaveBeenCalled();
    const run=getPivtDraftRuns().at(-1)!;
    expect(run.cards?.[0].actions.map(action=>action.label)).toEqual(['Apply','Dismiss']);
    // A disjoint manual edit after the proposal is kept when its patch is applied.
    fireEvent.change(screen.getByLabelText('VRL'),{target:{value:manual+'\n.extra = true'}});
    await act(()=>runCardAction(run.id,'parser-patch','apply'));
    expect((screen.getByLabelText('VRL') as HTMLTextAreaElement).value).toContain('string(.src_ip) ?? ""');
    expect((screen.getByLabelText('VRL') as HTMLTextAreaElement).value).toContain('.extra = true');
    await waitFor(()=>expect(mocks.testLogSourceVrl).toHaveBeenCalled());
    act(()=>getEditableArtifact()!.history.undo());
    expect((screen.getByLabelText('VRL') as HTMLTextAreaElement).value).toBe(manual+'\n.extra = true');
    expect(getEditableArtifact()!.history.depth()).toBe(0);
  });
  it('get_more_samples appends recent events, including samples edited while the search was in flight',async()=>{
    await openExistingParser();let resolve!:(value:unknown)=>void;
    mocks.search.mockImplementationOnce(()=>new Promise(r=>{resolve=r;}));
    const before=getEditableArtifact()!.getDoc() as {samples:string[]};
    const pending=getEditableArtifact()!.invoke!('get_more_samples',{n:20},new AbortController().signal);
    const box=screen.getByPlaceholderText(/^\{"timestamp":/);
    fireEvent.change(box,{target:{value:[...before.samples,'{"message":"manually added"}'].join('\n')}});
    await act(async()=>{resolve({results:Array.from({length:20},(_,i)=>({raw_data:JSON.stringify({message:'recent',i})}))});await pending;});
    expect((getEditableArtifact()!.getDoc() as {samples:string[]}).samples).toHaveLength(22);
    expect(mocks.search.mock.calls.at(-1)![0].limit).toBe(20);
    await act(()=>startEditTurn('run tests on the current parser and samples'));
    expect(getPivtDraftRuns().at(-1)?.cards?.[0].title).toBe('Ran tests');
  });
  it('reads resumed source activity from the list API when the detail row has no ingest counters', async () => {
    const source = { id: 'feed_existing', name: 'Vercel', match_values: ['vercel'], parser_vrl: '.',
      deployed: false, lifecycle_status: 'draft' };
    mocks.getLogSource.mockResolvedValueOnce(source);
    mocks.listLogSources.mockResolvedValueOnce([{ ...source, ingest: { source_slugs: ['vercel'], events_last_24h: 12 } }]);
    await openExistingParser();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Connect · Edit' }).textContent).toContain('receiving'));
    expect((getEditableArtifact()!.getDoc() as { recent_raw_event_count: number }).recent_raw_event_count).toBe(12);
  });
  it('loads and appends the original generic-lane payload with a bounded full-event search',async()=>{
    const original='{"deployment":"web-24","status":200}';
    const retained={raw_data:JSON.stringify({message:original,metadata:{parser_type:'generic'}})};
    mocks.search.mockResolvedValue({results:[retained]});
    await openExistingParser();
    expect((getEditableArtifact()!.getDoc() as {samples:string[]}).samples).toEqual([original]);
    const first=mocks.search.mock.calls[0][0];
    expect(first).toMatchObject({query:'metadata.log_source="vercel"',limit:10,table_view:false,skip_field_stats:true,skip_histogram:true});
    expect(new Date(first.time_range.end).getTime()-new Date(first.time_range.start).getTime()).toBe(24*60*60*1000);
    await act(()=>getEditableArtifact()!.invoke!('get_more_samples',{n:500},new AbortController().signal));
    expect(mocks.search.mock.calls.at(-1)![0].limit).toBe(200);
    expect((getEditableArtifact()!.getDoc() as {samples:string[]}).samples).toEqual([original,original]);
  });
  it('natural requests can test the last 50 raw events and fetch a different event type through page actions',async()=>{
    await openExistingParser();
    mocks.search.mockResolvedValueOnce({results:Array.from({length:50},(_,i)=>({raw_data:JSON.stringify({event_type:'request',i})}))});
    await act(()=>startEditTurn('test with the last 50 events'));
    expect(mocks.search.mock.calls.at(-1)![0].limit).toBe(50);
    expect((getEditableArtifact()!.getDoc() as {samples:string[]}).samples).toHaveLength(51);
    expect(getPivtDraftRuns().at(-1)?.cards?.map(card=>card.title)).toEqual(['Pulled 50 samples','Ran tests']);
    expect(mocks.testLogSourceVrl.mock.calls.some(call=>call[1].includes('\"i\":49'))).toBe(true);
    mocks.search.mockResolvedValueOnce({results:[{raw_data:'{"event_type":"request"}'},{raw_data:'{"event_type":"audit"}'}]});
    await act(()=>startEditTurn('pull samples with a different event type'));
    expect((getEditableArtifact()!.getDoc() as {samples:string[]}).samples).toHaveLength(52);
    expect(mocks.melodEditParser).not.toHaveBeenCalled();
  });
  it('overlapping patches are rejected and disjoint patches rebase without losing manual changes',()=>{
    expect(rebaseVrlPatch('a\nb\nc','a\nb\nc\nmanual','fixed\nb\nc')).toBe('fixed\nb\nc\nmanual');
    expect(()=>rebaseVrlPatch('a\nb','manual\nb','fixed\nb')).toThrow(/changed after the proposal/);
  });
});

it('NAN-4847: resumed conversion assigns the original credential without issuing a token', async () => {
  renderAddFeed('/ingestion/log-sources/wizard?convert=credential-existing&source=okta');
  await screen.findByRole('button', { name: 'Assign source' });
  fireEvent.change(screen.getByLabelText('Credential name'), { target: { value: 'Converted' } });
  fireEvent.click(screen.getByRole('button', { name: 'Assign source' }));
  await waitFor(() => expect(mocks.assignIngestSource).toHaveBeenCalledWith('credential-existing', 'okta', 'Converted'));
  expect(mocks.requestIngestCredential).not.toHaveBeenCalled();
  await waitFor(() => expect((screen.getByRole('button', { name: 'Finish' }) as HTMLButtonElement).disabled).toBe(false));
  expect(wizardLocation()).toContain('convert=credential-existing');
});
