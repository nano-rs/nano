// SPDX-License-Identifier: AGPL-3.0-or-later
import { test, afterEach, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { context, moduleMocks } from '../test/marketplace-dom';
import type { InventoryItem, MarketplaceEntitlement } from '../lib/api/marketplace-inventory';
import type { MarketplaceCatalogEntry } from '../lib/api/marketplace';
import type { HostedCollector } from '@/enterprise/api/hosted-collectors';
const { render, cleanup, waitFor, fireEvent, within } = await import('@testing-library/react');
const { MemoryRouter } = await import('react-router-dom');
const { QueryClient, QueryClientProvider } = await import('@tanstack/react-query');
const { BreadcrumbProvider } = await import('../contexts/BreadcrumbContext');
const { api, ApiClientError } = await import('../lib/api');
// Keep the actual InventoryEditor and drawers; replace only heavyweight child editors.
moduleMocks['/enterprise/pages/CustomEnrichmentWizard.tsx'] = { CustomEnrichmentWizard: ({ definitionId }: { definitionId: string }) => <p>Embedded provider {definitionId}</p> };
const { Marketplace } = await import('./Marketplace');
const { MarketplaceApi } = await import('../lib/api/marketplace');
const { inventoryRouteId } = await import('../lib/api/marketplace-inventory');
const { SECTIONS } = await import('../components/marketplace/MarketplaceShell');
const clients: InstanceType<typeof QueryClient>[] = [];
afterEach(() => { cleanup(); clients.splice(0).forEach(client => client.clear()); });
const catalog = ['abuseipdb', 'threatfox', 'ipinfo-lite', 'fixture-other'].map(slug => ({
  id: slug, slug, name: slug, description: 'Fixed catalog fixture', category: 'data', tags: ['ip'],
  installed: false, enabled: false, manifest_version: 1, requires_credential: 'none', credential_fields: [],
  source_type: 'system', execution_backend: 'native', author: 'nano', record_count: 0,
} as unknown as MarketplaceCatalogEntry));
function mount(path = '/marketplace') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false, gcTime: 0 } } });
  clients.push(client);
  return { client, ...render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><BreadcrumbProvider><Marketplace /></BreadcrumbProvider></MemoryRouter></QueryClientProvider>) };
}
// Captured from unmodified HEAD 420d5956ec3a84e25b6fca8d9c9053ad82dcb40a before shell extraction.
// This fixture is immutable: fix the rendered DOM if the comparison fails.
test('dedicated rendered DOM matches the pre-refactor HEAD snapshot', async () => {
  context.mode = 'dedicated';
  let calls = 0;
  api.getSystemConfig = async () => ({ air_gap: false }) as Awaited<ReturnType<typeof api.getSystemConfig>>;
  api.marketplace.listRepos = async () => [];
  api.marketplace.listCatalog = async () => { calls++; return { total: 4, entries: catalog, stats: { total_entries: 4, installed_count: 0, data_count: 4, agent_count: 0, identity_count: 0, collector_count: 0 } }; };
  const view = mount();
  await waitFor(() => assert.equal(view.container.querySelectorAll('[data-mp-card]').length, 4));
  assert.ok(calls > 0);
  assert.ok(view.getByText('Popular integrations'));
  const snapshot = new URL('./__snapshots__/Marketplace.dedicated.html', import.meta.url);
  assert.equal(view.container.innerHTML, readFileSync(snapshot, 'utf8'));
});

const common = { enabled: true, revision: 1, effective_health: 'ready', last_sync: null, next_refresh: null, reason: null, execution_stage: 'bronze_ingest', capabilities: ['ip'], can_toggle: false, can_edit: false, grant_revision: 1, feed_revision: 3 };
const items: InventoryItem[] = [
  { ...common, id: 'ipinfo_lite', name: 'IPinfo Lite', kind: 'baseline' },
  { ...common, id: 'threatfox', name: 'ThreatFox', kind: 'baseline' },
  { ...common, id: 'tor_exit_nodes', name: 'Tor exit nodes', kind: 'baseline' },
  { ...common, id: 'synthient', name: 'Synthient', kind: 'premium', entitled: false, enabled: false, can_toggle: false },
  ...['custom:fixture', 'connector:fixture', 'abuseipdb'].map(id => ({ ...common, id, name: id, kind: 'custom' as const, author: 'author', tenant_id: 'tenant', connector: 'fixture-connector', repo_commit: null, repository_id: null, artifact_id: null, artifact_sha256: null, can_edit: true, can_toggle: true })),
];
let fixtureItems = items;
let fixtureCollectors: HostedCollector[] = [];
let fixtureFeeds: Record<string, unknown[]> = {};
let airGap = false;
let urls: string[] = [];
let catalogCalls = 0;
let connectorSchemaRequest: string | undefined;
let purchaseCalls: (string | undefined)[] = [];
let entitlementCalls = 0;
let purchase: MarketplaceEntitlement = { feed_id: 'synthient', tier: 'sandbox', grant_revision: 1, revision: 1, state: 'pending', enabled: false, expires_at: null };
beforeEach(() => {
  context.mode = 'enterprise_shared'; context.coverage = false; context.permissions = true;
  fixtureItems = items; airGap = false; urls = []; catalogCalls = 0; connectorSchemaRequest = undefined; purchaseCalls = []; entitlementCalls = 0;
  fixtureCollectors = []; fixtureFeeds = {};
  purchase = { ...purchase, state: 'pending', revision: 1 };
  globalThis.fetch = async input => { urls.push(String(input)); throw new Error(`Unexpected fetch: ${input}`); };
  api.getSystemConfig = async () => ({ air_gap: airGap }) as Awaited<ReturnType<typeof api.getSystemConfig>>;
  // Exercise the real inventory endpoint builder, recording every item request.
  const inventoryApi = new MarketplaceApi(async <T,>(endpoint: string) => {
    urls.push(endpoint);
    if (endpoint === '/api/marketplace/items') return fixtureItems as T;
    if (endpoint === '/api/marketplace/collectors') return fixtureCollectors as T;
    if (endpoint.startsWith('/api/marketplace/collectors/')) return (fixtureFeeds[decodeURIComponent(endpoint.split('/').at(-1)!)] ?? []) as T;
    const id = decodeURIComponent(endpoint.split('/').at(-1)!);
    const item = fixtureItems.find(item => item.id === id);
    if (!item) throw new ApiClientError('Unavailable', 'not_found', undefined, 404);
    return item as T;
  });
  api.marketplace.listInventory = inventoryApi.listInventory.bind(inventoryApi);
  api.marketplace.inventoryDetail = inventoryApi.inventoryDetail.bind(inventoryApi);
  api.marketplace.hostedCollectors = inventoryApi.hostedCollectors.bind(inventoryApi);
  api.marketplace.hostedCollectorFeeds = inventoryApi.hostedCollectorFeeds.bind(inventoryApi);
  api.marketplace.listCatalog = async () => { catalogCalls++; throw new Error('Hosted must not list catalog'); };
  api.marketplace.listRepos = async () => [];
  api.marketplace.checkout = async (_id, origin) => { purchaseCalls.push(origin); return { redirect_url: 'http://localhost/', intent: { purchase_key: 'fixture', sku: 'synthient', origin: 'later', created_at: '2026-01-01' } }; };
  api.marketplace.inventoryEntitlement = async () => { entitlementCalls++; return { ...purchase }; };
  // NAN-3596: tenants are not admitted to cloud pull unless a test says so.
  api.pullSources.list = async () => { throw new ApiClientError('not enabled', 'pull_sources_not_enabled', undefined, 409); };
});
afterEach(() => {
  if (context.mode === 'enterprise_shared') {
    assert.equal(catalogCalls, 0, 'No hosted path may call listCatalog');
    // Connector configuration is tested separately: its native drawer retrieves
    // only the selected connector schema, never the marketplace item list.
    assert.deepEqual(urls.filter(url => url.includes('/api/marketplace/catalog')), connectorSchemaRequest ? [connectorSchemaRequest] : []);
  }
});

test('hosted cloud pull card shows only for admitted tenants and counts under Pull', async () => {
  const view = mount();
  await view.findByText('Other integrations');
  assert.equal(view.container.querySelector('[data-mp-slug="cloud-pull:aws"]'), null);
  assert.equal(view.queryByRole('button', { name: /^Pull\s*\d+$/ }), null);
  cleanup();
  api.pullSources.list = async () => [];
  const admitted = mount();
  await waitFor(() => assert.ok(admitted.container.querySelector('[data-mp-slug="cloud-pull:aws"]')));
  const card = admitted.container.querySelector('[data-mp-slug="cloud-pull:aws"]')!;
  assert.ok(card.closest('section')!.textContent!.includes('Cloud infrastructure'));
  assert.ok(within(card as HTMLElement).getByText('Set up'));
  fireEvent.click(admitted.getByRole('button', { name: /^Pull\s*1$/ }));
  assert.equal(admitted.container.querySelectorAll('[data-mp-card]').length, 1);
  fireEvent.click(admitted.getByRole('button', { name: 'enabled only' }));
  assert.equal(admitted.container.querySelector('[data-mp-slug="cloud-pull:aws"]'), null);
  cleanup();
  // Without a curated cloud item the Cloud infrastructure group still holds the card.
  fixtureItems = items.filter(item => item.id !== 'ipinfo_lite');
  const bare = mount();
  await waitFor(() => assert.ok(bare.container.querySelector('[data-mp-slug="cloud-pull:aws"]')));
  const group = bare.container.querySelector('[data-mp-slug="cloud-pull:aws"]')!.closest('section')!;
  assert.ok(group.textContent!.includes('Cloud infrastructure'));
  assert.equal(group.querySelectorAll('[data-mp-card]').length, 1);
});

test('hosted renders curated sections and custom providers using only inventory', async () => {
  const view = mount();
  for (const title of ['Popular integrations', 'Security tools', 'Cloud infrastructure', 'Custom providers', 'Other integrations']) await view.findByText(title);
  const section = (title: string) => view.getByText(title).closest('section')!;
  assert.ok(within(section('Cloud infrastructure')).getByText('IPinfo Lite'));
  assert.ok(within(section('Security tools')).getByText('ThreatFox'));
  assert.ok(within(section('Security tools')).getByText('Tor exit nodes'));
  assert.equal(view.container.querySelectorAll('[data-mp-slug="ipinfo_lite"]').length, 1);
  assert.equal(section('Custom providers').querySelectorAll('[data-mp-card]').length, 2);
  assert.ok(urls.includes('/api/marketplace/items'));
  for (const label of ['Enabled', 'Platform', 'Premium', 'Custom']) assert.ok(view.getAllByText(label).length);
});

const collectorFixture = (slug: string, name: string, description: string): HostedCollector => ({ slug, name, description, credential_fields: [], config_fields: [],
  streams: [{ id: 'system_log', label: 'System Log', source_type: slug, default: true }] });
const collectorCard = (view: { container: HTMLElement }, slug: string) => view.container.querySelector(`[data-mp-slug="collector:${slug}"]`) as HTMLButtonElement | null;

test('hosted collectors render as standard cards inside the Identity group of the catalog grid', async () => {
  fixtureCollectors = [collectorFixture('okta_system_log', 'Okta System Log', 'Okta audit events'), collectorFixture('google_workspace', 'Google Workspace', 'Workspace reports')];
  const view = mount();
  const heading = await view.findByText('Identity');
  const section = heading.closest('section')!;
  await waitFor(() => assert.equal(collectorCard(view, 'okta_system_log')?.disabled, false));
  assert.equal(section.querySelectorAll('[data-mp-card]').length, 2);
  assert.ok(within(section).getByText('Okta System Log'));
  assert.ok(within(section).getByText('Google Workspace'));
  assert.ok(within(section).getByText('· 2'));
  // Same grid as every other group, no separate full-width section.
  assert.equal(section.querySelector('.grid')!.className, view.getByText('Security tools').closest('section')!.querySelector('.grid')!.className);
  assert.equal(view.queryByText('Pull collectors'), null);
  assert.equal(collectorCard(view, 'okta_system_log')!.querySelector('p.font-mono')!.textContent, 'pull · not installed');
  assert.ok(urls.includes('/api/marketplace/collectors'));
  assert.ok(urls.includes('/api/marketplace/collectors/okta_system_log'));
});

test('Pull tab, All count, search and enabled-only include hosted collectors', async () => {
  fixtureCollectors = [collectorFixture('okta_system_log', 'Okta System Log', 'Okta audit events'), collectorFixture('google_workspace', 'Google Workspace', 'Workspace reports')];
  fixtureFeeds = { google_workspace: [{ id: 'feed', source_slug: 'gws_login', enabled: false, credential: 'ready', rollout_state: 'live', next_run_at: '2026-10-11T12:00:00Z' }] };
  const view = mount();
  await view.findByText('Identity');
  // 7 inventory items + 2 collectors.
  assert.ok(view.getByRole('button', { name: /^All\s*9$/ }));
  fireEvent.click(view.getByRole('button', { name: /^Pull\s*2$/ }));
  await waitFor(() => assert.equal(view.container.querySelectorAll('[data-mp-card]').length, 2));
  assert.ok(collectorCard(view, 'okta_system_log') && collectorCard(view, 'google_workspace'));
  fireEvent.change(view.getByRole('textbox'), { target: { value: 'workspace reports' } });
  assert.equal(view.container.querySelectorAll('[data-mp-card]').length, 1);
  assert.ok(collectorCard(view, 'google_workspace'));
  fireEvent.change(view.getByRole('textbox'), { target: { value: '' } });
  fireEvent.click(view.getByRole('button', { name: 'enabled only' }));
  // Installed (even if paused) counts as enabled.
  await waitFor(() => assert.equal(view.container.querySelectorAll('[data-mp-card]').length, 1));
  assert.ok(collectorCard(view, 'google_workspace')!.textContent!.endsWith('Installed · Off'));
  fireEvent.click(view.getByRole('button', { name: /^Custom\s*3$/ }));
  assert.equal(collectorCard(view, 'google_workspace'), null);
});

test('no Pull tab when the tenant has no hosted collectors', async () => {
  const view = mount();
  await view.findByText('ThreatFox');
  assert.equal(view.queryByRole('button', { name: /^Pull\s*\d+$/ }), null);
  assert.ok(view.getByRole('button', { name: /^All\s*7$/ }));
});

test('every curated slug groups under its canonical inventory id', async () => {
  fixtureItems = [...new Set(SECTIONS.flatMap(section => section.slugs.map(inventoryRouteId)))].map(id => ({ ...common, kind: 'baseline', id, name: id }));
  const view = mount();
  await view.findByText('Cloud infrastructure');
  assert.equal(view.queryByText('Other integrations'), null);
  for (const section of SECTIONS) for (const slug of section.slugs) {
    assert.ok(view.getByText(section.title).closest('section')!.querySelector(`[data-mp-slug="${inventoryRouteId(slug)}"]`));
  }
});

for (const item of items.slice(0, 4)) test(`${item.name} is provided without install/configure/credential controls`, async () => {
  const view = mount(`/?item=${item.id}`);
  const dialog = await view.findByRole('dialog');
  const card = view.container.querySelector(`[data-mp-slug="${item.id}"]`)!;
  for (const element of [card, dialog]) {
    assert.doesNotMatch(element.textContent ?? '', /install|configure|credential/i);
    assert.equal(element.querySelector('input,textarea,select'), null);
  }
  if (item.kind === 'baseline') {
    assert.ok(within(dialog as HTMLElement).getByText('Included · On'));
    assert.equal(within(dialog as HTMLElement).queryByRole('button', { name: /Enable|Disable/ }), null);
  } else assert.ok(within(dialog as HTMLElement).getByRole('button', { name: 'Purchase' }));
});

test('premium checkout, pending polling and revision invalidation remain live', async () => {
  const view = mount('/?item=synthient');
  await view.findByText('Payment pending');
  fireEvent.click(view.getByRole('button', { name: 'Purchase' }));
  await waitFor(() => assert.ok(purchaseCalls.includes('later')));
  const before = urls.filter(url => url === '/api/marketplace/items').length;
  purchase = { ...purchase, revision: 2, state: 'active', enabled: true };
  await view.findByText('Purchased · Enabled', {}, { timeout: 6500 });
  await waitFor(() => assert.ok(urls.filter(url => url === '/api/marketplace/items').length > before));
  assert.ok(entitlementCalls >= 2);
});

for (const [route, definition] of [['/?author=new', 'new'], ['/?item=custom:fixture&author=edit', 'fixture']]) test(`custom editor route ${route}`, async () => {
  const view = mount(route);
  await view.findByText('Marketplace · Custom provider');
  await view.findByText(`Embedded provider ${definition}`);
});

for (const tab of ['connections', 'about']) test(`connector route preserves the native connection drawer and ${tab} tab`, async () => {
  let requested: string | undefined;
  connectorSchemaRequest = '/api/marketplace/catalog/fixture-connector';
  const configurationApi = new MarketplaceApi(async <T,>(endpoint: string) => {
    urls.push(endpoint); requested = decodeURIComponent(endpoint.split('/').at(-1)!);
    return { ...catalog[0], slug: requested, name: 'Fixture connection', installed: true, execution_backend: 'collector', config: {} } as T;
  });
  api.marketplace.getCatalogEntry = configurationApi.getCatalogEntry.bind(configurationApi);
  api.integrations.listInstances = async () => ({ instances: [] });
  const view = mount(`/?item=connector:fixture&author=connect&tab=${tab}`);
  await view.findByText('Fixture connection');
  if (tab === 'connections') await view.findByText('Not connected to a tenant yet.');
  else assert.ok(view.getByRole('button', { name: 'About' }).className.includes('border-primary'));
  assert.equal(requested, 'fixture-connector');
});

test('air gap hides sources, shows import and connectivity, and disables purchase', async () => {
  airGap = true;
  const view = mount('/?item=synthient');
  const importLink = await view.findByRole('link', { name: 'Import enrichment bundle', hidden: true });
  assert.equal(importLink.getAttribute('href'), '/settings/airgap-import');
  assert.ok(view.getByText('Air-gapped install'));
  assert.equal(view.queryByRole('button', { name: /sources/i }), null);
  await view.findByRole('dialog');
  assert.equal((view.getByRole('button', { name: 'Purchase' }) as HTMLButtonElement).disabled, true);
  assert.equal(view.container.querySelectorAll('[data-mp-card]').length, view.getAllByText('Requires connectivity').length);
  fireEvent.click(view.getByRole('button', { name: 'Purchase' }));
  assert.ok(purchaseCalls.every(origin => origin === undefined));
});

for (const slug of ['threatfox', 'tor', 'tor-exit-nodes', 'tor_exit_nodes', 'ipinfo-lite', 'ipinfo_lite']) test(`legacy slug ${slug} opens canonical inventory detail`, async () => {
  const view = mount(`/?slug=${slug}`);
  const dialog = await view.findByRole('dialog');
  assert.ok(within(dialog as HTMLElement).getByText(inventoryRouteId(slug)));
});

test('missing virustotal link keeps sectioned marketplace and muted notice', async () => {
  const view = mount('/?slug=virustotal');
  await view.findByText("That integration isn't available on this tenant");
  assert.ok(view.getByText('Security tools'));
  assert.ok(view.queryByRole('alert') === null, 'unavailable integrations must not show an alert');
  assert.equal(view.queryByRole('dialog'), null);
});

test('hosted filters, counts, enabled-only and search hotkeys use the shared chrome', async () => {
  const view = mount('/?installed=true');
  await view.findByText('ThreatFox');
  assert.equal(view.queryByText('Synthient'), null);
  assert.equal(view.queryByText('Security tools'), null);
  fireEvent.click(view.getByRole('button', { name: 'enabled only' }));
  await view.findByText('Security tools');
  fireEvent.click(view.getByRole('button', { name: /^Custom\s*3$/ }));
  assert.equal(view.container.querySelectorAll('[data-mp-card]').length, 3);
  fireEvent.click(view.getByRole('button', { name: /^All\s*7$/ }));
  fireEvent.keyDown(document.body, { key: '/' });
  assert.equal(document.activeElement?.id, 'marketplace-search');
  fireEvent.change(view.getByRole('textbox'), { target: { value: 'tor_exit' } });
  assert.equal(view.container.querySelectorAll('[data-mp-card]').length, 1);
});

test('permission denial preserves read-only platform detail and hides authoring', async () => {
  context.permissions = false;
  const view = mount('/?item=synthient&author=new');
  await view.findByRole('dialog');
  assert.equal(view.queryByText('Create / Connect'), null);
  assert.equal(view.queryByText('Marketplace · Custom provider'), null);
  assert.equal((view.getByRole('button', { name: 'Purchase' }) as HTMLButtonElement).disabled, true);
  assert.equal(entitlementCalls, 0);
  assert.equal(purchaseCalls.length, 0);
});

test('coverage refresh updates its caller-bound cache and missing provider focuses search', async () => {
  context.coverage = true;
  let gets = 0;
  const coverage = { computed_at: '2026-09-20T12:00:00Z', artifacts: [{ id: 'ip', label: 'IP address', pct: 50, state: 'partial' as const, have: ['IPinfo Lite'], missing: ['ThreatFox'] }] };
  api.marketplace.getCoverage = async () => { gets++; return coverage; };
  api.marketplace.refreshCoverage = async () => ({ ...coverage, computed_at: '2026-09-21T12:00:00Z' });
  const view = mount();
  await view.findByText('Enrichment coverage · by artifact type');
  fireEvent.click(view.getByRole('button', { name: 'Refresh coverage' }));
  await waitFor(() => assert.equal(view.client.getQueryData<typeof coverage>(['marketplace', 'coverage', 'fixture-user'])?.computed_at, '2026-09-21T12:00:00Z'));
  assert.equal(gets, 1);
  const query = view.client.getQueryCache().find({ queryKey: ['marketplace', 'coverage', 'fixture-user'] })!;
  assert.equal(query.gcTime, 6 * 60 * 60 * 1000);
  fireEvent.click(view.getAllByText('ThreatFox').find(element => element.closest('button') && !element.closest('[data-mp-card]'))!);
  assert.equal((view.getByRole('textbox') as HTMLInputElement).value, 'ThreatFox');
  assert.equal(document.activeElement?.id, 'marketplace-search');
});

test('hosted sources retain platform Sync now, cadence, last sync and polling', async () => {
  let lists = 0;
  let syncs = 0;
  api.marketplace.listRepos = async () => {
    lists++;
    return [{ id: 'platform-repo', slug: 'nano-enrichments', name: 'Platform enrichments', url: 'https://example.test/repo', branch: 'main', description: '', enrichments_path: 'enrichments', auto_sync_enabled: true, sync_interval_hours: 12, last_synced_at: '2026-09-20T12:00:00Z', last_sync_status: 'success', enrichment_count: 7, managed_by_platform: true }] as Awaited<ReturnType<typeof api.marketplace.listRepos>>;
  };
  api.marketplace.syncRepo = async () => { syncs++; return { managed_by_platform: true } as Awaited<ReturnType<typeof api.marketplace.syncRepo>>; };
  const view = mount();
  await view.findByText('Security tools');
  assert.ok(view.getAllByText('auto-sync every 12h').length > 0);
  assert.match(view.container.textContent!, /last sync/);
  fireEvent.click(view.getByRole('button', { name: /Show repository sources/ }));
  fireEvent.click(view.getByRole('button', { name: 'Sync now Platform enrichments' }));
  await waitFor(() => assert.equal(syncs, 1));
  await waitFor(() => assert.equal(lists, 2), { timeout: 3000 });
});

test('enable/disable still requires confirmation and sends the selected revision', async () => {
  let toggles = 0;
  api.marketplace.toggleInventory = async item => { toggles++; assert.equal(item.revision, 1); return { ...item, enabled: false }; };
  const view = mount('/?item=custom:fixture');
  fireEvent.click(await view.findByRole('button', { name: 'Disable' }));
  assert.equal(toggles, 0);
  const confirmation = await view.findByRole('alertdialog');
  fireEvent.click(within(confirmation).getByRole('button', { name: 'Confirm' }));
  await waitFor(() => assert.equal(toggles, 1));
});

test('hosted permission expressions remain byte-identical to the original inventory page', () => {
  const source = readFileSync(new URL('./MarketplaceInventory.tsx', import.meta.url), 'utf8');
  const expressions = [
    "const canReadPurchase = selected?.kind === 'premium' && hasAllPermissions(['settings:system']);",
    "const canAuthor = hasAllPermissions(['enrichments:view', 'enrichments:configure', 'enrichments:code']);",
    "const canCreate = canAuthor && hasAllPermissions(['enrichments:custom:create']);",
    "const canOpenCreate = canCreate || hasAllPermissions(['lookup:view', 'lookup:create']) || hasAllPermissions(['enrichments:configure']);",
    "const editing = (canOpenCreate && params.get('author') === 'new') || (canAuthor && (params.get('author') === 'edit' && selected?.kind === 'custom' && selected.can_edit && selected.id.startsWith('custom:')));",
    "const canConnect = selected?.kind === 'custom' && (selected.id.startsWith('connector:') || !!selected.repository_id) && hasAllPermissions(['enrichments:configure']);",
    "const mayToggle = selected && hasAllPermissions(selected.kind === 'premium' ? ['enrichments:configure', 'settings:system'] : ['enrichments:configure']);",
  ];
  for (const expression of expressions) assert.ok(source.includes(expression), expression);
});

// NAN-3761: a failed load is an error with Retry, never "No integrations matched".
test('hosted inventory and collector load failures show an error state with Retry, not the empty state', async () => {
  let failing = true;
  const real = api.marketplace.listInventory;
  api.marketplace.listInventory = async () => {
    if (failing) throw new ApiClientError('deferred', 'RESOURCE_LOCK_CONTENTION', undefined, 503);
    return real();
  };
  const realCollectors = api.marketplace.hostedCollectors;
  api.marketplace.hostedCollectors = async () => {
    if (failing) throw new ApiClientError('deferred', 'RESOURCE_LOCK_CONTENTION', undefined, 503);
    return realCollectors();
  };
  const view = mount();
  const alert = await view.findByText('Could not load inventory and pull collectors.');
  assert.equal(view.queryByText('No integrations matched.'), null);
  failing = false;
  fireEvent.click(within(alert.closest('[role="alert"]') as HTMLElement).getByRole('button', { name: /Retry/ }));
  await view.findByText('Other integrations');
  assert.equal(view.queryByText(/Could not load/), null);
});

test('dedicated catalog load failure shows an error state with Retry, not the empty state', async () => {
  context.mode = 'dedicated';
  let failing = true;
  api.getSystemConfig = async () => ({ air_gap: false }) as Awaited<ReturnType<typeof api.getSystemConfig>>;
  api.marketplace.listRepos = async () => [];
  api.marketplace.listCatalog = async () => {
    if (failing) throw new ApiClientError('deferred', 'RESOURCE_LOCK_CONTENTION', undefined, 503);
    return { total: 4, entries: catalog, stats: { total_entries: 4, installed_count: 0, data_count: 4, agent_count: 0, identity_count: 0, collector_count: 0 } };
  };
  const view = mount();
  const alert = await view.findByText('Could not load the marketplace catalog.');
  assert.equal(view.queryByText('No integrations matched.'), null);
  failing = false;
  fireEvent.click(within(alert.closest('[role="alert"]') as HTMLElement).getByRole('button', { name: /Retry/ }));
  await waitFor(() => assert.equal(view.container.querySelectorAll('[data-mp-card]').length, 4));
});
