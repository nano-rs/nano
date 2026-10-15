// SPDX-License-Identifier: AGPL-3.0-or-later
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
// @ts-expect-error jsdom is an existing test dependency without bundled declarations.
import { JSDOM } from 'jsdom';
import type { InventoryItem } from '../../lib/api/marketplace-inventory';
const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://localhost' });
for (const key of ['window', 'document', 'HTMLElement', 'Element', 'Node', 'MutationObserver', 'CustomEvent', 'Event', 'MouseEvent', 'DocumentFragment', 'HTMLInputElement', 'NodeFilter', 'HTMLSelectElement', 'HTMLTextAreaElement']) {
  Object.defineProperty(globalThis, key, { configurable: true, value: (dom.window as unknown as Record<string, unknown>)[key] });
}
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: dom.window.navigator });
Object.defineProperty(globalThis, 'getComputedStyle', { configurable: true, value: dom.window.getComputedStyle });
const { render, cleanup, fireEvent } = await import('@testing-library/react');
const { MemoryRouter } = await import('react-router-dom');
const { InventoryCard } = await import('./InventoryCard');
const { InventoryDrawer } = await import('./InventoryDrawer');
const { InventoryEntitlement } = await import('./InventoryEntitlement');
const { inventoryRouteId, inventoryReason, customInventoryRedirect } = await import('../../lib/api/marketplace-inventory');
const { MarketplaceApi } = await import('../../lib/api/marketplace');
afterEach(cleanup);
const common = { id: 'fixture', name: 'Fixture provider', enabled: true, revision: 7, effective_health: 'unknown', last_sync: null, next_refresh: null, reason: 'missing', execution_stage: 'bronze_ingest', capabilities: [], can_toggle: true, can_edit: false };
const baseline: InventoryItem = { ...common, kind: 'baseline', grant_revision: 1, feed_revision: null };
const premium: InventoryItem = { ...common, kind: 'premium', grant_revision: null, feed_revision: null, entitled: false };
const custom: InventoryItem = { ...common, id: 'custom:fixture', kind: 'custom', author: 'author-id', tenant_id: 'tenant-id', connector: 'agent', repo_commit: 'abcd', repository_id: 'repo-id', artifact_id: 'artifact-id', artifact_sha256: 'hash', execution_stage: 'agent_on_demand' };
function drawer(item: InventoryItem, onToggle = () => {}) {
  return render(<MemoryRouter><InventoryDrawer item={item} onClose={() => {}} onToggle={onToggle} busy={false} /></MemoryRouter>);
}
test('baseline card is included and opens detail', () => {
  let opened = false;
  const view = render(<InventoryCard item={baseline} onOpen={() => { opened = true; }} />);
  fireEvent.click(view.getByRole('button'));
  assert.equal(opened, true); assert.ok(view.getByText('Included · On'));
});
test('premium offers purchase and entitled drawer toggles', () => {
  const view = render(<InventoryCard item={premium} onOpen={() => {}} />);
  assert.ok(view.getByText('Purchase')); cleanup();
  let toggled = false;
  const detail = drawer({ ...premium, entitled: true, grant_revision: 2 }, () => { toggled = true; });
  fireEvent.click(detail.getByRole('button', { name: 'Disable' })); assert.equal(toggled, true);
});
test('custom card shows the agent stage as user copy', () => {
  const view = render(<InventoryCard item={custom} onOpen={() => {}} />);
  assert.ok(view.getByText('On demand · pivt')); assert.ok(view.getByText('custom · unknown'));
});
// NAN-3762: execution_stage is mapped to user copy; the API value never renders.
test('execution stages render as user copy and unknown stages fall back to Enrichment', () => {
  const cases: Array<[string, string]> = [
    ['bronze_ingest', 'Built in · at ingest'],
    ['agent_on_demand', 'On demand · pivt'],
    ['tenant_scheduled_publication', 'Scheduled refresh'],
    ['search_time', 'Enrichment'],
    ['some_future_stage', 'Enrichment'],
    ['', 'Enrichment'],
  ];
  for (const [stage, label] of cases) {
    for (const item of [{ ...baseline, execution_stage: stage }, { ...custom, execution_stage: stage }] as InventoryItem[]) {
      const card = render(<InventoryCard item={item} onOpen={() => {}} />);
      assert.ok(card.getByText(label), `${stage} card`);
      const detail = drawer(item);
      assert.ok(detail.getAllByText(label).length > 0, `${stage} drawer`);
      for (const text of [card.container.textContent!, detail.baseElement.textContent!]) {
        if (stage) assert.ok(!text.includes(stage), `raw ${stage} rendered`);
        for (const raw of ['bronze_ingest', 'agent_on_demand', 'tenant_scheduled_publication']) assert.ok(!text.includes(raw), `raw ${raw} rendered`);
      }
      cleanup();
    }
  }
});
test('inventory capabilities never render as raw snake_case', () => {
  const view = drawer({ ...baseline, capabilities: ['ip_geo', 'threat_intel', 'brand_new_capability'] });
  assert.ok(view.getByText('IP geo, threat intel, brand new capability'));
});
test('custom drawer shows author provenance without grant labels', () => {
  const view = drawer(custom);
  for (const text of ['Author', 'author-id', 'tenant-id', 'abcd', 'artifact-id', 'On demand · pivt']) assert.ok(view.getByText(text));
  assert.equal(view.queryByText('Grant revision'), null);
});
test('platform drawer shows grants without author or key controls', () => {
  const view = drawer(baseline);
  assert.ok(view.getByText('Grant revision')); assert.equal(view.queryByText('Author'), null);
  assert.equal(view.queryByRole('textbox'), null); assert.equal(view.queryByRole('button', { name: 'Disable' }), null);
});
test('stale and unknown reasons are explicit', () => {
  const view = render(<InventoryCard item={{ ...baseline, reason: 'stale', effective_health: 'stale' }} onOpen={() => {}} />);
  assert.ok(view.getByText(/Feed is stale/));
  assert.equal(inventoryReason({ ...baseline, reason: 'new-server-reason' }), 'Provider status is unknown.');
});
test('legacy routes resolve to the same item', () => {
  for (const id of ['tor', 'tor-exit-nodes', 'tor_exit_nodes']) assert.equal(inventoryRouteId(id), 'tor_exit_nodes');
  assert.equal(inventoryRouteId('ipinfo-lite'), 'ipinfo_lite');
  assert.equal(inventoryRouteId('threatfox'), 'threatfox');
  assert.equal(inventoryRouteId('custom:fixture'), 'custom:fixture');
});
test('toggle sends expected revision to the existing service endpoint', async () => {
  let observed: { endpoint: string; options?: RequestInit } | undefined;
  const api = new MarketplaceApi(async <T,>(endpoint: string, options?: RequestInit) => { observed = { endpoint, options }; return { ...custom, enabled: false } as T; });
  assert.equal((await api.toggleInventory(custom)).enabled, false);
  assert.equal(observed?.endpoint, '/api/marketplace/items/custom%3Afixture/toggle');
  assert.deepEqual(JSON.parse(observed?.options?.body as string), { enabled: false, expected_revision: 7 });
});

test('custom settings redirect preserves dedicated and explicit editors', () => {
  assert.equal(customInventoryRedirect('enrich_abc', true, ''), '/marketplace?item=custom%3Aenrich_abc');
  assert.equal(customInventoryRedirect('enrich_abc', true, 'edit=true'), null);
  assert.equal(customInventoryRedirect('enrich_abc', false, ''), null);
});

test('custom detail opens the embedded editor without navigating away', () => {
  let edits = 0;
  const view = render(<MemoryRouter><InventoryDrawer item={{ ...custom, can_edit: true }} onClose={() => {}} onToggle={() => {}} busy={false} onEdit={() => { edits++; }} /></MemoryRouter>);
  fireEvent.click(view.getByRole('button', { name: 'Edit provider' }));
  assert.equal(edits, 1);
  assert.equal(view.queryByRole('link'), null);
});

test('custom detail does not offer editing without an authorized callback', () => {
  const view = drawer({ ...custom, can_edit: true });
  assert.equal(view.queryByRole('button', { name: 'Edit provider' }), null);
});

const purchase = { feed_id: 'synthient', tier: 'sandbox', grant_revision: 1, revision: 3, state: 'pending', enabled: false, expires_at: null };
test('pending payment stays pending despite a client success return', () => {
  let refreshes = 0;
  const view = render(<MemoryRouter initialEntries={['/marketplace?item=synthient&success=true']}><InventoryEntitlement status={purchase} loading={false} failed={false} onRefresh={() => { refreshes++; }} /></MemoryRouter>);
  assert.ok(view.getByText('Payment pending'));
  assert.equal(view.queryByText('Purchased · Enabled'), null);
  fireEvent.click(view.getByRole('button', { name: 'Refresh purchase status' }));
  assert.equal(refreshes, 1);
});

test('verified purchase and renewal preserve the server enabled preference', () => {
  const view = render(<InventoryEntitlement status={{ ...purchase, state: 'active', enabled: true, expires_at: '2099-01-01T00:00:00Z' }} loading={false} failed={false} onRefresh={() => {}} />);
  assert.ok(view.getByText('Purchased · Enabled'));
  view.rerender(<InventoryEntitlement status={{ ...purchase, state: 'active', enabled: false, revision: 4, expires_at: '2099-02-01T00:00:00Z' }} loading={false} failed={false} onRefresh={() => {}} />);
  assert.ok(view.getByText('Purchased · Disabled'));
  assert.ok(view.getByText('2099-02-01T00:00:00Z'));
});

test('expired and revoked purchases never render as enabled', () => {
  const view = render(<InventoryEntitlement status={{ ...purchase, state: 'active', enabled: true, expires_at: '2000-01-01T00:00:00Z' }} loading={false} failed={false} onRefresh={() => {}} />);
  assert.ok(view.getByText('Expired'));
  view.rerender(<InventoryEntitlement status={{ ...purchase, state: 'revoked', enabled: true }} loading={false} failed={false} onRefresh={() => {}} />);
  assert.ok(view.getByText('Revoked'));
});

test('purchase refresh failure hides stale success and permits retry', () => {
  let retries = 0;
  const view = render(<InventoryEntitlement status={{ ...purchase, state: 'active', enabled: true }} loading={false} failed onRefresh={() => { retries++; }} />);
  assert.ok(view.getByRole('alert'));
  assert.equal(view.queryByText('Purchased · Enabled'), null);
  fireEvent.click(view.getByRole('button'));
  assert.equal(retries, 1);
});

test('purchase status uses the existing tenant-bound endpoint with no mutation', async () => {
  let observed: { endpoint: string; options?: RequestInit } | undefined;
  const api = new MarketplaceApi(async <T,>(endpoint: string, options?: RequestInit) => { observed = { endpoint, options }; return purchase as T; });
  assert.deepEqual(await api.inventoryEntitlement('synthient'), purchase);
  assert.deepEqual(observed, { endpoint: '/api/enrichment/entitlements/synthient', options: undefined });
});

test('installed bundle opens the existing connection editor from its inventory detail', () => {
  let connects = 0;
  const view = render(<MemoryRouter><InventoryDrawer item={{ ...custom, id: 'connector:fixture', can_edit: false }} onClose={() => {}} onToggle={() => {}} busy={false} onConnect={() => { connects++; }} /></MemoryRouter>);
  fireEvent.click(view.getByRole('button', { name: 'Configure connection' }));
  assert.equal(connects, 1);
  assert.equal(view.queryByRole('button', { name: 'Edit provider' }), null);
});

test('purchase calls the configured handoff action and never enables locally', () => {
  let calls = 0;
  const view = render(<InventoryDrawer item={premium} onClose={() => {}} onToggle={() => assert.fail('must not toggle')} busy={false} onPurchase={() => { calls++; }} />);
  fireEvent.click(view.getByRole('button', { name: 'Purchase' }));
  assert.equal(calls, 1);
});
test('checkout retries send only origin; reload is read-only', async () => {
  const calls: { endpoint: string; options?: RequestInit }[] = [];
  const api = new MarketplaceApi(async <T,>(endpoint: string, options?: RequestInit) => { calls.push({ endpoint, options }); return {} as T; });
  await api.checkout('synthient', 'signup'); await api.checkout('synthient', 'signup'); await api.checkout('synthient');
  assert.deepEqual(calls[0], calls[1]);
  assert.deepEqual(JSON.parse(calls[0].options!.body as string), { origin: 'signup' });
  assert.equal(calls[2].options, undefined);
});
test('recorded checkout intent is pending without a fabricated entitlement', () => {
  const view = render(<InventoryEntitlement status={null} checkoutPending loading={false} failed={false} onRefresh={() => {}} />);
  assert.ok(view.getByText('Checkout started · awaiting verified billing confirmation'));
  assert.equal(view.queryByText('Purchased · Enabled'), null);
});
