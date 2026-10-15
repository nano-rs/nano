// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-3770: open-core named ingest tokens on Ingestion → Credentials.
 * NAN-3806: every token is bound to one source; unbound tokens are refused
 * until an admin binds them; per-source snippets and the Vector aggregator.
 */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const permissions = vi.hoisted(() => ({ admin: true }));
const calls = vi.hoisted(() => ({
  list: vi.fn(),
  create: vi.fn(),
  bind: vi.fn(),
  revoke: vi.fn(),
  setInstallTokenEnabled: vi.fn(),
  bindInstallToken: vi.fn(),
}));

// Radix Select needs these in jsdom.
beforeEach(() => {
  Element.prototype.hasPointerCapture ??= () => false;
  Element.prototype.releasePointerCapture ??= () => {};
  Element.prototype.scrollIntoView ??= () => {};
});

vi.mock('@/hooks/use-shared-tenant', () => ({ useSharedTenant: () => false }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 'u' },
    hasPermission: (p: string) => (p === 'settings:system' ? permissions.admin : true),
  }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/lib/api', () => ({
  api: {
    listIngestCredentials: () => Promise.reject(new Error('hosted only')),
    getIngestEndpoint: () => Promise.reject(new Error('hosted only')),
    ingestTokens: calls,
    landingSources: { list: () => Promise.resolve({ sources: [] }), files: () => Promise.resolve({ files: [] }) },
  },
}));

import { IngestCredentials } from '@/pages/IngestCredentials';
import { CapabilitiesContext, type CapabilitiesContextValue } from '@/hooks/use-capabilities';

const APACHE = {
  source_id: '5a0c0000-0000-4000-8000-0000000000a1',
  name: 'Apache HTTP',
  source_type: 'routed',
  route_key: 'apache_access',
  enabled: true,
};
const FIREWALL = {
  source_id: '5a0c0000-0000-4000-8000-0000000000f1',
  name: 'Palo Alto',
  source_type: 'splunk_hec',
  route_key: 'pan_traffic',
  enabled: true,
};
const ACTIVE = {
  credential_id: '0b8f6a52-6f1e-4c55-9a3e-2f1d7c9b1a01',
  name: 'lab-steady-blaster',
  token_prefix: 'nit_AbCd1234',
  state: 'active',
  source_id: APACHE.source_id,
  source_name: APACHE.name,
  route_key: APACHE.route_key,
  request_count: 1234,
  created_at: '2026-10-13T16:00:00Z',
  last_used_at: '2026-10-13T16:05:00Z',
  revocable: true,
};
const UNBOUND = {
  ...ACTIVE,
  credential_id: '0b8f6a52-6f1e-4c55-9a3e-2f1d7c9b1a04',
  name: 'edge-legacy',
  token_prefix: 'nit_Unb0und1',
  state: 'unbound',
  source_id: null,
  source_name: null,
  route_key: null,
  request_count: 0,
};
const REVOKED = {
  ...ACTIVE,
  credential_id: '0b8f6a52-6f1e-4c55-9a3e-2f1d7c9b1a02',
  name: 'old-forwarder',
  token_prefix: 'nit_ZyXw9876',
  state: 'revoked',
  revoked_at: '2026-10-13T16:10:00Z',
  last_used_at: null,
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <IngestCredentials />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  permissions.admin = true;
  calls.list.mockResolvedValue({
    tokens: [ACTIVE, REVOKED],
    install_token: {
      name: 'Install token (legacy)',
      enabled: true,
      state: 'active',
      source_id: APACHE.source_id,
      source_name: APACHE.name,
      route_key: APACHE.route_key,
    },
    sources: [APACHE, FIREWALL],
  });
  calls.create.mockResolvedValue({
    credential: { ...ACTIVE, credential_id: '0b8f6a52-6f1e-4c55-9a3e-2f1d7c9b1a03', name: 'fw-edge-01' },
    token: 'nit_TESTVALUEtestvalueTESTVALUEtestvalue12',
  });
  calls.revoke.mockResolvedValue({ ...ACTIVE, state: 'revoked' });
  calls.bind.mockResolvedValue({ ...UNBOUND, state: 'active', source_id: FIREWALL.source_id, route_key: 'pan_traffic' });
  calls.bindInstallToken.mockResolvedValue({ name: 'Install token (legacy)', enabled: true, state: 'active' });
  calls.setInstallTokenEnabled.mockResolvedValue({ name: 'Install token (legacy)', enabled: false });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it('lists named tokens by prefix and the install token as legacy, never a value', async () => {
  renderPage();
  const panel = await screen.findByTestId('ingest-tokens-panel');
  expect(within(panel).getByText('Install token (legacy)')).toBeTruthy();
  const rows = within(panel).getAllByTestId('ingest-token-row');
  expect(rows).toHaveLength(2);
  expect(within(rows[0]).getByText('nit_AbCd1234…')).toBeTruthy();
  // Each token shows the source it decides, and its request count.
  expect(within(rows[0]).getByText('apache_access')).toBeTruthy();
  expect(within(rows[0]).getByText('1,234')).toBeTruthy();
  expect(within(screen.getByTestId('install-token-row')).getByText('apache_access')).toBeTruthy();
  expect(screen.queryByTestId('unbound-tokens-alert')).toBeNull();
  expect(within(rows[0]).getByText('2026-10-13 16:05')).toBeTruthy();
  expect(within(rows[1]).getByText('revoked 2026-10-13 16:10')).toBeTruthy();
  // Only the active row can be revoked.
  expect(within(rows[0]).getByRole('button', { name: 'Revoke' })).toBeTruthy();
  expect(within(rows[1]).queryByRole('button', { name: 'Revoke' })).toBeNull();
  // Hosted-only controls are absent on open core.
  expect(screen.queryByRole('button', { name: /Add data/ })).toBeNull();
});

/** Opens a shared (Radix) Select by its label and picks an option. */
async function pick(container: HTMLElement, label: string, option: RegExp) {
  const trigger = within(container).getByRole('combobox', { name: label });
  fireEvent.keyDown(trigger, { key: 'Enter' });
  await waitFor(() => expect(trigger.getAttribute('aria-expanded')).toBe('true'));
  // The open listbox is the last one: a closed Select from an earlier render
  // can linger in the document under jsdom.
  const item = await waitFor(() => {
    const listboxes = document.querySelectorAll('[role="listbox"]');
    const listbox = listboxes[listboxes.length - 1];
    const found = listbox
      ? Array.from(listbox.querySelectorAll('[role="option"]')).find((el) => option.test(el.textContent ?? ''))
      : undefined;
    if (!found) throw new Error(`no option ${option} in ${label}`);
    return found;
  });
  fireEvent.keyDown(item, { key: 'Enter' });
  await waitFor(() => expect(trigger.textContent).toMatch(option));
}

// Kept ahead of the dialog tests: under jsdom a Radix Select opened after an
// earlier test's issue dialog reports expanded but never mounts its listbox.
it('shows per-source snippets and a Vector aggregator with one sink and token per log type', async () => {
  renderPage();
  const section = await screen.findByTestId('send-data-section');
  await pick(section, 'Send data to', /apache_access/);
  expect(within(section).getByTestId('send-data-tokens').textContent).toContain('lab-steady-blaster (nit_AbCd1234…)');
  const hec = within(section).getByTestId('snippet-hec').textContent ?? '';
  expect(hec).toContain(':8088/services/collector/event');
  expect(hec).toContain('Authorization: Splunk $NANO_TOKEN_APACHE_ACCESS');
  // The token decides the source: no snippet declares a sourcetype.
  expect(hec).not.toContain('"sourcetype"');
  const http = within(section).getByTestId('snippet-http').textContent ?? '';
  expect(http).toContain('Authorization: Bearer $NANO_TOKEN_APACHE_ACCESS');
  expect(http).not.toContain('X-Source-Type');
  const vector = within(section).getByTestId('snippet-vector-aggregator').textContent ?? '';
  expect(vector.match(/type = "splunk_hec_logs"/g)).toHaveLength(2);
  expect(vector).toContain('default_token = "${NANO_TOKEN_APACHE_ACCESS}"');
  expect(vector).toContain('default_token = "${NANO_TOKEN_PAN_TRAFFIC}"');
  expect(vector).not.toMatch(/^\s*sourcetype\s*=/m);
  // User-facing text says HEC, never the vendor name (the sink type is a wire literal).
  expect(section.textContent?.replace(/splunk_hec_logs|Authorization: Splunk/g, '')).not.toMatch(/splunk/i);
  // Admins can issue a token for the picked source straight from here.
  fireEvent.click(within(section).getByRole('button', { name: /Token for apache_access/ }));
  const dialog = await screen.findByTestId('issue-ingest-token-dialog');
  expect(within(dialog).getByRole('combobox', { name: 'Source' }).textContent).toContain('apache_access');
});

it('issues a token bound to a source and shows its value once', async () => {
  renderPage();
  fireEvent.click(await screen.findByRole('button', { name: /New token/ }));
  const dialog = await screen.findByTestId('issue-ingest-token-dialog');
  fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: ' fw-edge-01 ' } });
  // No source, no token.
  expect(within(dialog).getByRole('button', { name: 'Issue token' }).hasAttribute('disabled')).toBe(true);
  await pick(dialog, 'Source', /pan_traffic/);
  fireEvent.click(within(dialog).getByRole('button', { name: 'Issue token' }));
  await waitFor(() => expect(calls.create).toHaveBeenCalledWith('fw-edge-01', FIREWALL.source_id));
  expect((await screen.findByTestId('issued-ingest-token')).textContent).toBe(
    'nit_TESTVALUEtestvalueTESTVALUEtestvalue12',
  );
  fireEvent.click(screen.getByRole('button', { name: 'Done' }));
  await waitFor(() => expect(screen.queryByTestId('issued-ingest-token')).toBeNull());
  expect(document.body.textContent).not.toContain('nit_TESTVALUE');
});

it('revokes after confirmation', async () => {
  renderPage();
  const rows = await screen.findAllByTestId('ingest-token-row');
  fireEvent.click(within(rows[0]).getByRole('button', { name: 'Revoke' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
  await waitFor(() => expect(calls.revoke).toHaveBeenCalledWith(ACTIVE.credential_id));
});

it('warns before disabling the install token', async () => {
  renderPage();
  const row = await screen.findByTestId('install-token-row');
  fireEvent.click(within(row).getByRole('button', { name: 'Disable' }));
  expect(await screen.findByText(/Move every sender to a named token first/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Disable' }));
  await waitFor(() => expect(calls.setInstallTokenEnabled).toHaveBeenCalledWith(false));
});

it('hides create, revoke and install toggles from non-admins', async () => {
  permissions.admin = false;
  renderPage();
  await screen.findByTestId('ingest-tokens-panel');
  expect(screen.queryByRole('button', { name: /New token/ })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Revoke' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Disable' })).toBeNull();
});

it('flags unbound tokens as refused and binds them to a source', async () => {
  calls.list.mockResolvedValue({
    tokens: [UNBOUND, ACTIVE],
    install_token: { name: 'Install token (legacy)', enabled: true, state: 'unbound' },
    sources: [APACHE, FIREWALL],
  });
  renderPage();
  const alert = await screen.findByTestId('unbound-tokens-alert');
  expect(alert.textContent).toContain('2 tokens are not bound to a source');
  expect(alert.textContent).toContain('HTTP 401');
  const rows = screen.getAllByTestId('ingest-token-row');
  expect(within(rows[0]).getByText('unbound')).toBeTruthy();
  expect(within(rows[0]).getByText('no source')).toBeTruthy();
  // A bound token has no Bind action: a binding never changes.
  expect(within(rows[1]).queryByRole('button', { name: 'Bind' })).toBeNull();

  fireEvent.click(within(rows[0]).getByRole('button', { name: 'Bind' }));
  const dialog = await screen.findByTestId('bind-ingest-token-dialog');
  expect(within(dialog).getByText('Bind this token to a source')).toBeTruthy();
  await pick(dialog, 'Source', /pan_traffic/);
  fireEvent.click(within(dialog).getByRole('button', { name: 'Bind' }));
  await waitFor(() => expect(calls.bind).toHaveBeenCalledWith(UNBOUND.credential_id, FIREWALL.source_id));

  // The install token binds the same way.
  fireEvent.click(within(screen.getByTestId('install-token-row')).getByRole('button', { name: 'Bind' }));
  const installDialog = await screen.findByTestId('bind-ingest-token-dialog');
  await pick(installDialog, 'Source', /apache_access/);
  fireEvent.click(within(installDialog).getByRole('button', { name: 'Bind' }));
  await waitFor(() => expect(calls.bindInstallToken).toHaveBeenCalledWith(APACHE.source_id));
});

it('NAN-3844: a Tenzir-only install shows the bucket drop and a note instead of tokens', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <CapabilitiesContext.Provider
        value={{ edition: 'open', version: 'test', ingestMode: 'tenzir_only', capabilities: {} as CapabilitiesContextValue['capabilities'] }}
      >
        <MemoryRouter>
          <IngestCredentials />
        </MemoryRouter>
      </CapabilitiesContext.Provider>
    </QueryClientProvider>,
  );
  expect(await screen.findByTestId('landing-sources-panel')).toBeTruthy();
  expect(within(screen.getByTestId('ingest-tokens-disabled')).getByTestId('tenzir-only-note').textContent).toBe(
    'This install ingests via Tenzir; re-run install.sh --add-vector to enable',
  );
  expect(screen.queryByText('lab-steady-blaster')).toBeNull();
  expect(calls.list).not.toHaveBeenCalled();
});
