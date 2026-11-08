// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4907 (ported from main's NAN-3770 / NAN-3806 tests): named ingest tokens
 * on Log Sources → Credentials (NAN-4922; formerly Ingestion → Ingest tokens). Every token is bound to one source; unbound
 * tokens are refused until an admin binds them; rotate shows the new value
 * once; the install token's deprecated legacy multiplex mode is flagged.
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
  rotate: vi.fn(),
  setInstallTokenStrict: vi.fn(),
  setInstallTokenEnabled: vi.fn(),
  bindInstallToken: vi.fn(),
}));

// Radix Select needs these in jsdom.
beforeEach(() => {
  Element.prototype.hasPointerCapture ??= () => false;
  Element.prototype.releasePointerCapture ??= () => {};
  Element.prototype.scrollIntoView ??= () => {};
});

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 'u' },
    hasPermission: (p: string) => (p === 'settings:system' ? permissions.admin : true),
  }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/lib/api', () => ({
  api: {
    ingestTokens: calls,
    getIngestEndpoint: () => Promise.reject(new Error('not under test')),
  },
}));

import { IngestCredentials } from '@/pages/IngestCredentials';

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
      mode: 'strict',
      deprecated: false,
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
  calls.rotate.mockResolvedValue({
    credential: { ...ACTIVE, credential_id: '0b8f6a52-6f1e-4c55-9a3e-2f1d7c9b1a09', rotated_from: ACTIVE.credential_id },
    token: 'nit_ROTATEDrotatedROTATEDrotatedROTATED12',
    replaced: { ...ACTIVE, state: 'revoked' },
  });
  calls.setInstallTokenStrict.mockResolvedValue({ name: 'Install token (legacy)', enabled: true, state: 'unbound' });
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
  // Only the active row can be rotated.
  expect(within(rows[0]).getByRole('button', { name: 'Rotate' })).toBeTruthy();
  expect(within(rows[1]).queryByRole('button', { name: 'Rotate' })).toBeNull();
  expect(screen.queryByTestId('legacy-multiplex-alert')).toBeNull();
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
  // The HEC listener has acknowledgements on: a request without a channel is refused (code 10).
  expect(hec).toContain('X-Splunk-Request-Channel:');
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
  expect(section.textContent?.replace(/splunk_hec_logs|Authorization: Splunk|X-Splunk-Request-Channel/g, '')).not.toMatch(/splunk/i);
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
    install_token: { name: 'Install token (legacy)', enabled: true, mode: 'strict', deprecated: false, state: 'unbound' },
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

it('rotates after confirmation and shows the new value once', async () => {
  renderPage();
  const rows = await screen.findAllByTestId('ingest-token-row');
  fireEvent.click(within(rows[0]).getByRole('button', { name: 'Rotate' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Rotate' }));
  await waitFor(() => expect(calls.rotate).toHaveBeenCalledWith(ACTIVE.credential_id));
  expect((await screen.findByTestId('rotated-ingest-token')).textContent).toBe(
    'nit_ROTATEDrotatedROTATEDrotatedROTATED12',
  );
  fireEvent.click(screen.getByRole('button', { name: 'Done' }));
  await waitFor(() => expect(screen.queryByTestId('rotated-ingest-token')).toBeNull());
  expect(document.body.textContent).not.toContain('nit_ROTATED');
});

it('flags the deprecated legacy multiplex install token and can end it', async () => {
  calls.list.mockResolvedValue({
    tokens: [ACTIVE],
    install_token: {
      name: 'Install token (legacy)',
      enabled: true,
      mode: 'legacy_multiplex',
      deprecated: true,
      state: 'legacy_multiplex',
    },
    sources: [APACHE, FIREWALL],
  });
  renderPage();
  const alert = await screen.findByTestId('legacy-multiplex-alert');
  expect(alert.textContent).toContain('Deprecated');
  expect(alert.textContent).toContain('X-Source-Type');
  expect(within(screen.getByTestId('install-token-row')).getByText('X-Source-Type (multiplex)')).toBeTruthy();
  // Legacy multiplex is not "unbound": it is accepted, so no 401 alert.
  expect(screen.queryByTestId('unbound-tokens-alert')).toBeNull();
  fireEvent.click(within(alert).getByRole('button', { name: 'Stop multiplexing' }));
  const confirms = await screen.findAllByRole('button', { name: 'Stop multiplexing' });
  fireEvent.click(confirms[confirms.length - 1]);
  await waitFor(() => expect(calls.setInstallTokenStrict).toHaveBeenCalled());
});

it('refuses to offer token issuing when delivery to Vector is not configured', async () => {
  calls.list.mockResolvedValue({
    tokens: [ACTIVE],
    install_token: { name: 'Install token (legacy)', enabled: true, mode: 'strict', deprecated: false, state: 'unbound' },
    sources: [APACHE],
    delivery: 'none',
  });
  renderPage();
  const alert = await screen.findByTestId('token-delivery-alert');
  expect(alert.textContent).toContain('NANO_INGEST_TOKENS_DELIVERY');
  expect(screen.queryByRole('button', { name: /New token/ })).toBeNull();
});

it('discards the rotated value from mutation state when the dialog closes', async () => {
  renderPage();
  const rows = await screen.findAllByTestId('ingest-token-row');
  fireEvent.click(within(rows[0]).getByRole('button', { name: 'Rotate' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Rotate' }));
  await screen.findByTestId('rotated-ingest-token');
  fireEvent.click(screen.getByRole('button', { name: 'Done' }));
  await waitFor(() => expect(screen.queryByTestId('rotated-ingest-token')).toBeNull());
  // Re-opening the confirm never resurfaces the previous value.
  fireEvent.click(within(screen.getAllByTestId('ingest-token-row')[0]).getByRole('button', { name: 'Rotate' }));
  expect(document.body.textContent).not.toContain('nit_ROTATED');
});
