// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4912 phase 2 (main's NAN-4847 A): unassigned source keys and unbound
 * tokens on Log sources, converted without changing any token value.
 */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const perms = vi.hoisted(() => ({ system: true, inventory: true }));
const calls = vi.hoisted(() => ({ listUnassigned: vi.fn(), convert: vi.fn() }));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    hasPermission: (p: string) =>
      p === 'settings:system' ? perms.system : ['search:execute', 'log_sources:create', 'detections:view', 'source_scopes:view'].includes(p) ? perms.inventory : true,
  }),
}));
vi.mock('@/lib/api', () => ({ api: { logSourceConnect: calls } }));

import { UnassignedSources } from './UnassignedSources';

const UNBOUND = {
  credential_id: '5a0c0000-0000-4000-8000-0000000000b1',
  name: 'old-edge',
  token_prefix: 'nit_abcdefgh',
  state: 'unbound',
  revocable: true,
  created_at: '2026-11-01T00:00:00Z',
  request_count: 12,
};

function renderIt() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/ingestion/log-sources']}>
        <Routes>
          <Route path="/ingestion/log-sources" element={<UnassignedSources />} />
          <Route path="/ingestion/log-sources/new" element={<div data-testid="wizard">wizard</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  perms.system = true;
  perms.inventory = true;
  calls.listUnassigned.mockReset();
  calls.convert.mockReset();
  calls.listUnassigned.mockResolvedValue({
    window_hours: 24,
    install_token_mode: 'legacy_multiplex',
    sources: [
      { route_key: 'legacy_fw', events_24h: 4200, last_seen: new Date().toISOString(), convertible: true },
      { route_key: 'Bad Key', events_24h: 5, last_seen: null, convertible: false },
    ],
    unbound_tokens: [UNBOUND],
  });
});
afterEach(cleanup);

it('lists unassigned keys and unbound tokens, explains legacy multiplex', async () => {
  renderIt();
  await waitFor(() => expect(screen.getAllByTestId('unassigned-key')).toHaveLength(2));
  expect(screen.getByTestId('unassigned-sources').textContent).toContain('legacy multiplex');
  expect(screen.getAllByTestId('unassigned-key')[0].textContent).toContain('4.2k / 24h');
  // A key unsafe for generated config is shown but not convertible.
  expect(screen.getAllByTestId('unassigned-key')[1].textContent).toContain('fix at sender');
  expect(screen.getByTestId('unassigned-token').textContent).toContain('refused · source deleted');
});

it('converts a key into a draft with no token, then continues at Parse', async () => {
  calls.convert.mockResolvedValue({ log_source: { id: 'lsrc_x' }, bound_token: null, publication_pending: false });
  renderIt();
  await waitFor(() => screen.getAllByRole('button', { name: 'Create source' }));
  fireEvent.click(screen.getAllByRole('button', { name: 'Create source' })[0]);
  expect((screen.getByTestId('convert-key') as HTMLInputElement).disabled).toBe(true);
  fireEvent.change(screen.getByTestId('convert-name'), { target: { value: 'Legacy firewall' } });
  fireEvent.click(screen.getByTestId('convert-submit'));
  await waitFor(() => expect(screen.getByTestId('wizard')).toBeTruthy());
  expect(calls.convert).toHaveBeenCalledWith({ route_key: 'legacy_fw', name: 'Legacy firewall', credential_id: undefined });
});

it('assigns an unbound token to a new source key (same token, no rotation)', async () => {
  calls.convert.mockResolvedValue({ log_source: { id: 'lsrc_y' }, bound_token: { ...UNBOUND, state: 'active' }, publication_pending: false });
  renderIt();
  await waitFor(() => screen.getByRole('button', { name: 'Assign to new source' }));
  fireEvent.click(screen.getByRole('button', { name: 'Assign to new source' }));
  const submit = screen.getByTestId('convert-submit') as HTMLButtonElement;
  expect(submit.disabled).toBe(true);
  fireEvent.change(screen.getByTestId('convert-key'), { target: { value: 'Orphan App' } });
  expect(submit.disabled).toBe(true);
  fireEvent.change(screen.getByTestId('convert-key'), { target: { value: 'orphan_app' } });
  fireEvent.click(submit);
  await waitFor(() => expect(calls.convert).toHaveBeenCalled());
  expect(calls.convert.mock.calls[0][0]).toMatchObject({ route_key: 'orphan_app', credential_id: UNBOUND.credential_id });
});

it('without settings:system, a token cannot be assigned', async () => {
  perms.system = false;
  renderIt();
  await waitFor(() => screen.getByTestId('unassigned-token'));
  expect(screen.queryByRole('button', { name: 'Assign to new source' })).toBeNull();
});

it('shows a server refusal in the dialog', async () => {
  calls.convert.mockRejectedValue(new Error('Log source "x" already receives source key "legacy_fw"'));
  renderIt();
  await waitFor(() => screen.getAllByRole('button', { name: 'Create source' }));
  fireEvent.click(screen.getAllByRole('button', { name: 'Create source' })[0]);
  fireEvent.click(screen.getByTestId('convert-submit'));
  await waitFor(() => expect(screen.getByTestId('convert-error').textContent).toContain('already receives'));
});

it('without a live-inventory capability, neither queries nor renders (the server would 403)', async () => {
  perms.inventory = false;
  const { container } = renderIt();
  await new Promise((r) => setTimeout(r, 20));
  expect(calls.listUnassigned).not.toHaveBeenCalled();
  expect(container.textContent).toBe('');
});
