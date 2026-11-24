// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-5770: a just-deleted source's route key read "arriving · no source" and
 * was offered for conversion. The server now sets those keys aside as
 * `removed_sources`; the panel shows them as removed, with no Create action.
 * Unbound tokens with no sampled traffic are collapsed, never hidden (the
 * usage sample misses refused requests).
 */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const calls = vi.hoisted(() => ({ listUnassigned: vi.fn(), convert: vi.fn() }));

vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true }) }));
vi.mock('@/lib/api', () => ({ api: { logSourceConnect: calls } }));

import { UnassignedSources, isUsedToken } from './UnassignedSources';

const token = (over: Record<string, unknown>) => ({
  credential_id: '5a0c0000-0000-4000-8000-0000000000b1',
  name: 'old-edge',
  token_prefix: 'nit_abcdefgh',
  state: 'unbound',
  revocable: true,
  created_at: '2026-11-01T00:00:00Z',
  request_count: 0,
  ...over,
});

function renderIt() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <UnassignedSources />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  calls.listUnassigned.mockReset();
});
afterEach(cleanup);

it('shows a deleted source key as removed, never as an unassigned stream', async () => {
  calls.listUnassigned.mockResolvedValue({
    window_hours: 24,
    install_token_mode: 'per_source',
    sources: [{ route_key: 'fresh_sender', events_24h: 10, last_seen: new Date().toISOString(), convertible: true }],
    removed_sources: [
      {
        route_key: 'e2e_0e0caa2a98',
        log_source_name: 'e2e source',
        deleted_at: new Date(Date.now() - 120_000).toISOString(),
        events_24h: 2,
        last_seen: new Date(Date.now() - 180_000).toISOString(),
      },
    ],
    unbound_tokens: [],
  });
  renderIt();
  await waitFor(() => expect(screen.getByTestId('unassigned-removed')).toBeTruthy());
  const keys = screen.getAllByTestId('unassigned-key').map((r) => r.textContent ?? '');
  expect(keys).toHaveLength(1);
  expect(keys[0]).toContain('fresh_sender');
  const removed = screen.getByTestId('unassigned-removed');
  expect(removed.textContent).toContain('e2e_0e0caa2a98');
  expect(removed.textContent).toContain('removed · source deleted');
  expect(removed.textContent).not.toContain('arriving');
  expect(removed.querySelector('button')).toBeNull();
  expect(screen.getByTestId('unassigned-removed-count').textContent).toContain('1 removed');
});

it('flags tokens with traffic and collapses, never drops, tokens with no sampled traffic', async () => {
  calls.listUnassigned.mockResolvedValue({
    window_hours: 24,
    install_token_mode: 'per_source',
    sources: [],
    unbound_tokens: [
      token({ credential_id: 'a', name: 'never-used' }),
      token({ credential_id: 'b', name: 'still-used', request_count: 3 }),
    ],
  });
  renderIt();
  await waitFor(() => expect(screen.getAllByTestId('unassigned-token')).toHaveLength(1));
  const used = screen.getByTestId('unassigned-token');
  expect(used.textContent).toContain('still-used');
  expect(used.textContent).toContain('traffic without a bound source');
  const toggle = screen.getByTestId('unassigned-quiet-toggle');
  expect(toggle.textContent).toContain('Show 1 unbound token with no sampled traffic');
  fireEvent.click(toggle);
  await waitFor(() => expect(screen.getAllByTestId('unassigned-token')).toHaveLength(2));
  expect(screen.getAllByTestId('unassigned-token')[1].textContent).toContain('no sampled traffic');
});

it('keeps the panel visible when only quiet tokens remain', async () => {
  calls.listUnassigned.mockResolvedValue({
    window_hours: 24,
    install_token_mode: 'per_source',
    sources: [],
    unbound_tokens: [token({})],
  });
  renderIt();
  await waitFor(() => expect(screen.getByTestId('unassigned-quiet-tokens')).toBeTruthy());
  expect(screen.getByTestId('unassigned-sources')).toBeTruthy();
  expect(screen.queryAllByTestId('unassigned-token')).toHaveLength(0);
});

it('isUsedToken counts requests or a seen last use', () => {
  expect(isUsedToken({ request_count: 0, last_used_at: null })).toBe(false);
  expect(isUsedToken({ request_count: 1 })).toBe(true);
  expect(isUsedToken({ request_count: 0, last_used_at: '2026-11-20T00:00:00Z' })).toBe(true);
});
