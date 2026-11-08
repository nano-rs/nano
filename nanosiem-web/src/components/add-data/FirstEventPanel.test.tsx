// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-4922 (main's NAN-2599 tests, re-backed): the checklist reads the source's connect status. */
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const calls = vi.hoisted(() => ({ getStatus: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { logSourceConnect: { getStatus: calls.getStatus } } }));
import { FirstEventPanel } from './FirstEventPanel';

const issuedAt = new Date(Date.now() - 20_000).toISOString();
function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <FirstEventPanel logSourceId="lsrc_1" credentialId="c1" issuedAt={issuedAt} sourceSlugs={['acme']} parserHref="/parse" searchField="metadata.log_source" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
afterEach(cleanup);

it('shows the searchable state, the 24h count, the unparsed hint and an OCSF-scoped search link', async () => {
  const now = new Date().toISOString();
  calls.getStatus.mockResolvedValue({ source_id: 'lsrc_1', route_key: 'acme', state: 'receiving_unparsed', deployed: false, lifecycle_status: 'draft',
    push_capable: true, events_24h: 3, active_tokens: 1, last_seen: now,
    tokens: [{ credential_id: 'c1', name: 'acme-hec', token_prefix: 'nit_x', state: 'active', created_at: issuedAt, last_used_at: now, revocable: true }] });
  renderPanel();
  await waitFor(() => expect(screen.getByText('First event is searchable')).toBeTruthy());
  expect(screen.getByTestId('first-event-step-searchable').getAttribute('data-state')).toBe('done');
  expect(screen.getByTestId('first-event-counts').textContent).toContain('3');
  expect(screen.getByTestId('first-event-hint-unparsed')).toBeTruthy();
  expect(screen.getByTestId('first-event-parser-link').getAttribute('href')).toBe('/parse');
  const href = screen.getByTestId('first-event-search-link').getAttribute('href') ?? '';
  // NAN-4927: the query rides in the fragment so it never reaches server logs.
  expect(href.startsWith('/search#')).toBe(true);
  expect(new URLSearchParams(href.split('#')[1]).get('q')).toBe('metadata.log_source="acme"');
});

it('keeps waiting while nothing arrived after the token was issued', async () => {
  calls.getStatus.mockResolvedValue({ source_id: 'lsrc_1', route_key: 'acme', state: 'awaiting_data', deployed: false, lifecycle_status: 'draft',
    push_capable: true, events_24h: 0, active_tokens: 1, tokens: [] });
  renderPanel();
  await waitFor(() => expect(calls.getStatus).toHaveBeenCalled());
  expect(screen.getByText('Waiting for the first event')).toBeTruthy();
  expect(screen.getByTestId('first-event-step-received').getAttribute('data-state')).toBe('active');
});
