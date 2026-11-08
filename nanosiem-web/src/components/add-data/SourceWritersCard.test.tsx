// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-4922 (main's NAN-2597 / NAN-2946 tests): the tokens that can write a source, revoke, and inline issuance. */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const calls = vi.hoisted(() => ({ getStatus: vi.fn(), revoke: vi.fn(), endpoint: vi.fn() }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true }) }));
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error { status?: number },
  api: { logSourceConnect: { getStatus: calls.getStatus }, ingestTokens: { revoke: calls.revoke, create: vi.fn() }, getIngestEndpoint: calls.endpoint },
}));
import { SourceWritersCard } from './SourceWritersCard';

function renderCard(entry = '/ingestion/log-sources/lsrc_1') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <SourceWritersCard logSourceId="lsrc_1" canRevoke canIssue />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
beforeEach(() => {
  calls.getStatus.mockReset().mockResolvedValue({ source_id: 'lsrc_1', route_key: 'acme', state: 'receiving', deployed: true, lifecycle_status: 'active',
    push_capable: true, events_24h: 10, active_tokens: 1,
    tokens: [
      { credential_id: 'c1', name: 'acme-hec', token_prefix: 'nit_aaaa1111', state: 'active', created_at: '', last_used_at: null, request_count: 7, revocable: true },
      { credential_id: 'c0', name: 'old', token_prefix: 'nit_bbbb', state: 'revoked', created_at: '', revocable: false },
    ] });
  calls.revoke.mockReset().mockResolvedValue({ name: 'acme-hec' });
  calls.endpoint.mockReset().mockResolvedValue({ base_url: 'http://h', hostname: 'h', scheme: 'http', hec_url: 'http://h:8088', hec_event_url: 'http://h:8088/services/collector/event',
    hec_health_url: '', nano_https_url: 'http://h/ingest', otlp_logs_url: '', otlp_traces_url: '', otlp_metrics_url: '', configured: false });
});
afterEach(cleanup);

it('lists active writers (never revoked ones or secrets) and revokes after confirmation', async () => {
  renderCard();
  const table = await screen.findByTestId('source-writers-table');
  expect(table.textContent).toContain('acme-hec');
  expect(table.textContent).toContain('nit_aaaa1111…');
  expect(table.textContent).not.toContain('old');
  fireEvent.click(screen.getByRole('button', { name: /Revoke/ }));
  fireEvent.click(await screen.findByRole('button', { name: 'Revoke token' }));
  await waitFor(() => expect(calls.revoke).toHaveBeenCalledWith('c1'));
});

it('opens inline issuance from ?action=add-credential', async () => {
  renderCard('/ingestion/log-sources/lsrc_1?action=add-credential');
  expect(await screen.findByTestId('source-writers-issue-panel')).toBeTruthy();
  expect(await screen.findByTestId('issue-credential-panel')).toBeTruthy();
});

it('renders nothing for a source with no push path', async () => {
  calls.getStatus.mockResolvedValue({ source_id: 'lsrc_1', route_key: 'k', state: 'receiving', deployed: true, lifecycle_status: 'active',
    push_capable: false, events_24h: 0, active_tokens: 0, tokens: [] });
  const { container } = renderCard();
  await waitFor(() => expect(calls.getStatus).toHaveBeenCalled());
  await waitFor(() => expect(container.querySelector('[data-testid="source-writers"]')).toBeNull());
});
