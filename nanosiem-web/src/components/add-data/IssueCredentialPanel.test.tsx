// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4922 (main's NAN-2593 / NAN-4890 tests, re-backed on NAN-4907 tokens):
 * the Connect step issues a token bound to the source, shows it once, builds
 * the Send step from it (endpoint, header, snippet) and watches for the first
 * event; nothing waits on a parser publish.
 */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { IngestEndpoint } from '@/lib/api/types';

const calls = vi.hoisted(() => ({ create: vi.fn(), getStatus: vi.fn(), perms: new Set<string>(['settings:system']) }));
vi.mock('@/lib/clipboard', () => ({ copyText: vi.fn().mockResolvedValue(true) }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: (p: string) => calls.perms.has(p) }) }));
vi.mock('@/lib/api', () => ({
  api: { ingestTokens: { create: calls.create }, logSourceConnect: { getStatus: calls.getStatus } },
}));

import { IssueCredentialPanel } from './IssueCredentialPanel';

const endpoint: IngestEndpoint = {
  base_url: 'http://siem.local', hostname: 'siem.local', scheme: 'http', hec_url: 'http://siem.local:8088', hec_event_url: 'http://siem.local:8088/services/collector/event',
  hec_health_url: '', nano_https_url: 'http://siem.local/ingest', otlp_logs_url: 'http://siem.local/otlp/v1/logs',
  otlp_traces_url: '', otlp_metrics_url: '', configured: false,
};
const source = { slug: 'acme_vpn', protocols: ['hec', 'nano_https', 'otlp_http'] as const, enrolled: true };

function renderPanel(props: Partial<Parameters<typeof IssueCredentialPanel>[0]> = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <IssueCredentialPanel endpoint={endpoint} source={{ ...source, protocols: [...source.protocols] }} logSourceId="lsrc_1" linear initialProtocol="hec" {...props} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  calls.perms = new Set(['settings:system']);
  calls.create.mockReset().mockResolvedValue({
    token: 'nit_SECRETVALUE',
    credential: { credential_id: 'cred-1', name: 'acme_vpn-hec', token_prefix: 'nit_SECRETVA', state: 'active', route_key: 'acme_vpn',
      created_at: '', revocable: true },
  });
  calls.getStatus.mockReset().mockResolvedValue({ source_id: 'lsrc_1', route_key: 'acme_vpn', state: 'awaiting_data', deployed: false,
    lifecycle_status: 'draft', push_capable: true, events_24h: 0, active_tokens: 1, tokens: [] });
});
afterEach(cleanup);

it('orders credential → send → first events and locks the later steps until a token exists', () => {
  renderPanel();
  expect(screen.getByTestId('connect-step-credential').getAttribute('data-state')).toBe('active');
  expect(screen.getByTestId('connect-step-send').getAttribute('data-state')).toBe('locked');
  expect(screen.getByTestId('connect-step-events').getAttribute('data-state')).toBe('locked');
  expect(screen.queryByTestId('sender-snippets')).toBeNull();
});

it('issues a token bound to the source and builds the Send step from it', async () => {
  renderPanel();
  fireEvent.click(screen.getByRole('button', { name: /Issue token/ }));
  await waitFor(() => expect(calls.create).toHaveBeenCalledWith('acme_vpn-hec', 'lsrc_1'));
  expect(await screen.findByLabelText('Ingest token')).toHaveProperty('value', 'nit_SECRETVALUE');
  const send = screen.getByTestId('connect-step-send');
  expect(within(send).getByTestId('ingest-endpoint-card').textContent).toContain('http://siem.local:8088/services/collector/event');
  expect(within(send).getByTestId('connect-auth-header').textContent).toContain('Authorization: Splunk <token>');
  expect(within(send).getByTestId('sender-snippet-body').textContent).toContain('Authorization: Splunk nit_SECRETVALUE');
});

it('starts the first-event checklist once the token is copied', async () => {
  renderPanel();
  fireEvent.click(screen.getByRole('button', { name: /Issue token/ }));
  fireEvent.click(await screen.findByRole('button', { name: 'Copy token' }));
  expect(await screen.findByTestId('first-event-panel')).toBeTruthy();
  await waitFor(() => expect(calls.getStatus).toHaveBeenCalledWith('lsrc_1'));
});

it('explains a refusal and needs settings:system to issue', async () => {
  calls.create.mockRejectedValueOnce(Object.assign(new Error('name taken'), { status: 409 }));
  renderPanel();
  fireEvent.click(screen.getByRole('button', { name: /Issue token/ }));
  expect((await screen.findByRole('alert')).textContent).toContain('Name already used');
  cleanup();
  calls.perms = new Set();
  renderPanel();
  expect(screen.getByRole('button', { name: /Issue token/ })).toHaveProperty('disabled', true);
  expect(screen.getByText('settings:system')).toBeTruthy();
});
