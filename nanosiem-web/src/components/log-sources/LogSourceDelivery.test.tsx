// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-4922 (main's NAN-3661 tests, re-backed): push tokens, the pull source config, accepted counts and collector errors. */
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { LogSourceHealth } from '@/lib/api/types';

const calls = vi.hoisted(() => ({ getStatus: vi.fn(), getSourceConfig: vi.fn(), listSourceConfigs: vi.fn(async () => [] as unknown[]), listRoutingRules: vi.fn((id: string): Promise<unknown[]> => Promise.resolve(id ? [] : [])) }));
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error { status?: number },
  api: {
    logSourceConnect: { getStatus: calls.getStatus },
    getSourceConfig: calls.getSourceConfig,
    listSourceConfigs: calls.listSourceConfigs,
    listRoutingRules: calls.listRoutingRules,
  },
}));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true }) }));
import { LogSourceDelivery } from './LogSourceDelivery';

const health = { events_last_hour: 12, events_last_24h: 3400, last_event_at: new Date().toISOString(), parse_errors_24h: 0,
  collector_errors: [{ timestamp: new Date().toISOString(), level: 'ERROR', message: 'AccessDenied on sqs:ReceiveMessage', error_code: 'failed_fetching_sqs_events',
    error_type: 'request_failed', stage: 'receiving', component_type: 'aws_s3' }],
  collector_errors_24h: 4, collector_error_hint: 'Grant sqs:ReceiveMessage to the role.' } as unknown as LogSourceHealth;

function renderPanel(dispatch?: string, matchValues?: string[]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter><LogSourceDelivery logSourceId="lsrc_1" dispatchSourceConfigId={dispatch} matchValues={matchValues} health={health} /></MemoryRouter>
    </QueryClientProvider>,
  );
}
afterEach(cleanup);

it('shows the push path with its tokens, accepted counts and the collector error with its hint', async () => {
  calls.getStatus.mockResolvedValue({ source_id: 'lsrc_1', route_key: 'acme', state: 'receiving', push_capable: true, events_24h: 3400, active_tokens: 1,
    tokens: [{ credential_id: 'c1', name: 't', token_prefix: 'nit_x', state: 'active', created_at: '', last_used_at: new Date().toISOString(), revocable: true }] });
  renderPanel();
  expect(await screen.findByTestId('delivery-row-push')).toBeTruthy();
  expect(screen.getByTestId('delivery-row-push').textContent).toContain('1 active');
  expect(screen.getByTestId('delivery-accepted-1h').textContent).toBe('12');
  expect(screen.getByTestId('delivery-accepted-24h').textContent).toContain('3.4');
  expect(screen.getByTestId('delivery-error-code').textContent).toBe('failed_fetching_sqs_events');
  expect(screen.getByTestId('delivery-error-hint').textContent).toContain('sqs:ReceiveMessage');
  expect(screen.getByTestId('delivery-errors-24h').textContent).toContain('4');
});

it('shows the pull source configuration as failing while the collector errors', async () => {
  calls.getStatus.mockResolvedValue({ source_id: 'lsrc_1', route_key: 'k', state: 'receiving', push_capable: false, events_24h: 0, active_tokens: 0, tokens: [] });
  calls.getSourceConfig.mockResolvedValue({ id: 'sc1', name: 'CloudTrail bucket', config_type: 'aws_s3', enabled: true, deployed: true, connection_config: {}, created_at: '', updated_at: '' });
  renderPanel('sc1');
  await waitFor(() => expect(screen.getByTestId('delivery-row-pull').textContent).toContain('CloudTrail bucket'));
  expect(screen.getByTestId('delivery-row-pull').textContent).toContain('failing');
  expect(screen.queryByTestId('delivery-row-push')).toBeNull();
  // NAN-4941: the config opens under Log Sources, not the retired Source Configs page.
  expect(screen.getByRole('link', { name: 'CloudTrail bucket' }).getAttribute('href')).toBe('/ingestion/log-sources/inputs/sc1');
});

it('lists a push listener whose routing rule targets this source, linked to its detail (NAN-4941)', async () => {
  calls.getStatus.mockResolvedValue({ source_id: 'lsrc_1', route_key: 'k', state: 'idle', push_capable: false, events_24h: 0, active_tokens: 0, tokens: [] });
  calls.listSourceConfigs.mockResolvedValue([
    { id: 'sc_http', name: 'Edge HTTP', config_type: 'http', enabled: true, deployed: true, connection_config: {}, created_at: '', updated_at: '' },
    { id: 'sc_vec', name: 'Fleet vector', config_type: 'vector', enabled: true, deployed: false, connection_config: {}, created_at: '', updated_at: '' },
    { id: 'sc_s3', name: 'Bucket', config_type: 'aws_s3', enabled: true, deployed: true, connection_config: {}, created_at: '', updated_at: '' },
  ]);
  calls.listRoutingRules.mockImplementation(async (id: string) =>
    id === 'sc_http' ? [{ id: 'r1', target_source_type: 'acme_fw' }] : id === 'sc_vec' ? [{ id: 'r2', target_source_type: 'other' }] : [{ id: 'r3', target_source_type: 'acme_fw' }],
  );
  renderPanel(undefined, ['acme_fw']);
  const rows = await screen.findAllByTestId('delivery-row-listener');
  expect(rows).toHaveLength(1);
  expect(rows[0].textContent).toContain('HTTP listener');
  expect(screen.getByRole('link', { name: 'Edge HTTP' }).getAttribute('href')).toBe('/ingestion/log-sources/inputs/sc_http');
  // Pull configs are never asked for listener rules.
  expect(calls.listRoutingRules).not.toHaveBeenCalledWith('sc_s3');
});
