// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-5318: a source dispatched from the splunk_hec routing profile is push, receiving — never "Pull · paused". */
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
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

it('renders a disabled HEC routing profile as a receiving push path, not pull paused', async () => {
  calls.getStatus.mockResolvedValue({ source_id: 'lsrc_1', route_key: 'apache_access', state: 'receiving', push_capable: true, events_24h: 7, active_tokens: 0,
    last_seen: new Date().toISOString(), tokens: [] });
  const hec = { id: 'hec', name: 'Splunk HEC', config_type: 'splunk_hec', enabled: false, deployed: false, connection_config: {}, created_at: '', updated_at: '' };
  calls.getSourceConfig.mockResolvedValue(hec);
  calls.listSourceConfigs.mockResolvedValue([hec]);
  calls.listRoutingRules.mockResolvedValue([{ id: 'r', target_source_type: 'apache_access' }]);
  renderPanel('hec', ['apache_access']);
  const rows = await screen.findAllByTestId('delivery-row-listener');
  // Listed once (dispatch + routing rule dedupe), as push.
  expect(rows).toHaveLength(1);
  expect(rows[0].textContent).toContain('Push · HEC listener');
  expect(rows[0].textContent).toContain('receiving');
  expect(rows[0].textContent).not.toContain('paused');
  expect(rows[0].textContent).not.toContain('not deployed');
  expect(screen.getByTestId('delivery-hec-profile-off')).toBeTruthy();
  expect(screen.queryByTestId('delivery-row-pull')).toBeNull();
});
