// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4941: Log Sources → Cloud pull owns pull-source setup and the cloud
 * credentials they read with (the retired Source Configs and Credentials pages).
 */
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const perms = vi.hoisted(() => ({ granted: null as Set<string> | null }));
const calls = vi.hoisted(() => ({
  rotateCredential: vi.fn(),
  listCredentialVersions: vi.fn(async () => ({ versions: [] })),
  listFeeds: vi.fn(async () => [] as unknown[]),
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => perms.granted === null || perms.granted.has(p) }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error { status?: number },
  api: {
    listSourceConfigs: async () => [
      { id: 'a', name: 'CloudTrail bucket', config_type: 'aws_s3', enabled: true, deployed: true, events_24h: 1200, connection_config: {}, created_at: '', updated_at: '' },
      { id: 'b', name: 'Audit topic', config_type: 'kafka', enabled: true, deployed: false, connection_config: {}, created_at: '', updated_at: '' },
      { id: 'c', name: 'HEC listener', config_type: 'splunk_hec', enabled: true, deployed: true, connection_config: {}, created_at: '', updated_at: '' },
    ],
    listCredentials: async () => ({
      credentials: [
        { id: 'cred_aws', name: 'AWS prod', provider: 'aws_s3', active_version: 2, created_at: '', updated_at: '' },
        { id: 'cred_okta', name: 'Okta prod', provider: 'okta', active_version: 1, created_at: '', updated_at: '' },
      ],
    }),
    connectorFeeds: {
      list: calls.listFeeds,
      listSpecs: async () => [{ name: 'okta_system_log', display_name: 'Okta System Log', credential_provider: 'okta', source_type: 'okta', schedule: '*/2 * * * *', config_fields: ['OKTA_DOMAIN'], optional_config_fields: [], credential_fields: ['API_TOKEN'] }],
    },
    rotateCredential: calls.rotateCredential,
    listCredentialVersions: calls.listCredentialVersions,
  },
}));
import { CloudPull } from './CloudPull';
import { ingestionHomeFor } from '@/lib/ingestion-paths';
afterEach(() => {
  cleanup();
  perms.granted = null;
});

function renderPage(path = '/ingestion/log-sources/cloud-pull') {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={[path]}><CloudPull /></MemoryRouter>
    </QueryClientProvider>,
  );
}

it('lists only pull transports with deploy actions, and the Log Sources tabs', async () => {
  renderPage();
  const sources = await screen.findByTestId('cloud-pull-sources');
  expect(await within(sources).findByText('CloudTrail bucket')).toBeTruthy();
  expect(within(sources).getByText('Audit topic')).toBeTruthy();
  expect(within(sources).queryByText('HEC listener')).toBeNull();
  expect(within(sources).getByRole('button', { name: /Add cloud pull/ })).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Cloud pull' }).getAttribute('aria-current')).toBe('page');
  expect(screen.getByRole('link', { name: 'Credentials' }).getAttribute('href')).toBe('/ingestion/log-sources/credentials');
  expect(screen.getByRole('link', { name: 'Pull feeds' }).getAttribute('href')).toBe('/ingestion/log-sources/pull-feeds');
});

it('shows the cloud credential store scoped to cloud providers, with the add form', async () => {
  renderPage();
  const store = await screen.findByTestId('credentials-manager');
  expect(await within(store).findByText('AWS prod')).toBeTruthy();
  // Connector credentials belong to Pull feeds.
  expect(within(store).queryByText('Okta prod')).toBeNull();
  fireEvent.click(within(store).getByRole('button', { name: /Add credential/ }));
  expect(await screen.findByTestId('add-credential-sheet')).toBeTruthy();
});

it('opens a credential named by ?cred= (the old /ingestion/credentials/:id link)', async () => {
  renderPage('/ingestion/log-sources/cloud-pull?cred=cred_aws');
  const inspector = await screen.findByTestId('credential-inspector');
  await waitFor(() => expect(within(inspector).getAllByText('AWS prod').length).toBeGreaterThan(0));
  expect(within(inspector).getByTestId('credential-secret-masked').textContent).toContain('••••');
});

it('explains SQS at-least-once delays for both rotate and rollback', async () => {
  renderPage('/ingestion/log-sources/cloud-pull?cred=cred_aws');
  const inspector = await screen.findByTestId('credential-inspector');
  fireEvent.click(within(inspector).getByRole('button', { name: /^Rotate$/ }));
  expect(await screen.findByText(/visibility timeout \(300 seconds by default\)/)).toBeTruthy();
  expect(screen.getByText(/messages are delayed, not lost/)).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  const reopened = await screen.findByTestId('credential-inspector');
  fireEvent.click(within(reopened).getByRole('button', { name: 'Versions' }));
  expect(await within(reopened).findByText(/rotate or rollback can delay in-flight messages/)).toBeTruthy();
});

it('keeps each section behind its own permission', async () => {
  perms.granted = new Set(['credentials:view']);
  renderPage();
  expect(await screen.findByTestId('credentials-manager')).toBeTruthy();
  expect(screen.queryByTestId('cloud-pull-sources')).toBeNull();
});

it('lands a credentials-only role on a home that shows all its credentials, and it can rotate an Okta credential there (NAN-4941 review P1)', async () => {
  perms.granted = new Set(['credentials:view', 'credentials:rotate']);
  const has = (p: string) => perms.granted!.has(p);
  expect(ingestionHomeFor(has)).toBe('/ingestion/log-sources/cloud-pull');
  calls.rotateCredential.mockResolvedValue({
    credential: { id: 'cred_okta', name: 'Okta prod', provider: 'okta', active_version: 2 },
    version: { version_number: 2 },
    redeploy: null,
  });
  renderPage();
  // Pull feeds stays reachable as a tab; Cloud pull shows connector credentials too.
  expect(screen.getByRole('link', { name: 'Pull feeds' })).toBeTruthy();
  const store = await screen.findByTestId('credentials-manager');
  expect(await within(store).findByText('AWS prod')).toBeTruthy();
  fireEvent.click(await within(store).findByText('Okta prod'));
  const inspector = await screen.findByTestId('credential-inspector');
  fireEvent.click(within(inspector).getByRole('button', { name: /^Rotate$/ }));
  const token = await screen.findByLabelText('API_TOKEN');
  fireEvent.change(token, { target: { value: 'okta-new-token' } });
  const submit = screen.getByRole('button', { name: /Rotate & activate v2/ });
  await waitFor(() => expect((submit as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(submit);
  await waitFor(() => expect(calls.rotateCredential).toHaveBeenCalledWith('cred_okta', expect.objectContaining({ credentials: { API_TOKEN: 'okta-new-token' } })));
  // Feed data needs log_sources:view and is never asked for.
  expect(calls.listFeeds).not.toHaveBeenCalled();
});
