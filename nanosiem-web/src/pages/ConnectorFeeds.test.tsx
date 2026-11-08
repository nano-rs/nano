// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4941: Pull feeds is a Log Sources tab that owns its vendor secrets: each
 * feed shows its credential masked with an inline Rotate, and the connector
 * credentials are managed below the list.
 *
 * NAN-4970: "+ New pull feed" opens the right-side Sheet flyout (not a centered
 * dialog), and `identity_allow_shrink` is a checkbox, not a free-text field.
 */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const perms = vi.hoisted(() => ({ granted: null as Set<string> | null }));
const calls = vi.hoisted(() => ({ listFeeds: vi.fn(), listSpecs: vi.fn(), create: vi.fn() }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => perms.granted === null || perms.granted.has(p) }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
const feed = {
  id: 'cfeed_1', name: 'Okta prod', connector: 'okta_system_log', source_type: 'okta', enabled: true, running: false,
  schedule: null, effective_schedule: '*/5 * * * *', config: {}, credential_id: 'cred_okta', max_run_secs: null,
  next_run_at: new Date().toISOString(), consecutive_failures: 0, last_run_at: null, last_status: 'success',
  last_error: null, last_success_at: new Date().toISOString(), created_at: '',
};
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error { status?: number },
  api: {
    connectorFeeds: { list: calls.listFeeds, listSpecs: calls.listSpecs, create: calls.create },
    listCredentials: async () => ({
      credentials: [
        { id: 'cred_okta', name: 'Okta token', provider: 'okta', active_version: 2, created_at: '', updated_at: '' },
        { id: 'cred_aws', name: 'AWS prod', provider: 'aws_s3', active_version: 1, created_at: '', updated_at: '' },
      ],
    }),
    listSourceConfigs: async () => [],
  },
}));
import { ConnectorFeeds } from './ConnectorFeeds';

const identitySpec = {
  name: 'okta_users', display_name: 'Okta users', kind: 'identity', credential_provider: 'okta', source_type: 'identity',
  schedule: '0 * * * *', config_fields: ['OKTA_DOMAIN', 'identity_allow_shrink'],
  optional_config_fields: ['identity_allow_shrink'], credential_fields: ['api_token'],
};

beforeEach(() => {
  calls.create.mockResolvedValue({ ...feed, id: 'cfeed_2' });
  calls.listFeeds.mockResolvedValue([feed]);
  calls.listSpecs.mockResolvedValue([{ name: 'okta_system_log', display_name: 'Okta System Log', credential_provider: 'okta', source_type: 'okta', schedule: '*/5 * * * *', config_fields: ['domain'], optional_config_fields: [], credential_fields: ['api_token'] }]);
});
afterEach(() => {
  cleanup();
  perms.granted = null;
  vi.clearAllMocks();
});

function renderPage() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/ingestion/log-sources/pull-feeds']}><ConnectorFeeds /></MemoryRouter>
    </QueryClientProvider>,
  );
}

it('renders as the Pull feeds tab with each feed credential masked and rotatable in place', async () => {
  renderPage();
  expect(screen.getByRole('link', { name: 'Pull feeds' }).getAttribute('aria-current')).toBe('page');
  const region = await screen.findByTestId('pull-feeds-region');
  const row = (await within(region).findByText('Okta prod')).closest('tr') as HTMLElement;
  expect(await within(row).findByText('Okta token')).toBeTruthy();
  expect(within(row).getByLabelText('Secret hidden').textContent).toContain('••••');
  fireEvent.click(within(row).getByRole('button', { name: 'Rotate' }));
  expect(await screen.findByRole('button', { name: /Rotate & activate v3/ })).toBeTruthy();
});

it('manages connector credentials only, with no standalone add (secrets are entered with the feed)', async () => {
  renderPage();
  const store = await screen.findByTestId('credentials-manager');
  expect(await within(store).findByText('Okta token')).toBeTruthy();
  expect(within(store).queryByText('AWS prod')).toBeNull();
  expect(within(store).queryByRole('button', { name: /Add credential/ })).toBeNull();
});

it('opens for a credentials-only role with the connector credentials and no feed list (NAN-4941 review P1)', async () => {
  perms.granted = new Set(['credentials:view', 'credentials:rotate']);
  renderPage();
  expect(screen.getByRole('link', { name: 'Pull feeds' }).getAttribute('aria-current')).toBe('page');
  const store = await screen.findByTestId('credentials-manager');
  expect(await within(store).findByText('Okta token')).toBeTruthy();
  expect(screen.queryByTestId('pull-feeds-region')).toBeNull();
  expect(screen.queryByRole('button', { name: /New pull feed/ })).toBeNull();
  expect(calls.listFeeds).not.toHaveBeenCalled();
});

async function openFlyout() {
  const open = (await screen.findByRole('button', { name: /New pull feed/ })) as HTMLButtonElement;
  await vi.waitFor(() => expect(open.disabled).toBe(false)); // enabled once the specs load
  fireEvent.click(open);
  const sheet = await screen.findByTestId('new-pull-feed-sheet');
  return sheet;
}

it('opens New pull feed as a right-side flyout and creates the feed with every field (NAN-4970)', async () => {
  renderPage();
  const sheet = await openFlyout();
  expect(sheet.getAttribute('role')).toBe('dialog');
  // The shared Sheet's right-side variant, not the centered Dialog.
  expect(sheet.className).toContain('right-0');
  expect(sheet.className).not.toContain('translate-x-[-50%]');
  expect(within(sheet).getByText('New pull feed')).toBeTruthy();

  const create = within(sheet).getByRole('button', { name: /Create feed/ }) as HTMLButtonElement;
  expect(create.disabled).toBe(true); // name required
  fireEvent.change(within(sheet).getByPlaceholderText('Okta production'), { target: { value: '  Okta EU  ' } });
  const domain = within(sheet).getByText('domain').parentElement!.querySelector('input') as HTMLInputElement;
  fireEvent.change(domain, { target: { value: 'acme.okta.com' } });
  fireEvent.change(sheet.querySelector('input[type="password"]') as HTMLInputElement, { target: { value: 's3cret' } });
  fireEvent.change(within(sheet).getByPlaceholderText('*/5 * * * *'), { target: { value: '*/10 * * * *' } });
  expect(create.disabled).toBe(false);
  fireEvent.click(create);

  await vi.waitFor(() => expect(calls.create).toHaveBeenCalledTimes(1));
  expect(calls.create.mock.calls[0][0]).toEqual({
    name: 'Okta EU', connector: 'okta_system_log', config: { domain: 'acme.okta.com' },
    credentials: { api_token: 's3cret' }, schedule: '*/10 * * * *',
  });
  await vi.waitFor(() => expect(screen.queryByTestId('new-pull-feed-sheet')).toBeNull());
});

it('renders identity_allow_shrink as a checkbox, omitted unless checked (NAN-4970)', async () => {
  calls.listSpecs.mockResolvedValue([identitySpec]);
  renderPage();
  const sheet = await openFlyout();
  expect(within(sheet).getByText(/Directory feeds sync users/)).toBeTruthy();
  // No free-text field for the engine flag; OKTA_DOMAIN stays a text field.
  expect(within(sheet).queryByText('identity_allow_shrink', { selector: 'label' })).toBeNull();
  expect(within(sheet).getByText('OKTA_DOMAIN')).toBeTruthy();
  const box = within(sheet).getByRole('checkbox', { name: /drop more than half/ });
  expect(box.getAttribute('aria-checked')).toBe('false');

  fireEvent.change(within(sheet).getByPlaceholderText('Okta production'), { target: { value: 'Okta directory' } });
  const domain = within(sheet).getByText('OKTA_DOMAIN').parentElement!.querySelector('input') as HTMLInputElement;
  fireEvent.change(domain, { target: { value: 'acme.okta.com' } });
  fireEvent.change(sheet.querySelector('input[type="password"]') as HTMLInputElement, { target: { value: 'tok' } });
  fireEvent.click(within(sheet).getByRole('button', { name: /Create feed/ }));
  await vi.waitFor(() => expect(calls.create).toHaveBeenCalledTimes(1));
  expect(calls.create.mock.calls[0][0].config).toEqual({ OKTA_DOMAIN: 'acme.okta.com' });
});

it('sends identity_allow_shrink as boolean true when checked (NAN-4970)', async () => {
  calls.listSpecs.mockResolvedValue([identitySpec]);
  renderPage();
  const sheet = await openFlyout();
  fireEvent.change(within(sheet).getByPlaceholderText('Okta production'), { target: { value: 'Okta directory' } });
  const domain = within(sheet).getByText('OKTA_DOMAIN').parentElement!.querySelector('input') as HTMLInputElement;
  fireEvent.change(domain, { target: { value: 'acme.okta.com' } });
  fireEvent.change(sheet.querySelector('input[type="password"]') as HTMLInputElement, { target: { value: 'tok' } });
  fireEvent.click(within(sheet).getByRole('checkbox', { name: /drop more than half/ }));
  fireEvent.click(within(sheet).getByRole('button', { name: /Create feed/ }));
  await vi.waitFor(() => expect(calls.create).toHaveBeenCalledTimes(1));
  expect(calls.create.mock.calls[0][0].config).toEqual({ OKTA_DOMAIN: 'acme.okta.com', identity_allow_shrink: true });
});
