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
const calls = vi.hoisted(() => ({ listFeeds: vi.fn(), listSpecs: vi.fn(), create: vi.fn(), plan: vi.fn(), setEnabled: vi.fn(), adoptSpec: vi.fn() }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => perms.granted === null || perms.granted.has(p) }),
}));
const toasts = vi.hoisted(() => ({ toast: vi.fn() }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: toasts.toast }) }));
const feed = {
  id: 'cfeed_1', name: 'Okta prod', connector: 'okta_system_log', source_type: 'okta', enabled: true, running: false,
  schedule: null, effective_schedule: '*/5 * * * *', config: {}, credential_id: 'cred_okta', max_run_secs: null,
  next_run_at: new Date().toISOString(), consecutive_failures: 0, last_run_at: null, last_status: 'success',
  last_error: null, last_success_at: new Date().toISOString(), created_at: '',
};
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error {
    constructor(message: string, public code = 'ERROR', public details?: unknown) { super(message); }
  },
  api: {
    connectorFeeds: { list: calls.listFeeds, listSpecs: calls.listSpecs, create: calls.create, plan: calls.plan, setEnabled: calls.setEnabled, adoptSpec: calls.adoptSpec },
    listCredentials: async () => ({
      credentials: [
        { id: 'cred_okta', name: 'Okta token', provider: 'okta', active_version: 2, created_at: '', updated_at: '' },
        { id: 'cred_aws', name: 'AWS prod', provider: 'aws_s3', active_version: 1, created_at: '', updated_at: '' },
      ],
    }),
    listSourceConfigs: async () => [],
  },
}));
import { ApiClientError } from '@/lib/api';
import { ConnectorFeeds } from './ConnectorFeeds';

const identitySpec = {
  name: 'okta_users', display_name: 'Okta users', kind: 'identity', credential_provider: 'okta', source_type: 'identity',
  schedule: '0 * * * *', config_fields: ['OKTA_DOMAIN', 'identity_allow_shrink'],
  optional_config_fields: ['identity_allow_shrink'], credential_fields: ['api_token'],
};

beforeEach(() => {
  calls.create.mockResolvedValue({ ...feed, id: 'cfeed_2' });
  calls.plan.mockResolvedValue({ lanes: [], log_sources: [], creates: 0, changes_log_sources: false, required_permissions: [], missing_permissions: [] });
  calls.adoptSpec.mockResolvedValue({ adopted: true, checkpoints_reset: 0 });
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
  fireEvent.change(within(sheet).getByLabelText('Domain'), { target: { value: 'acme.okta.com' } });
  fireEvent.change(sheet.querySelector('input[type="password"]') as HTMLInputElement, { target: { value: 's3cret' } });
  // NAN-5903: the cron placeholder reads as a default, not a filled-in value.
  fireEvent.change(within(sheet).getByPlaceholderText('Default: every 5 minutes'), { target: { value: '*/10 * * * *' } });
  expect(create.disabled).toBe(false);
  fireEvent.click(create);

  await vi.waitFor(() => expect(calls.create).toHaveBeenCalledTimes(1));
  expect(calls.create.mock.calls[0][0]).toEqual({
    name: 'Okta EU', connector: 'okta_system_log', config: { domain: 'acme.okta.com' },
    // Nothing to set up was confirmed, so no consent is sent (P2-3): a source
    // that vanished since the plan is refused by the server, not set up unasked.
    credentials: { api_token: 's3cret' }, schedule: '*/10 * * * *', set_up_log_sources: false,
  });
  expect(calls.plan).toHaveBeenCalledWith('okta_system_log', { domain: 'acme.okta.com' });
  await vi.waitFor(() => expect(screen.queryByTestId('new-pull-feed-sheet')).toBeNull());
});

it('renders identity_allow_shrink as a checkbox, omitted unless checked (NAN-4970)', async () => {
  calls.listSpecs.mockResolvedValue([identitySpec]);
  renderPage();
  const sheet = await openFlyout();
  expect(within(sheet).getByText(/Directory feeds copy users/)).toBeTruthy();
  // No free-text field for the engine flag; OKTA_DOMAIN stays a text field.
  expect(within(sheet).queryByText('identity_allow_shrink', { selector: 'label' })).toBeNull();
  expect(within(sheet).getByLabelText('Okta domain')).toBeTruthy();
  const box = within(sheet).getByRole('checkbox', { name: /drop more than half/ });
  expect(box.getAttribute('aria-checked')).toBe('false');

  fireEvent.change(within(sheet).getByPlaceholderText('Okta production'), { target: { value: 'Okta directory' } });
  fireEvent.change(within(sheet).getByLabelText('Okta domain'), { target: { value: 'acme.okta.com' } });
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
  fireEvent.change(within(sheet).getByLabelText('Okta domain'), { target: { value: 'acme.okta.com' } });
  fireEvent.change(sheet.querySelector('input[type="password"]') as HTMLInputElement, { target: { value: 'tok' } });
  fireEvent.click(within(sheet).getByRole('checkbox', { name: /drop more than half/ }));
  fireEvent.click(within(sheet).getByRole('button', { name: /Create feed/ }));
  await vi.waitFor(() => expect(calls.create).toHaveBeenCalledTimes(1));
  expect(calls.create.mock.calls[0][0].config).toEqual({ OKTA_DOMAIN: 'acme.okta.com', identity_allow_shrink: true });
});

// NAN-5903: Google Workspace, as the server describes it.
const gwsSpec = {
  name: 'google_workspace', display_name: 'Google Workspace audit (service account, domain-wide delegation)', kind: 'collector',
  credential_provider: 'google_workspace', source_type: 'gws_{{item}}', schedule: '*/5 * * * *',
  config_fields: ['ADMIN_EMAIL', 'STREAMS'], optional_config_fields: [], credential_fields: ['CLIENT_EMAIL', 'PRIVATE_KEY'],
  parsers: ['google_workspace_ocsf'],
  config_field_info: [
    { key: 'ADMIN_EMAIL', label: 'Admin email to act as', help: 'The email of a Workspace admin.', placeholder: 'admin@example.com', choices: [] },
    {
      key: 'STREAMS', label: 'Which Workspace apps to collect', help: 'Each app is collected on its own.', placeholder: null,
      choices: [
        { value: 'login', label: 'Sign-ins', default: true },
        { value: 'admin', label: 'Admin console changes', default: true },
        { value: 'saml', label: 'SAML app sign-ins', default: true },
        { value: 'calendar', label: 'Calendar', default: false },
      ],
    },
  ],
  credential_field_info: [],
};

const gwsPlan = {
  lanes: ['gws_admin', 'gws_login', 'gws_saml'],
  log_sources: [
    { action: 'reuse', log_source_id: 'ls_1', log_source_name: 'My login source', lanes: ['gws_login'], added_lanes: [], parser: null },
    { action: 'create', log_source_id: null, log_source_name: 'Google Workspace Audit (OCSF)', lanes: ['gws_admin', 'gws_saml'], added_lanes: ['gws_admin', 'gws_saml'], parser: 'google_workspace_ocsf' },
  ],
  creates: 1, changes_log_sources: true, required_permissions: ['parser_repositories:import'], missing_permissions: [],
};

async function fillGws() {
  calls.listSpecs.mockResolvedValue([gwsSpec]);
  renderPage();
  const sheet = await openFlyout();
  fireEvent.change(within(sheet).getByPlaceholderText('Okta production'), { target: { value: 'Workspace' } });
  fireEvent.change(within(sheet).getByLabelText('Admin email to act as'), { target: { value: 'admin@acme.test' } });
  fireEvent.change(sheet.querySelector('textarea') as HTMLTextAreaElement, { target: { value: '{"type":"service_account"}' } });
  return sheet;
}

it('shows Streams as a plain-English multi-select with the defaults ticked, never the raw key', async () => {
  const sheet = await fillGws();
  expect(within(sheet).queryByText('STREAMS')).toBeNull();
  expect(within(sheet).queryByText('ADMIN_EMAIL')).toBeNull();
  expect(within(sheet).getByText('Which Workspace apps to collect')).toBeTruthy();
  expect(within(sheet).getByRole('button', { name: 'About Which Workspace apps to collect' })).toBeTruthy();
  const group = within(sheet).getByRole('group', { name: 'Which Workspace apps to collect' });
  const box = (name: string) => within(group).getByRole('checkbox', { name: new RegExp(name) });
  expect(box('Sign-ins').getAttribute('aria-checked')).toBe('true');
  expect(box('SAML app').getAttribute('aria-checked')).toBe('true');
  expect(box('Calendar').getAttribute('aria-checked')).toBe('false');
  fireEvent.click(box('Calendar'));
  fireEvent.click(box('Admin console'));
  // No jargon banner.
  expect(within(sheet).queryByText(/HEC log source first/)).toBeNull();
  // Nothing ticked: create stays off.
  for (const name of ['Sign-ins', 'SAML app', 'Calendar']) fireEvent.click(box(name));
  expect((within(sheet).getByRole('button', { name: /Create feed/ }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(box('Calendar'));
  fireEvent.click(within(sheet).getByRole('button', { name: /Create feed/ }));
  await vi.waitFor(() => expect(calls.plan).toHaveBeenCalledTimes(1));
  expect(calls.plan.mock.calls[0][1]).toEqual({ ADMIN_EMAIL: 'admin@acme.test', STREAMS: 'calendar' });
});

it('confirms the log sources it will set up, then creates the feed and says what it made', async () => {
  calls.plan.mockResolvedValue(gwsPlan);
  calls.create.mockResolvedValue({ id: 'cfeed_9', credential_id: 'cred_9', log_sources: gwsPlan.log_sources.map((s) => ({ ...s, log_source_id: s.log_source_id ?? 'ls_new' })) });
  const sheet = await fillGws();
  fireEvent.click(within(sheet).getByRole('button', { name: /Create feed/ }));
  const confirm = await screen.findByTestId('feed-setup-confirm');
  const dialog = confirm.closest('[role="alertdialog"]') as HTMLElement;
  expect(within(dialog).getByText('This will also create 1 log source')).toBeTruthy();
  expect(within(confirm).getByText(/Create the log source "Google Workspace Audit \(OCSF\)" from the google_workspace_ocsf parser, for gws_admin, gws_saml\./)).toBeTruthy();
  expect(within(confirm).getByText(/Already set up: "My login source" \(gws_login\)/)).toBeTruthy();
  expect(calls.create).not.toHaveBeenCalled();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Set up and continue' }));
  await vi.waitFor(() => expect(calls.create).toHaveBeenCalledTimes(1));
  expect(calls.create.mock.calls[0][0].set_up_log_sources).toBe(true);
  await vi.waitFor(() => expect(toasts.toast).toHaveBeenCalled());
  const done = toasts.toast.mock.calls.at(-1)![0];
  expect(done.title).toBe('Pull feed created');
  expect(done.description).toContain('Created the log source "Google Workspace Audit (OCSF)" for gws_admin, gws_saml.');
});

it('cancelling the confirm creates nothing', async () => {
  calls.plan.mockResolvedValue(gwsPlan);
  const sheet = await fillGws();
  fireEvent.click(within(sheet).getByRole('button', { name: /Create feed/ }));
  const dialog = (await screen.findByTestId('feed-setup-confirm')).closest('[role="alertdialog"]') as HTMLElement;
  fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
  await vi.waitFor(() => expect(screen.queryByTestId('feed-setup-confirm')).toBeNull());
  expect(calls.create).not.toHaveBeenCalled();
});

it('says which permission is missing and does not offer to set up', async () => {
  calls.plan.mockResolvedValue({ ...gwsPlan, missing_permissions: ['parser_repositories:import'] });
  const sheet = await fillGws();
  fireEvent.click(within(sheet).getByRole('button', { name: /Create feed/ }));
  const confirm = await screen.findByTestId('feed-setup-confirm');
  expect(within(confirm).getByRole('alert').textContent).toContain('also takes the parser_repositories:import permission');
  const dialog = confirm.closest('[role="alertdialog"]') as HTMLElement;
  expect((within(dialog).getByRole('button', { name: 'Set up and continue' }) as HTMLButtonElement).disabled).toBe(true);
});

it('shows a refusal (no matching parser) in plain English', async () => {
  calls.plan.mockRejectedValue(new Error('nano could not find the Google Workspace audit parser (google_workspace_ocsf) in your parser catalog.'));
  const sheet = await fillGws();
  fireEvent.click(within(sheet).getByRole('button', { name: /Create feed/ }));
  await vi.waitFor(() => expect(toasts.toast).toHaveBeenCalled());
  expect(toasts.toast.mock.calls.at(-1)![0]).toMatchObject({ title: 'Could not create the feed', variant: 'destructive' });
  expect(calls.create).not.toHaveBeenCalled();
});

it('a resume refused for missing log sources offers Fix setup, which confirms the setup and resumes with consent', async () => {
  const paused = { ...feed, enabled: false, config: { OKTA_DOMAIN: 'acme.okta.com' } };
  calls.listFeeds.mockResolvedValue([paused]);
  calls.setEnabled.mockRejectedValueOnce(
    new ApiClientError('Some log sources this feed needs are missing, so its events to `okta` would be dropped.', 'LOG_SOURCES_MISSING'),
  );
  calls.plan.mockResolvedValue({
    lanes: ['okta'], creates: 1, changes_log_sources: true, required_permissions: [], missing_permissions: [],
    log_sources: [{ action: 'create', log_source_id: null, log_source_name: 'Okta (OCSF)', lanes: ['okta'], added_lanes: ['okta'], parser: 'okta_ocsf' }],
  });
  calls.setEnabled.mockResolvedValue({ ...paused, enabled: true });
  renderPage();
  const region = await screen.findByTestId('pull-feeds-region');
  const row = (await within(region).findByText('Okta prod')).closest('tr') as HTMLElement;
  fireEvent.click(within(row).getByRole('button', { name: /Resume/ }));
  await vi.waitFor(() => expect(calls.setEnabled).toHaveBeenCalledWith('cfeed_1', true));
  const banner = await screen.findByTestId('feed-fix-setup');
  expect(banner.textContent).toContain('Some log sources this feed needs are missing');
  expect(calls.plan).not.toHaveBeenCalled();
  fireEvent.click(within(banner).getByRole('button', { name: 'Fix setup' }));
  const confirm = await screen.findByTestId('feed-setup-confirm');
  expect(calls.plan).toHaveBeenCalledWith('okta_system_log', { OKTA_DOMAIN: 'acme.okta.com' });
  expect(confirm.textContent).toContain('Create the log source "Okta (OCSF)" from the okta_ocsf parser, for okta.');
  fireEvent.click(screen.getByRole('button', { name: 'Set up and continue' }));
  await vi.waitFor(() => expect(calls.setEnabled).toHaveBeenCalledWith('cfeed_1', true, true));
  await vi.waitFor(() => expect(screen.queryByTestId('feed-fix-setup')).toBeNull());
});

it('?new=<connector> opens New pull feed with that connector preselected (the Marketplace hop)', async () => {
  calls.listSpecs.mockResolvedValue([
    { name: 'okta_system_log', display_name: 'Okta System Log', credential_provider: 'okta', source_type: 'okta', schedule: '*/5 * * * *', config_fields: ['domain'], optional_config_fields: [], credential_fields: ['api_token'] },
    gwsSpec,
  ]);
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/ingestion/log-sources/pull-feeds?new=google_workspace']}><ConnectorFeeds /></MemoryRouter>
    </QueryClientProvider>,
  );
  const sheet = await screen.findByTestId('new-pull-feed-sheet');
  expect(within(sheet).getByText('Which Workspace apps to collect')).toBeTruthy();
  expect(within(sheet).getAllByRole('combobox')[0].textContent).toContain('Google Workspace audit');
});

it('?fix=<feed id>&action=adopt repeats the adopt with consent, not a resume', async () => {
  calls.listFeeds.mockResolvedValue([{ ...feed, enabled: true, spec_update_available: true, config: {} }]);
  calls.plan.mockResolvedValue({ lanes: ['okta'], log_sources: [], creates: 0, changes_log_sources: false, required_permissions: [], missing_permissions: [] });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/ingestion/log-sources/pull-feeds?fix=cfeed_1&action=adopt']}><ConnectorFeeds /></MemoryRouter>
    </QueryClientProvider>,
  );
  const banner = await screen.findByTestId('feed-fix-setup');
  fireEvent.click(within(banner).getByRole('button', { name: 'Fix setup' }));
  await vi.waitFor(() => expect(calls.adoptSpec).toHaveBeenCalledWith('cfeed_1', false));
  expect(calls.setEnabled).not.toHaveBeenCalled();
});

it('?fix=<feed id> offers Fix setup for that feed (the Marketplace hop)', async () => {
  calls.listFeeds.mockResolvedValue([{ ...feed, enabled: false }]);
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/ingestion/log-sources/pull-feeds?fix=cfeed_1']}><ConnectorFeeds /></MemoryRouter>
    </QueryClientProvider>,
  );
  const banner = await screen.findByTestId('feed-fix-setup');
  expect(within(banner).getByRole('button', { name: 'Fix setup' })).toBeTruthy();
});

it('pausing never asks about log sources', async () => {
  calls.setEnabled.mockResolvedValue({ ...feed, enabled: false });
  renderPage();
  const region = await screen.findByTestId('pull-feeds-region');
  const row = (await within(region).findByText('Okta prod')).closest('tr') as HTMLElement;
  fireEvent.click(within(row).getByRole('button', { name: /Pause/ }));
  await vi.waitFor(() => expect(calls.setEnabled).toHaveBeenCalledWith('cfeed_1', false));
  expect(calls.plan).not.toHaveBeenCalled();
});

it('shows that setting up log sources can take a few minutes while it runs', async () => {
  calls.plan.mockResolvedValue(gwsPlan);
  let finish: (v: unknown) => void = () => {};
  calls.create.mockReturnValue(new Promise((resolve) => { finish = resolve; }));
  const sheet = await fillGws();
  fireEvent.click(within(sheet).getByRole('button', { name: /Create feed/ }));
  const confirm = await screen.findByTestId('feed-setup-confirm');
  expect(within(confirm).queryByTestId('feed-setup-progress')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Set up and continue' }));
  const progress = await screen.findByTestId('feed-setup-progress');
  expect(progress.textContent).toBe('Setting up log sources… this can take a few minutes.');
  expect(progress.getAttribute('role')).toBe('status');
  finish({ id: 'cfeed_9', credential_id: null, log_sources: [] });
  await vi.waitFor(() => expect(screen.queryByTestId('feed-setup-progress')).toBeNull());
});
