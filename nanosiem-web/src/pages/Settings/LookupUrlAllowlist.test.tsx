// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { LookupUrlAllowlist } from './LookupUrlAllowlist';
import { browserTenantRuntime } from '@/lib/tenant-runtime';

const mock = vi.hoisted(() => ({
  shared: true,
  admin: true,
  viewUsers: true,
  listUsers: vi.fn(),
  get: vi.fn(),
  add: vi.fn(),
  remove: vi.fn(),
}));
vi.mock('@/lib/api', () => ({
  api: { lookupUrlAllowlist: mock, listUsers: mock.listUsers },
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { deployment_mode: mock.shared ? 'enterprise_shared' : 'open' },
    hasPermission: (permission: string) =>
      permission === 'users:view'
        ? mock.viewUsers
        : mock.admin && ['settings:system', 'audit:view'].includes(permission),
  }),
}));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }));
const entry = {
  host: 'intel.example.com',
  note: 'Daily intel',
  created_by: '11111111-2222-3333-4444-555555555555',
  created_at: '2026-10-02T12:00:00Z',
};
const creator = {
  id: entry.created_by,
  name: 'Ana Analyst',
  email: 'ana@example.test',
};
function queryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
}
function page(client = queryClient()) {
  const tree = () => (
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <LookupUrlAllowlist />
      </MemoryRouter>
    </QueryClientProvider>
  );
  const view = render(tree());
  return { client, refresh: () => view.rerender(tree()) };
}
beforeEach(() => {
  vi.resetAllMocks();
  mock.admin = true;
  mock.viewUsers = true;
  mock.shared = true;
  browserTenantRuntime.activate({
    kind: 'enterprise_shared',
    userId: 'reviewer',
    tenant: { id: '018f6f72-84b6-7a10-9f11-7ab36f02200a', slug: 'tenant-a' },
  });
  mock.listUsers.mockResolvedValue({ users: [creator], total: 1 });
  mock.get.mockResolvedValue({ entries: [] });
  mock.add.mockResolvedValue({});
  mock.remove.mockResolvedValue({});
});
afterEach(() => {
  cleanup();
  browserTenantRuntime.activate({ kind: 'anonymous' });
});

test('empty default is explicit, without fabricated attribution or counts', async () => {
  page();
  await screen.findByText('No hosts allowed yet');
  expect(
    screen.getByText(
      'All lookup URL fetches are blocked until an admin adds a host.',
    ),
  ).toBeTruthy();
  expect(
    screen
      .getByRole('link', { name: 'View audit history' })
      .getAttribute('href'),
  ).toBe('/settings/audit?action=inputlookup_allowlist_updated');
  expect(mock.listUsers).not.toHaveBeenCalled();
});
test('validates the host and UTF-8 note before calling the server', async () => {
  page();
  await screen.findByText('No hosts allowed yet');
  fireEvent.change(screen.getByLabelText('Host'), {
    target: { value: 'a.internal' },
  });
  expect(screen.getByText('internal hostnames are forbidden')).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Add host' })).toHaveProperty(
    'disabled',
    true,
  );
  expect(mock.add).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Host'), {
    target: { value: 'INTEL.Example.COM.' },
  });
  fireEvent.change(screen.getByLabelText('Note'), {
    target: { value: '🙂'.repeat(251) },
  });
  expect(screen.getByText('note must be at most 1000 bytes')).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Add host' })).toHaveProperty(
    'disabled',
    true,
  );
  fireEvent.change(screen.getByLabelText('Note'), {
    target: { value: 'Daily intel' },
  });
  mock.get.mockResolvedValue({ entries: [entry] });
  fireEvent.click(screen.getByRole('button', { name: 'Add host' }));
  await screen.findByText(creator.name);
  expect(mock.add).toHaveBeenCalledWith('intel.example.com', 'Daily intel');
  expect(screen.getByTitle(entry.created_at).getAttribute('datetime')).toBe(
    entry.created_at,
  );
  expect(screen.getByText('EXACT')).toBeTruthy();
});
test('remove requires an explicit second step; Keep cancels it', async () => {
  mock.get.mockResolvedValue({ entries: [entry] });
  page();
  await screen.findByTitle(entry.host);
  fireEvent.click(screen.getByRole('button', { name: 'Remove ' + entry.host }));
  expect(mock.remove).not.toHaveBeenCalled();
  let confirm = screen.getByRole('group', {
    name: 'Remove ' + entry.host + '?',
  });
  fireEvent.click(within(confirm).getByRole('button', { name: 'Keep' }));
  expect(mock.remove).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Remove ' + entry.host }));
  confirm = screen.getByRole('group', { name: 'Remove ' + entry.host + '?' });
  mock.get.mockResolvedValue({ entries: [] });
  fireEvent.click(within(confirm).getByRole('button', { name: 'Remove' }));
  await waitFor(() => expect(mock.remove).toHaveBeenCalledWith(entry.host));
  await screen.findByText('No hosts allowed yet');
});
test('filters hosts and notes, with a separate no-match state', async () => {
  mock.get.mockResolvedValue({
    entries: [
      entry,
      { ...entry, host: '*.example.org', note: 'Response feeds' },
    ],
  });
  page();
  await screen.findByTitle(entry.host);
  fireEvent.change(screen.getByLabelText('Filter hosts'), {
    target: { value: 'response' },
  });
  expect(screen.queryByTitle(entry.host)).toBeNull();
  expect(screen.getByText('SUBDOMAINS')).toBeTruthy();
  expect(screen.getByText('1 of 2 hosts')).toBeTruthy();
  fireEvent.change(screen.getByLabelText('Filter hosts'), {
    target: { value: 'absent' },
  });
  expect(screen.getByText('No matching hosts')).toBeTruthy();
  expect(screen.queryByText('No hosts allowed yet')).toBeNull();
});
test('URL tester uses exact/wildcard rules and never fetches or echoes URL credentials', async () => {
  mock.get.mockResolvedValue({
    entries: [entry, { ...entry, host: '*.example.org' }],
  });
  page();
  await screen.findByTitle(entry.host);
  const input = screen.getByLabelText('URL to check');
  fireEvent.change(input, {
    target: {
      value: 'https://intel.example.com/feeds.csv?sig=fixture-private',
    },
  });
  expect(screen.getByRole('status').textContent).toBe(
    'Allowed by intel.example.com.',
  );
  expect(screen.getByRole('status').textContent).not.toContain(
    'fixture-private',
  );
  fireEvent.change(input, { target: { value: 'https://a.example.org/x' } });
  expect(screen.getByRole('status').textContent).toBe(
    'Allowed by *.example.org.',
  );
  fireEvent.change(input, { target: { value: 'https://example.org/x' } });
  expect(screen.getByRole('status').textContent).toContain(
    "host not in this tenant's",
  );
  fireEvent.change(input, {
    target: { value: 'https://intel.example.com/bucket/../x' },
  });
  expect(screen.getByRole('status').textContent).toBe(
    'Shared inputlookup requires a static public HTTPS URL on port 443',
  );
  expect(mock.get).toHaveBeenCalledTimes(1);
  expect(mock.add).not.toHaveBeenCalled();
  expect(mock.remove).not.toHaveBeenCalled();
});
test('non-admin view exposes no editing controls', async () => {
  mock.admin = false;
  mock.get.mockResolvedValue({ entries: [entry] });
  page();
  await screen.findByTitle(entry.host);
  expect(
    screen.getByText('Read-only. A tenant admin manages allowed hosts.'),
  ).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Add host' })).toBeNull();
  expect(
    screen.queryByRole('button', { name: 'Remove ' + entry.host }),
  ).toBeNull();
});
test('does not issue a settings request outside hosted-shared', () => {
  mock.shared = false;
  page();
  expect(
    screen.getByText('Lookup URL allowlists are managed for shared tenants.'),
  ).toBeTruthy();
  expect(mock.get).not.toHaveBeenCalled();
  expect(mock.listUsers).not.toHaveBeenCalled();
});

test('resolves the real user name and initials, with the UUID only in a mono tooltip', async () => {
  mock.get.mockResolvedValue({ entries: [entry] });
  page();
  const name = await screen.findByText(creator.name);
  expect(screen.getByText('AA')).toBeTruthy();
  expect(screen.queryByText(entry.created_by)).toBeNull();
  expect(mock.listUsers).toHaveBeenCalledTimes(1);
  fireEvent.focus(name);
  const tooltip = await screen.findByRole('tooltip');
  expect(within(tooltip).getByText(creator.email)).toBeTruthy();
  expect(within(tooltip).getByText(entry.created_by).className).toContain(
    'font-mono',
  );
});

test('uses the real email and its initials when the display name is blank', async () => {
  mock.get.mockResolvedValue({ entries: [entry] });
  mock.listUsers.mockResolvedValue({
    users: [{ ...creator, name: ' ' }],
    total: 1,
  });
  page();
  expect(await screen.findByText(creator.email)).toBeTruthy();
  expect(screen.getByText('AN')).toBeTruthy();
  expect(screen.queryByText(entry.created_by)).toBeNull();
});

test.each(['missing user', 'forbidden directory'])(
  'shows unknown user for %s and keeps the UUID inside the tooltip',
  async (reason) => {
    mock.get.mockResolvedValue({ entries: [entry] });
    if (reason === 'missing user')
      mock.listUsers.mockResolvedValue({ users: [], total: 0 });
    else
      mock.listUsers.mockRejectedValue(
        Object.assign(new Error('Forbidden'), { status: 403 }),
      );
    const view = page();
    await waitFor(() => expect(view.client.isFetching()).toBe(0));
    const name = await screen.findByText('unknown user');
    expect(screen.queryByText(entry.created_by)).toBeNull();
    expect(screen.queryByText(creator.name)).toBeNull();
    fireEvent.focus(name);
    expect(
      within(await screen.findByRole('tooltip')).getByText(entry.created_by)
        .className,
    ).toContain('font-mono');
  },
);

test('without users:view, neither fetches users nor exposes cached names or emails', async () => {
  mock.get.mockResolvedValue({ entries: [entry] });
  mock.viewUsers = false;
  const client = queryClient();
  client.setQueryData(['users', browserTenantRuntime.current().key], {
    users: [creator],
    total: 1,
  });
  page(client);
  const name = await screen.findByText('unknown user');
  expect(mock.listUsers).not.toHaveBeenCalled();
  fireEvent.focus(name);
  const tooltip = await screen.findByRole('tooltip');
  expect(within(tooltip).getByText(entry.created_by)).toBeTruthy();
  expect(screen.queryByText(creator.name)).toBeNull();
  expect(screen.queryByText(creator.email)).toBeNull();
});

test('revoking users:view immediately hides a previously resolved name', async () => {
  mock.get.mockResolvedValue({ entries: [entry] });
  const view = page();
  await screen.findByText(creator.name);
  mock.viewUsers = false;
  view.refresh();
  expect(screen.getByText('unknown user')).toBeTruthy();
  expect(screen.queryByText(creator.name)).toBeNull();
  expect(mock.listUsers).toHaveBeenCalledTimes(1);
});

test('keeps nil-UUID attribution migrated without looking up a user', async () => {
  mock.get.mockResolvedValue({
    entries: [{ ...entry, created_by: '00000000-0000-0000-0000-000000000000' }],
  });
  page();
  expect(await screen.findByText('Unknown (migrated)')).toBeTruthy();
  expect(mock.listUsers).not.toHaveBeenCalled();
});

test('does not resolve an actor using another tenant’s cached user directory', async () => {
  mock.get.mockResolvedValue({ entries: [entry] });
  const view = page();
  await screen.findByText(creator.name);
  mock.listUsers.mockResolvedValue({ users: [], total: 0 });
  browserTenantRuntime.activate({
    kind: 'enterprise_shared',
    userId: 'reviewer',
    tenant: { id: '018f6f72-84b6-7a10-9f11-7ab36f02200b', slug: 'tenant-b' },
  });
  view.refresh();
  expect(screen.queryByText(creator.name)).toBeNull();
  await waitFor(() => expect(mock.listUsers).toHaveBeenCalledTimes(2));
  expect(await screen.findByText('unknown user')).toBeTruthy();
  expect(
    view.client.getQueryCache().findAll({ queryKey: ['users'] }),
  ).toHaveLength(2);
});
test.each([403, 503])(
  'keeps server %i authoritative and preserves an unsuccessful draft',
  async (status) => {
    mock.add.mockRejectedValue(
      Object.assign(
        new Error(status === 403 ? 'Access denied' : 'Unavailable; retry'),
        { status },
      ),
    );
    page();
    await screen.findByText('No hosts allowed yet');
    fireEvent.change(screen.getByLabelText('Host'), {
      target: { value: entry.host },
    });
    fireEvent.change(screen.getByLabelText('Note'), {
      target: { value: entry.note },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add host' }));
    expect(await screen.findByRole('alert')).toHaveProperty(
      'textContent',
      status === 403 ? 'Access denied' : 'Unavailable; retry',
    );
    expect(screen.getByLabelText('Host')).toHaveProperty('value', entry.host);
    expect(mock.add).toHaveBeenCalledTimes(1);
  },
);
test('load failure is not presented as an empty allowlist or a tester decision', async () => {
  mock.get.mockRejectedValue(new Error('Unavailable'));
  page();
  await screen.findByRole('alert');
  expect(screen.queryByText('No hosts allowed yet')).toBeNull();
  fireEvent.change(screen.getByLabelText('URL to check'), {
    target: { value: 'https://intel.example.com/x' },
  });
  expect(screen.getByRole('status').textContent).toBe(
    'Load the allowlist before checking a URL.',
  );
});
