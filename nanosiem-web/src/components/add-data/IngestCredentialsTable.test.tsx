// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-2593: Log Sources → Credentials: routes per credential, and self-revoke with a reason. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { TenantIngestCredential, TenantIngestCredentialRequest } from '@/lib/api/types';
import { IngestCredentialsTable } from './IngestCredentialsTable';

const mocks = vi.hoisted(() => ({
  permissions: new Set<string>(['log_sources:deploy', 'log_sources:view']),
  revoke: vi.fn(),
  toast: vi.fn(),
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user_me' }, hasPermission: (p: string) => mocks.permissions.has(p) }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: mocks.toast }) }));
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error {},
  api: { revokeIngestCredential: mocks.revoke },
}));

const now = new Date().toISOString();
const issued: TenantIngestCredential = {
  credential_id: '11111111-1111-4111-8111-111111111111', kind: 'source', protocol: 'hec', label: 'fw-hec', state: 'active',
  source_slugs: ['palo_alto_traffic'],
  routes: [{ route_id: '22222222-2222-4222-8222-222222222222', source_slug: 'palo_alto_traffic', state: 'active', revision: 3 }],
  cell_name: 'cell-a', created_at: now, revoked_at: null, revocable: true,
  request_id: '33333333-3333-4333-8333-333333333333', requested_by: 'user_me', requested_at: now, revealed_at: now,
};
const operator: TenantIngestCredential = {
  ...issued, credential_id: '44444444-4444-4444-8444-444444444444', label: 'okta source', source_slugs: ['okta'],
  routes: [{ route_id: '55555555-5555-4555-8555-555555555555', source_slug: 'okta', state: 'active', revision: 1 }],
  request_id: null, requested_by: null, requested_at: null, revealed_at: null,
};
const revoked: TenantIngestCredential = { ...issued, credential_id: '66666666-6666-4666-8666-666666666666', label: 'old', state: 'revoked', revocable: false, revoked_at: now };
const rejected: TenantIngestCredentialRequest = {
  id: '77777777-7777-4777-8777-777777777777', protocol: 'hec', label: 'denied', state: 'rejected', requested_by: 'user_other',
  requested_at: now, updated_at: now, kind: 'source', source_slugs: ['hr_app'], restricted_sources_acknowledged: false,
  sealed_token_ready: false, disposition: 'source_restricted: requester cannot see hr_app',
};

function renderTable() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <IngestCredentialsTable credentials={[issued, operator, revoked]} requests={[rejected]} currentUserId="user_me" />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  mocks.permissions = new Set(['log_sources:deploy', 'log_sources:view']);
  mocks.revoke.mockReset().mockResolvedValue({ credential_id: issued.credential_id, revoked: true, replayed: false, revoked_at: now });
  mocks.toast.mockReset();
});
afterEach(cleanup);

describe('IngestCredentialsTable (NAN-2593)', () => {
  it('lists credentials with mono source chips, provenance and routes', () => {
    renderTable();
    const table = screen.getByTestId('ingest-credentials-table');
    expect(within(table).getByText('fw-hec')).toBeTruthy();
    expect(within(table).getByText(/issued on app.nano.rs/)).toBeTruthy();
    expect(within(table).getAllByText('you').length).toBeGreaterThan(0);
    // Revoke is offered on active credentials only.
    expect(within(table).getAllByRole('button', { name: /revoke/i })).toHaveLength(2);

    fireEvent.click(screen.getByRole('button', { name: 'Show routes for fw-hec' }));
    const routes = screen.getByTestId(`routes-${issued.credential_id}`);
    expect(routes.textContent).toContain(issued.routes[0].route_id);
    expect(routes.textContent).toContain('palo_alto_traffic');

    const requests = screen.getByTestId('ingest-credential-requests');
    expect(requests.textContent).toMatch(/Source is hidden from you/);
  });

  it('revokes through the shared ConfirmDialog with a required reason', async () => {
    renderTable();
    const row = screen.getByText('fw-hec').closest('tr')!;
    fireEvent.click(within(row).getByRole('button', { name: /revoke/i }));
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog.textContent).toMatch(/refused within about 5\s+seconds/);
    const confirm = within(dialog).getByRole('button', { name: 'Revoke' }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText(/reason/i), { target: { value: '  rotated sender config  ' } });
    expect(confirm.disabled).toBe(false);
    await act(async () => {
      fireEvent.click(confirm);
    });
    await waitFor(() => expect(mocks.revoke).toHaveBeenCalledWith(issued.credential_id, 'rotated sender config'));
    await waitFor(() => expect(mocks.toast).toHaveBeenCalledWith(expect.objectContaining({ title: 'Credential revoked' })));
  });

  it('explains a refused revoke', async () => {
    mocks.revoke.mockRejectedValue(new Error('Forbidden: ingest_credential_refused: permission_missing'));
    renderTable();
    fireEvent.click(within(screen.getByText('fw-hec').closest('tr')!).getByRole('button', { name: /revoke/i }));
    const dialog = await screen.findByRole('alertdialog');
    fireEvent.change(within(dialog).getByLabelText(/reason/i), { target: { value: 'x' } });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
    });
    await waitFor(() => expect(mocks.toast).toHaveBeenCalledWith(expect.objectContaining({ title: 'Revoke failed: Permission required', variant: 'destructive' })));
  });

  it('hides revoke without log_sources:deploy', () => {
    mocks.permissions = new Set(['log_sources:view']);
    renderTable();
    expect(screen.queryAllByRole('button', { name: /revoke/i })).toHaveLength(0);
  });
});

describe('IngestCredentialsTable, collectors (NAN-2597)', () => {
  const collector: TenantIngestCredential = {
    ...issued, credential_id: '88888888-8888-4888-8888-888888888888', kind: 'collector', label: 'cribl-hec',
    source_slugs: ['okta', 'palo_alto_traffic'], source_aliases: { 'pan:traffic': 'palo_alto_traffic' },
    routes: [
      { route_id: '99999999-9999-4999-8999-999999999991', source_slug: 'okta', state: 'active', revision: 1 },
      { route_id: '99999999-9999-4999-8999-999999999992', source_slug: 'palo_alto_traffic', state: 'active', revision: 1 },
    ],
  };

  it('shows one row per collector with its sources, the implicit unknown and its aliases', () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <IngestCredentialsTable credentials={[collector, issued]} requests={[]} currentUserId="user_me" />
      </QueryClientProvider>,
    );
    const rows = within(screen.getByTestId('ingest-credentials-table')).getAllByRole('row');
    const row = rows.find((r) => r.textContent?.includes('cribl-hec'))!;
    expect(row.textContent).toContain('collector');
    expect(row.textContent).toMatch(/okta.*palo_alto_traffic.*unknown/);
    fireEvent.click(within(row).getByRole('button', { name: 'Show routes for cribl-hec' }));
    expect(screen.getByTestId(`aliases-${collector.credential_id}`).textContent).toContain('pan:traffic → palo_alto_traffic');
    expect(within(screen.getByTestId(`routes-${collector.credential_id}`)).getAllByRole('row')).toHaveLength(3);
  });

  it('a ?revoke=<id> deep link opens the revoke dialog for that credential', async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <IngestCredentialsTable credentials={[collector, issued]} requests={[]} currentUserId="user_me" initialRevokeId={collector.credential_id} />
      </QueryClientProvider>,
    );
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog.textContent).toContain('cribl-hec');
  });
});

describe('IngestCredentialsTable activity columns (NAN-2599)', () => {
  it('shows last seen, events 24h, parse failures and the last error; a restricted credential shows nothing', () => {
    const seen = new Date(Date.now() - 5 * 60_000).toISOString();
    const withActivity: TenantIngestCredential = {
      ...issued,
      activity: { last_seen_at: seen, edge_events_24h: 1234, lake_events_24h: 1200, parse_failures_24h: 7,
        last_rejected_at: new Date().toISOString(), last_rejection_class: 'source_not_allowed', last_rejection_status: 403, redacted: false },
    };
    const hidden: TenantIngestCredential = {
      ...operator,
      activity: { last_seen_at: null, edge_events_24h: null, lake_events_24h: 0, parse_failures_24h: 0,
        last_rejected_at: null, last_rejection_class: null, last_rejection_status: null, redacted: true },
    };
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <IngestCredentialsTable credentials={[withActivity, hidden]} requests={[]} currentUserId="user_me" />
      </QueryClientProvider>,
    );
    const [first, second] = screen.getAllByTestId('credential-events-24h');
    expect(first.textContent).toMatch(/1\.2K/);
    expect(first.textContent).toMatch(/7 failed/);
    expect(screen.getAllByTestId('credential-last-error')[0].textContent).toMatch(/403 source_not_allowed/);
    expect(screen.getAllByTestId('credential-last-seen')[1].textContent).toBe('restricted');
    expect(second.textContent).toBe('—');
  });
});
