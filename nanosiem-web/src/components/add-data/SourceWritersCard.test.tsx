// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-2597: "credentials that can write S" on Log Source detail and Source Visibility. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { TenantSourceWriters } from '@/lib/api/types';
import { addDataLink, revokeLink } from '@/lib/add-data-sources';
import { INGEST_CREDENTIALS_PATH } from './LogSourcesTabs';
import { SourceWritersCard } from './SourceWritersCard';

const mocks = vi.hoisted(() => ({ byLogSource: vi.fn(), bySlug: vi.fn() }));
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error {},
  api: { getLogSourceCredentials: mocks.byLogSource, getSourceWriters: mocks.bySlug },
}));

const base = {
  protocol: 'hec', state: 'active', cell_name: 'cell', created_at: '2026-09-22T00:00:00Z', revocable: true,
  source_aliases: {}, request_id: null, requested_by: null, requested_at: null, revealed_at: null,
};
const writers: TenantSourceWriters = {
  source_slugs: ['palo_alto_traffic'],
  writers: [
    { ...base, credential_id: 'c-direct', kind: 'source', label: 'fw-direct', source_slugs: ['palo_alto_traffic'], routes: [],
      writes: ['palo_alto_traffic'], declared_names: [], implicit: false },
    { ...base, credential_id: 'c-cribl', kind: 'collector', label: 'cribl', source_slugs: ['okta', 'palo_alto_traffic'], routes: [],
      source_aliases: { 'pan:traffic': 'palo_alto_traffic' }, writes: ['palo_alto_traffic'],
      declared_names: ['palo_alto_traffic', 'pan:traffic'], implicit: false },
  ],
};

function renderCard(props: Parameters<typeof SourceWritersCard>[0]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <SourceWritersCard {...props} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  mocks.byLogSource.mockReset();
  mocks.bySlug.mockReset();
});

describe('SourceWritersCard (NAN-2597)', () => {
  it('lists every writer of a log source with how events declare it and a revoke link', async () => {
    mocks.byLogSource.mockResolvedValue(writers);
    renderCard({ logSourceId: 'lsrc_1', canRevoke: true });
    const table = await screen.findByTestId('source-writers-table');
    expect(mocks.byLogSource).toHaveBeenCalledWith('lsrc_1');
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows[0].textContent).toContain('fixed by the token');
    expect(rows[1].textContent).toContain('pan:traffic');
    const link = within(rows[1]).getByRole('link', { name: /revoke/i });
    expect(link.getAttribute('href')).toBe(revokeLink('c-cribl'));
    expect(revokeLink('c-cribl')).toBe(`${INGEST_CREDENTIALS_PATH}?revoke=c-cribl`);
  });

  it('shows collectors that write Unattributed through undeclared events, without revoke when not allowed', async () => {
    mocks.bySlug.mockResolvedValue({
      source_slugs: ['unknown'],
      writers: [{ ...writers.writers[1], writes: ['unknown'], declared_names: [], implicit: true }],
    });
    renderCard({ sourceSlug: 'unknown', canRevoke: false });
    const table = await screen.findByTestId('source-writers-table');
    expect(mocks.bySlug).toHaveBeenCalledWith('unknown');
    expect(table.textContent).toContain('undeclared events (unknown)');
    expect(within(table).queryByRole('link')).toBeNull();
  });

  it('offers Issue credential with the source preselected, including from the empty state (NAN-2946)', async () => {
    mocks.byLogSource.mockResolvedValue({ source_slugs: ['apache_access'], writers: [] });
    renderCard({ logSourceId: 'lsrc_1', canRevoke: true, canIssue: true });
    const header = await screen.findByTestId('source-writers-issue');
    expect(header.getAttribute('href')).toBe(addDataLink('apache_access'));
    const empty = await screen.findByRole('link', { name: 'Issue one' });
    expect(empty.getAttribute('href')).toBe(addDataLink('apache_access'));
  });

  it('opens the source picker for several labels and hides the action without permission (NAN-2946)', async () => {
    mocks.byLogSource.mockResolvedValue({ source_slugs: ['a', 'b'], writers: [] });
    renderCard({ logSourceId: 'lsrc_2', canRevoke: true, canIssue: true });
    expect((await screen.findByTestId('source-writers-issue')).getAttribute('href')).toBe(addDataLink());
    cleanup();
    mocks.byLogSource.mockResolvedValue({ source_slugs: ['a'], writers: [] });
    renderCard({ logSourceId: 'lsrc_3', canRevoke: true });
    await screen.findByText('No active credential can write this source.');
    expect(screen.queryByTestId('source-writers-issue')).toBeNull();
  });

  it('offers nothing for the Unattributed labels (NAN-2946)', async () => {
    mocks.bySlug.mockResolvedValue({ source_slugs: ['unknown'], writers: [] });
    renderCard({ sourceSlug: 'unknown', canRevoke: true, canIssue: true });
    await screen.findByText('No active credential can write this source.');
    expect(screen.queryByRole('link')).toBeNull();
  });
});
