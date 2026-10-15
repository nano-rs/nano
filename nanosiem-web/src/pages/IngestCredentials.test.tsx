// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-3250: Ingest credentials flows in the app scroller (same layout family as NAN-3248). */
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { IngestCredentials } from './IngestCredentials';

vi.mock('@/hooks/use-shared-tenant', () => ({ useSharedTenant: () => true }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'u' }, hasPermission: () => true }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/lib/api', () => ({
  api: {
    listIngestCredentials: () => Promise.resolve({ credentials: [], requests: [] }),
    getIngestEndpoint: () => Promise.resolve({ hostname: 'ingest.example.test' }),
  },
}));

afterEach(() => cleanup());

it('flows in the app scroller: no fill-height column or min-h-0 scroll box around the table', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <IngestCredentials />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  const page = screen.getByTestId('ingest-credentials-page');
  expect(page.getAttribute('data-page-shell')).toBe('log-sources');
  expect(page.className).not.toMatch(/(^|\s)h-full(\s|$)/);
  expect(page.className).not.toMatch(/(^|\s)min-h-0(\s|$)/);
  const region = screen.getByTestId('ingest-credentials-region');
  expect(region.className).not.toMatch(/(^|\s)(min-h-0|flex-1|overflow-auto|overflow-y-auto)(\s|$)/);
  await waitFor(() => expect(within(page).getByText(/endpoint ingest\.example\.test/)).toBeTruthy());
});
