// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// NAN-3883: a search that escalated to a durable job shows an honest running
// state (phase, elapsed, "background job") instead of a 0% bar that reads as
// hung, and keeps the cancel and a way to reopen it from Running jobs.
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ComponentProps } from 'react';
import { SearchResults } from './SearchResults';

vi.mock('@/lib/api', () => ({
  api: { getSchemaFields: async () => ({ schema: 'udm', fields: [] }) },
}));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));

afterEach(cleanup);

function mount(props: Partial<ComponentProps<typeof SearchResults>>) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(['schema-fields'], { schema: 'udm', fields: [] });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <SearchResults
          results={[]}
          totalCount={0}
          isSearching
          hasSearched={false}
          isAggregateQuery
          displayType="table"
          onAddToQuery={vi.fn()}
          onLoadMore={vi.fn()}
          query="* | stats count by actor.user.name"
          {...props}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

it('a phase-only durable job shows its phase, retry, elapsed time and the background note, not a 0% bar', () => {
  const onOpenJobs = vi.fn();
  const onCancel = vi.fn();
  mount({
    asyncJobId: 'job-1', asyncJobStatus: 'running', onOpenJobs, onCancelAsyncJob: onCancel,
    asyncJobProgress: { phase: 'scanning', attempt: 2, rows_scanned: 0, rows_total: 0, percent: 0, elapsed_ms: 125_000 },
  });
  expect(screen.getByText('Scanning in the background (attempt 2)…')).toBeTruthy();
  expect(screen.getByTestId('async-job-elapsed').textContent).toBe('2m 05s elapsed');
  expect(screen.queryByText(/% complete/)).toBeNull();
  expect(screen.getByTestId('async-job-background-note').textContent).toContain('You can leave this page');
  fireEvent.click(screen.getByRole('button', { name: 'Running jobs' }));
  expect(onOpenJobs).toHaveBeenCalledOnce();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(onCancel).toHaveBeenCalledOnce();
});

it('a job with a real measure keeps the progress bar', () => {
  mount({
    asyncJobId: 'job-2', asyncJobStatus: 'running',
    asyncJobProgress: { rows_scanned: 4_000, rows_total: 10_000, percent: 40, elapsed_ms: 46_000 },
  });
  expect(screen.getByText(/40% complete/)).toBeTruthy();
  expect(screen.queryByTestId('async-job-elapsed')).toBeNull();
  expect(screen.getByTestId('async-job-background-note')).toBeTruthy();
});

it('a streaming (non-job) search shows no background note', () => {
  mount({ asyncJobId: null, asyncJobStatus: 'running', asyncJobProgress: { rows_scanned: 0, rows_total: 0, percent: 0, elapsed_ms: 1_000 } });
  expect(screen.queryByTestId('async-job-background-note')).toBeNull();
  expect(screen.getByText('Scanning rows...')).toBeTruthy();
});
