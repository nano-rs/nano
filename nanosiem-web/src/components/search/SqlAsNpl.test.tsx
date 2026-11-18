// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-5575: agent SQL shows as nPL first, the SQL one click away. */
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { SqlToNplResponse } from '@/lib/api/types';

const calls = vi.hoisted(() => ({ sqlToNplBatch: vi.fn(), sqlToNplAi: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: calls }));
vi.mock('@/hooks/use-in-view', () => ({ useInView: () => true }));
import { SqlAsNpl } from './SqlAsNpl';
import { CapabilitiesContext, type CapabilitiesContextValue } from '@/hooks/use-capabilities';

const SQL = "SELECT * FROM logs WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} AND dest_port = 443";

function result(over: Partial<SqlToNplResponse>): SqlToNplResponse {
  return {
    npl: 'dest_port=443',
    earliest: '2026-11-01T00:00:00Z',
    latest: '2026-11-02T00:00:00Z',
    exact: true,
    approximate: false,
    differences: [],
    unsupported_reason: null,
    unsupported_span: null,
    no_search_dataset: false,
    ...over,
  };
}

function renderIt(sql = SQL) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <SqlAsNpl sql={sql} windowStart="2026-11-01T00:00:00Z" windowEnd="2026-11-02T00:00:00Z" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
afterEach(() => {
  cleanup();
  calls.sqlToNplBatch.mockReset();
});

it('shows the nPL first, opens Search over the range, and keeps the SQL behind a toggle', async () => {
  calls.sqlToNplBatch.mockResolvedValue({ results: [result({})] });
  renderIt();
  await waitFor(() => expect(screen.getByTestId('sql-as-npl-npl').textContent).toBe('dest_port=443'));
  expect(calls.sqlToNplBatch).toHaveBeenCalledWith([
    { sql: SQL, window_start: '2026-11-01T00:00:00Z', window_end: '2026-11-02T00:00:00Z' },
  ]);
  const href = screen.getByText('Open in Search').getAttribute('href') ?? '';
  const params = new URLSearchParams(href.split('#')[1]);
  expect(params.get('q')).toBe('dest_port=443');
  expect(params.get('mode')).toBe('piped');
  expect(params.get('start')).toBe('2026-11-01T00:00:00.000Z');
  // Exact: no badge, SQL hidden until asked for.
  expect(screen.queryByText('broader')).toBeNull();
  expect(screen.queryByTestId('sql-as-npl-sql')).toBeNull();
  fireEvent.click(screen.getByText('SQL'));
  expect(screen.getByTestId('sql-as-npl-sql').textContent).toBe(SQL);
});

it('marks a broader conversion', async () => {
  calls.sqlToNplBatch.mockResolvedValue({
    results: [result({ exact: false, differences: [{ kind: 'broader', detail: 'case-insensitive' }] })],
  });
  renderIt();
  await waitFor(() => expect(screen.getByText('broader')).toBeTruthy());
});

it('says why it cannot convert and shows the SQL, with no Search link', async () => {
  calls.sqlToNplBatch.mockResolvedValue({
    results: [result({ npl: null, exact: false, unsupported_reason: 'a JOIN' })],
  });
  renderIt();
  await waitFor(() => expect(screen.getByTestId('sql-as-npl-unsupported').textContent).toContain('a JOIN'));
  expect(screen.getByTestId('sql-as-npl-sql').textContent).toBe(SQL);
  expect(screen.queryByText('Open in Search')).toBeNull();
  expect(screen.getByText('Copy SQL')).toBeTruthy();
  // No capability provider: the AI path is not offered, and never runs on its own.
  expect(screen.queryByText('Try AI conversion')).toBeNull();
  expect(calls.sqlToNplAi).not.toHaveBeenCalled();
});

it('runs the AI conversion only on an explicit click, and says when AI is not configured', async () => {
  calls.sqlToNplBatch.mockResolvedValue({ results: [result({ npl: null, exact: false, unsupported_reason: 'a JOIN' })] });
  calls.sqlToNplAi.mockRejectedValue(Object.assign(new Error('x'), { status: 503 }));
  const caps = { edition: 'enterprise', version: 'test', capabilities: { melod: true } } as unknown as CapabilitiesContextValue;
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <CapabilitiesContext.Provider value={caps}>
        <MemoryRouter>
          <SqlAsNpl sql={SQL} />
        </MemoryRouter>
      </CapabilitiesContext.Provider>
    </QueryClientProvider>,
  );
  await waitFor(() => expect(screen.getByText('Try AI conversion')).toBeTruthy());
  expect(calls.sqlToNplAi).not.toHaveBeenCalled();
  fireEvent.click(screen.getByText('Try AI conversion'));
  await waitFor(() => expect(screen.getByText('AI is not configured on this install')).toBeTruthy());
  expect(calls.sqlToNplAi).toHaveBeenCalledTimes(1);
});

it('opens SQL over the detections in Search on dataset=signals (NAN-5612)', async () => {
  calls.sqlToNplBatch.mockResolvedValue({
    results: [result({ npl: '* | stats count() as fires by rule_name', dataset: 'signals' })],
  });
  renderIt("SELECT rule_name, count() AS fires FROM {signals} WHERE timestamp >= {earliest:DateTime64(6, 'UTC')} GROUP BY rule_name");
  await waitFor(() => expect(screen.getByTestId('sql-as-npl-dataset').textContent).toBe('dataset=signals'));
  const href = screen.getByText('Open in Search').getAttribute('href') ?? '';
  const params = new URLSearchParams(href.split('#')[1]);
  expect(params.get('dataset')).toBe('signals');
  expect(params.get('q')).toBe('* | stats count() as fires by rule_name');
});

it('keeps the logs Search link free of a dataset parameter', async () => {
  calls.sqlToNplBatch.mockResolvedValue({ results: [result({ dataset: 'logs' })] });
  renderIt();
  await waitFor(() => expect(screen.getByTestId('sql-as-npl-npl').textContent).toBe('dest_port=443'));
  expect(screen.queryByTestId('sql-as-npl-dataset')).toBeNull();
  const href = screen.getByText('Open in Search').getAttribute('href') ?? '';
  expect(new URLSearchParams(href.split('#')[1]).get('dataset')).toBeNull();
});
