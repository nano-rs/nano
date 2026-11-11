// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, render, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ComponentProps } from 'react';
import { FieldsPanel, type FieldStat } from './FieldsPanel';

const mocks = vi.hoisted(() => ({ ext: vi.fn() }));
vi.mock('@/lib/api', () => ({
  api: {
    getExtFieldNames: mocks.ext,
    getExtendedFieldNames: async () => [],
    getSchemaFields: async () => ({ schema: 'udm', fields: [] }),
    sourceScopes: { listRestricted: async () => ({ restricted: [] }) },
  },
}));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => false }) }));

const stats = (): FieldStat[] => [{ field: 'src_ip', count: 1, uniqueCount: 1, topValues: [{ value: '10.0.0.1', count: 1, percentage: 100 }] }];
const range = { start: '2026-10-08T13:00:00.000Z', end: '2026-10-08T14:00:00.000Z' };

function props(overrides: Partial<ComponentProps<typeof FieldsPanel>> = {}): ComponentProps<typeof FieldsPanel> {
  return {
    fieldStats: stats(), baseFieldStats: [], isAggregateQuery: false, showBaseFields: false,
    onToggleShowBaseFields: () => {}, expandedFields: new Set(), onToggleField: () => {}, onAddToQuery: () => {},
    isExpanded: true, onToggleExpanded: () => {}, query: 'user="jsmith"', timeRange: range,
    onFetchFieldValues: async () => ({ values: [], total_count: 0 }),
    ...overrides,
  };
}

let client: QueryClient;
beforeEach(() => {
  mocks.ext.mockReset().mockResolvedValue(['custom_key']);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(cleanup);

const panel = (p: ComponentProps<typeof FieldsPanel>) => <QueryClientProvider client={client}><FieldsPanel {...p} /></QueryClientProvider>;

it('NAN-3299: fetches ext names once per run scope, across re-renders and a remount', async () => {
  const view = render(panel(props()));
  await waitFor(() => expect(mocks.ext).toHaveBeenCalledOnce());
  // New arrays (field stats landing, a re-render) and a remount (the panel
  // collapsing and expanding) with the same run scope reuse the response.
  view.rerender(panel(props({ fieldStats: stats() })));
  view.unmount();
  render(panel(props({ fieldStats: stats() })));
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(mocks.ext).toHaveBeenCalledOnce();
  expect(mocks.ext).toHaveBeenCalledWith('user="jsmith"', range.start, range.end, expect.any(AbortSignal));
});

it('NAN-3299: waits for a field index, so a pre-run window is never fetched', async () => {
  const view = render(panel(props({ fieldStats: [], timeRange: { start: '2026-10-08T12:59:00.000Z', end: '2026-10-08T13:59:00.000Z' } })));
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(mocks.ext).not.toHaveBeenCalled();
  view.rerender(panel(props()));
  await waitFor(() => expect(mocks.ext).toHaveBeenCalledOnce());
  expect(mocks.ext.mock.calls[0][1]).toBe(range.start);
});

it('NAN-3299: a superseded ext fetch is aborted when the run scope moves on', async () => {
  mocks.ext.mockImplementationOnce(() => new Promise(() => {}));
  const view = render(panel(props()));
  await waitFor(() => expect(mocks.ext).toHaveBeenCalledOnce());
  const first: AbortSignal = mocks.ext.mock.calls[0][3];
  view.rerender(panel(props({ query: 'user="other"' })));
  await waitFor(() => expect(mocks.ext).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(first.aborted).toBe(true));
});
