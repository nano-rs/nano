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

function expectNoTilde(container: HTMLElement) {
  expect(container.textContent).not.toContain('~');
  for (const element of container.querySelectorAll('[title]')) {
    expect(element.getAttribute('title')).not.toContain('~');
  }
}

function expectSampleBelowValues(view: ReturnType<typeof render>, label: string) {
  const disclosures = view.getAllByText(label);
  expect(disclosures).toHaveLength(1);
  const disclosure = disclosures[0];
  expect(disclosure.className).toContain('font-mono');
  expect(disclosure.className).toContain('text-muted-foreground');
  expect(disclosure.parentElement?.lastElementChild).toBe(disclosure);
  expect(view.getByText('10.0.0.1').compareDocumentPosition(disclosure) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expectNoTilde(view.container);
}

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

it('shows plain sampled cardinality and discloses the sample below values while loading', async () => {
  const fieldStats = stats().map(stat => ({ ...stat, sampledRows: 1000 }));
  const view = render(panel(props({ fieldStats, onFetchFieldValues: undefined })));
  expect(view.getByTitle('1 unique values in a sample of 1,000 events. Expand to load field statistics.').textContent).toBe('1');
  expect(view.queryByText('sample · 1,000 events')).toBeNull();
  expectNoTilde(view.container);
  view.rerender(panel(props({
    fieldStats,
    expandedFields: new Set(['src_ip']),
    onFetchFieldValues: () => new Promise(() => {}),
  })));
  await waitFor(() => expect(view.getByText('Loading full stats…')).toBeTruthy());
  expect(view.getByText('1 unique · 1 events')).toBeTruthy();
  expect(view.getByText('100.0%')).toBeTruthy();
  expectSampleBelowValues(view, 'sample · 1,000 events');
});

it('removes the sample disclosure after an exact drill-in returns', async () => {
  const view = render(panel(props({
    fieldStats: stats().map(stat => ({ ...stat, sampledRows: 1000 })),
    expandedFields: new Set(['src_ip']),
    onFetchFieldValues: async () => ({ values: [
      { value: '10.0.0.1', count: 1500, percentage: 99.93 },
      { value: '10.0.0.2', count: 1, percentage: 0.07 },
    ], total_count: 1501 }),
  })));
  await waitFor(() => expect(view.getByTitle('2 unique values')).toBeTruthy());
  expect(view.queryByText(/^sample ·/)).toBeNull();
  expect(view.getByText('2 unique · 1,501 events')).toBeTruthy();
  expect(view.getByText('10.0.0.2')).toBeTruthy();
  expectNoTilde(view.container);
});

it('discloses the time sample once below values when the drill-in is still approximate', async () => {
  const view = render(panel(props({
    fieldStats: stats().map(stat => ({ ...stat, sampledRows: 1000 })),
    expandedFields: new Set(['src_ip']),
    onFetchFieldValues: async () => ({ values: stats()[0].topValues, total_count: 1,
      approximate: true, sampled_start: range.start, sampled_end: range.end }),
  })));
  await waitFor(() => expect(view.getByText('sample · last 1h')).toBeTruthy());
  expect(view.queryByText('sample · 1,000 events')).toBeNull();
  expectSampleBelowValues(view, 'sample · last 1h');
});

it('keeps plain counts and the sample disclosure when the drill-in fails', async () => {
  const view = render(panel(props({
    fieldStats: stats().map(stat => ({ ...stat, sampledRows: 1000 })),
    expandedFields: new Set(['src_ip']),
    onFetchFieldValues: async () => { throw new Error('Field values unavailable'); },
  })));
  await waitFor(() => expect(view.queryByText('Loading full stats…')).toBeNull());
  expect(view.getByTitle('1 unique values in a sample of 1,000 events. Expand to load field statistics.').textContent).toBe('1');
  expectSampleBelowValues(view, 'sample · 1,000 events');
});

it.each([0, 1234])('formats sampled cardinality %i as a plain number', uniqueCount => {
  const view = render(panel(props({
    fieldStats: stats().map(stat => ({ ...stat, uniqueCount, sampledRows: 5000 })),
    onFetchFieldValues: undefined,
  })));
  expect(view.getByTitle(`${uniqueCount.toLocaleString()} unique values in a sample of 5,000 events. Expand to load field statistics.`).textContent).toBe(uniqueCount.toLocaleString());
  expectNoTilde(view.container);
});

it('leaves exact field cardinality unmarked', () => {
  const view = render(panel(props({ onFetchFieldValues: undefined })));
  expect(view.getByTitle('1 unique values').textContent).toBe('1');
  expect(view.queryByText(/^sample ·/)).toBeNull();
  expectNoTilde(view.container);
});
