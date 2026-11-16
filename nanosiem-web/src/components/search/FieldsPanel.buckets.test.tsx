// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ComponentProps } from 'react';
import { FieldsPanel, type FieldStat } from './FieldsPanel';

// NAN-5265: the sidebar's on-demand sections mirror the event inspector —
// Extended (UDM ext.* / valid non-promoted OCSF attributes) and Unmapped (the
// OCSF unmapped.* spill only) — and never double the spill namespace.

const mocks = vi.hoisted(() => ({ ext: vi.fn(), extended: vi.fn(), schema: vi.fn(), inventory: vi.fn(), requests: [] as Array<Record<string, unknown>> }));
vi.mock('@/lib/api', () => ({
  api: {
    getExtFieldNames: mocks.ext,
    getExtendedFieldNames: mocks.extended,
    // NAN-5485: the panel reads the inventories (names + completeness).
    getFieldInventory: async (req: { query: string; start: string; end: string; bucket?: string }, signal?: AbortSignal) => {
      mocks.requests.push(req);
      const bucket = req.bucket ?? 'spill';
      const names = await (bucket === 'extended' ? mocks.extended : mocks.ext)(req.query, req.start, req.end, signal);
      return mocks.inventory(bucket) ?? { names, partial: false };
    },
    getSchemaFields: mocks.schema,
    sourceScopes: { listRestricted: async () => ({ restricted: [] }) },
  },
}));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => false }) }));

const range = { start: '2026-11-10T13:00:00.000Z', end: '2026-11-10T14:00:00.000Z' };
const ocsfStats = (): FieldStat[] => [
  { field: 'src_endpoint.ip', count: 1, uniqueCount: 1, topValues: [{ value: '10.0.0.1', count: 1, percentage: 100 }] },
  { field: 'process.cmd_line', count: 1, uniqueCount: 1, topValues: [] },
  { field: 'metadata.version', count: 1, uniqueCount: 1, topValues: [] },
];

function props(overrides: Partial<ComponentProps<typeof FieldsPanel>> = {}): ComponentProps<typeof FieldsPanel> {
  return {
    fieldStats: ocsfStats(), baseFieldStats: [], isAggregateQuery: false, showBaseFields: false,
    onToggleShowBaseFields: () => {}, expandedFields: new Set(), onToggleField: () => {}, onAddToQuery: () => {},
    isExpanded: true, onToggleExpanded: () => {}, query: 'source_type=windows_sysmon', timeRange: range,
    onFetchFieldValues: async () => ({ values: [], total_count: 0 }),
    ...overrides,
  };
}

let client: QueryClient;
beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  mocks.ext.mockReset();
  mocks.extended.mockReset();
  mocks.schema.mockReset();
  mocks.inventory.mockReset();
  mocks.requests.length = 0;
});
afterEach(cleanup);

const panel = (p: ComponentProps<typeof FieldsPanel>) => (
  <QueryClientProvider client={client}><FieldsPanel {...p} /></QueryClientProvider>
);
const header = (label: string) => screen.getByRole('button', { name: new RegExp(`^${label}\\s*\\d+$`, 'i') });

describe('OCSF', () => {
  beforeEach(() => {
    mocks.schema.mockResolvedValue({ schema: 'ocsf', fields: [] });
    // The API contract: bare spill keys, full Extended attribute paths.
    mocks.ext.mockResolvedValue(['client_ip', 'event_data.utc_time', 'task']);
    mocks.extended.mockResolvedValue(['module.file.company_name', 'module.file.hashes', 'actor.process.file.name']);
  });

  it('renders Extended and Unmapped sections with the inspector labels and tooltips', async () => {
    render(panel(props()));
    await waitFor(() => expect(header('Extended')).toBeTruthy());
    expect(header('Extended').getAttribute('title')).toBe('Valid OCSF fields stored in the event JSON');
    expect(header('Unmapped').getAttribute('title')).toBe("Source fields the parser didn't map to OCSF");
    for (const core of ['Selected', 'Available']) {
      expect(screen.getByText(core).closest('[title]')?.getAttribute('title')).toBe('Indexed columns');
    }
    expect(header('Extended').textContent).toMatch(/3$/);
    expect(header('Unmapped').textContent).toMatch(/3$/);
    expect(mocks.extended).toHaveBeenCalledWith('source_type=windows_sysmon', range.start, range.end, expect.any(AbortSignal));

    fireEvent.click(header('Extended'));
    fireEvent.click(header('Unmapped'));
    for (const f of ['module.file.company_name', 'module.file.hashes', 'actor.process.file.name']) {
      expect(screen.getByText(f)).toBeTruthy();
    }
    for (const f of ['unmapped.client_ip', 'unmapped.event_data.utc_time', 'unmapped.task']) {
      expect(screen.getByText(f)).toBeTruthy();
    }
    expect(screen.queryByText(/unmapped\.unmapped\./)).toBeNull();
    expect(screen.queryByText('unmapped.module.file.company_name')).toBeNull();
  });

  it('click, expand and add-to-filter all use the single-prefix name a user would type', async () => {
    const onToggleField = vi.fn();
    const onAddToQuery = vi.fn();
    const onFetchFieldValues = vi.fn().mockResolvedValue({ values: [{ value: '7', count: 6991, percentage: 100 }], total_count: 6991 });
    const view = render(panel(props({ onToggleField, onAddToQuery, onFetchFieldValues })));
    await waitFor(() => expect(header('Unmapped')).toBeTruthy());
    fireEvent.click(header('Unmapped'));
    fireEvent.click(screen.getByText('unmapped.task'));
    expect(onToggleField).toHaveBeenCalledWith('unmapped.task');

    view.rerender(panel(props({ onToggleField, onAddToQuery, onFetchFieldValues, expandedFields: new Set(['unmapped.task']) })));
    await waitFor(() => expect(onFetchFieldValues).toHaveBeenCalledWith('unmapped.task', 'source_type=windows_sysmon', range.start, range.end));
    const valueRow = await screen.findByTitle('7');
    fireEvent.contextMenu(valueRow);
    fireEvent.click(await screen.findByText('Add to filter'));
    expect(onAddToQuery).toHaveBeenCalledWith('unmapped.task', '7', false);
    // Search.addToQuery appends `${field}="${value}"` — the exact hand-typed
    // filter that returns rows, not the `unmapped.unmapped.task` that matched 0.
    const [field, value] = onAddToQuery.mock.calls[0];
    expect(`${field}="${value}"`).toBe('unmapped.task="7"');
  });

  it('labels a partial inventory instead of showing it as every field (NAN-5485)', async () => {
    mocks.inventory.mockImplementation((bucket: string) =>
      bucket === 'spill'
        ? { names: ['client_ip'], partial: true, reason: 'row_limit', rows_examined: 100000, row_limit: 100000 }
        : undefined);
    render(panel(props()));
    const hdr = await screen.findByRole('button', { name: /^Unmapped · partial\s*1$/i });
    expect(hdr.getAttribute('title')).toContain('Listed from the first 100,000 matching events');
    // The complete Extended list carries no label.
    expect(await screen.findByRole('button', { name: /^Extended\s*3$/i })).toBeTruthy();
  });

  it('shows a failed (empty) partial inventory rather than hiding the section', async () => {
    mocks.inventory.mockImplementation((bucket: string) =>
      bucket === 'extended' ? { names: [], partial: true, reason: 'scan_failed', rows_examined: null, row_limit: 10000 } : undefined);
    render(panel(props()));
    const hdr = await screen.findByRole('button', { name: /^Extended · partial\s*0$/i });
    expect(hdr.getAttribute('title')).toContain('The scan for these fields failed');
  });

  it('labels a section whose inventory request failed instead of dropping it', async () => {
    mocks.inventory.mockImplementation((bucket: string) => {
      if (bucket === 'spill') throw new Error('500');
      return undefined;
    });
    render(panel(props()));
    const hdr = await screen.findByRole('button', { name: /^Unmapped · partial\s*0$/i });
    expect(hdr.getAttribute('title')).toContain('could not be loaded');
  });

  it('says when field stats are a head sample of the matched events', async () => {
    render(panel(props({ statsGap: { sampledFromRows: 100000, partialReason: 'row_cap' } })));
    expect((await screen.findByTestId('fields-stats-gap')).textContent).toContain('first 100,000 matching events');
  });

  it('says when field stats failed instead of passing page-local stats off as complete', async () => {
    render(panel(props({ statsGap: { unavailable: true } })));
    expect((await screen.findByTestId('fields-stats-gap')).textContent).toContain('Field stats unavailable');
  });

  it('labels dropped columns and shows no note for complete stats', async () => {
    render(panel(props({ statsGap: { partialReason: 'columns_dropped' } })));
    expect((await screen.findByTestId('fields-stats-gap')).textContent).toContain('could not be computed');
    cleanup();
    render(panel(props({ statsGap: null })));
    expect(screen.queryByTestId('fields-stats-gap')).toBeNull();
  });

  it('asks for the inventory of the search dataset (non-logs are answered partial)', async () => {
    mocks.inventory.mockImplementation(() => ({ names: [], partial: true, reason: 'dataset_not_supported' }));
    render(panel(props({ dataset: 'spans' })));
    await waitFor(() => expect(mocks.requests.length).toBeGreaterThan(0));
    expect(mocks.requests.every((r) => r.dataset === 'spans')).toBe(true);
    const hdr = await screen.findByRole('button', { name: /^Unmapped · partial\s*0$/i });
    expect(hdr.getAttribute('title')).toContain('This dataset has no list of these fields.');
  });

  it('labels derived fields a pipeline creates as not listed', async () => {
    mocks.inventory.mockImplementation((bucket: string) =>
      bucket === 'spill' ? { names: ['client_ip'], partial: true, reason: 'derived_fields_not_listed' } : undefined);
    render(panel(props({ query: 'source_type=windows_sysmon | eval tag="x"' })));
    const hdr = await screen.findByRole('button', { name: /^Unmapped · partial\s*1$/i });
    expect(hdr.getAttribute('title')).toContain('Fields this pipeline creates');
  });

  it('runs the inventories under the search request id (cancelled with it)', async () => {
    render(panel(props({ requestId: 'req-42' })));
    await waitFor(() => expect(mocks.requests.length).toBe(2));
    expect(mocks.requests.map((r) => [r.bucket ?? 'spill', r.request_id]).sort()).toEqual([
      ['extended', 'req-42'],
      ['spill', 'req-42'],
    ]);
  });
});

describe('UDM', () => {
  beforeEach(() => {
    mocks.schema.mockResolvedValue({ schema: 'udm', fields: [] });
    mocks.ext.mockResolvedValue(['custom_key']);
  });

  it('keeps ext.* under Extended, with no Unmapped section and no extended fetch', async () => {
    render(panel(props({ fieldStats: [{ field: 'src_ip', count: 1, uniqueCount: 1, topValues: [] }] })));
    await waitFor(() => expect(header('Extended')).toBeTruthy());
    expect(header('Extended').getAttribute('title')).toBe('Non-indexed fields stored in the ext JSON');
    fireEvent.click(header('Extended'));
    expect(screen.getByText('ext.custom_key')).toBeTruthy();
    expect(screen.queryByText(/^Unmapped/)).toBeNull();
    expect(mocks.extended).not.toHaveBeenCalled();
  });
});
