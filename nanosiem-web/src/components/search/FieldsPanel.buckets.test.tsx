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

const mocks = vi.hoisted(() => ({ ext: vi.fn(), extended: vi.fn(), schema: vi.fn() }));
vi.mock('@/lib/api', () => ({
  api: {
    getExtFieldNames: mocks.ext,
    getExtendedFieldNames: mocks.extended,
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
