// NAN-5595: dashboard edits are nPL panels only, offered only where the server
// accepts the save, bound to the dashboard version the card showed
// (expected_updated_at), and run through pivtApi (the analyst, marked pivt).
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Dashboard, PanelConfig } from '@/lib/api/types';
import { capPageContext, PivtRefusal } from '@/contexts/pivt-page';

const mock = vi.hoisted(() => ({ get: vi.fn(), update: vi.fn(), query: vi.fn() }));
vi.mock('@/lib/api/pivt-api', () => ({
  pivtApi: { getDashboard: mock.get, updateDashboard: mock.update, panelQuery: mock.query },
}));

import { DASHBOARD_CONTEXT_BUDGET, dashboardEditActions, dashboardSummary, dashboardViewActions, previewWindow, summarizeRows } from './dashboardsPivt';

const panel = (id: string, over: Partial<PanelConfig> = {}): PanelConfig => ({
  id,
  title: `panel ${id}`,
  query: 'class_name="Authentication" | stats count by user',
  queryMode: 'piped',
  visualizationType: 'table',
  visualizationConfig: {},
  timeRangeMode: 'dashboard',
  drilldownEnabled: true,
  ...over,
});

const dash = (over: Partial<Dashboard> = {}): Dashboard =>
  ({
    id: 'dash_1',
    name: 'SOC overview',
    layout: { columns: 12, rowHeight: 80, items: [{ i: 'p1', x: 0, y: 0, w: 6, h: 4 }], variables: [{ name: 'host', label: 'Host', type: 'text' }] },
    panels: [panel('p1'), panel('p_sql', { queryMode: 'sql', query: 'SELECT 1' }), panel('p_metric', { visualizationType: 'obs_metric', query: '' })],
    visibility: 'private',
    is_owner: true,
    created_at: '2026-11-17T00:00:00Z',
    updated_at: '2026-11-17T10:00:00Z',
    ...over,
  }) as Dashboard;

let shown: Dashboard | null;
const target = () => ({
  dashboard: () => shown,
  timeRange: () => ({ start: '2026-11-17T00:00:00Z', end: '2026-11-17T01:00:00Z' }),
  substitute: (q: string) => q.replaceAll('$host', '"web-1"'),
  onChanged: vi.fn(),
});

beforeEach(() => {
  vi.clearAllMocks();
  shown = dash();
  mock.get.mockImplementation(async () => dash());
  mock.update.mockResolvedValue({});
  mock.query.mockResolvedValue({ results: [], total_count: 42, execution_time_ms: 5 });
});

function spec(name: string, t = target(), canEdit = true) {
  const s = dashboardEditActions(t, { canEdit }).find((a) => a.name === name);
  if (!s) throw new Error(`${name} not offered`);
  return s;
}

describe('dashboard edit actions', () => {
  it('need dashboards:edit, change state, and are offered only where the server accepts the save', () => {
    const all = dashboardEditActions(target(), { canEdit: true });
    expect(all.map((a) => [a.name, a.permission, a.mutates])).toEqual([
      ['dashboards.add_panel', ['dashboards:edit', 'search:execute'], true],
      ['dashboards.edit_panel', ['dashboards:edit', 'search:execute'], true],
    ]);
    expect(dashboardEditActions(target(), { canEdit: false })).toEqual([]);
  });

  it('add_panel binds the dashboard version, previews the query read-only, then saves with expected_updated_at', async () => {
    const t = target();
    const s = spec('dashboards.add_panel', t);
    const bound = s.bind!({ title: ' Top users ', query: ' host=$host | stats count by user ', visualization: 'bar' });
    expect(bound).toMatchObject({ title: 'Top users', dashboard_id: 'dash_1', expected_updated_at: '2026-11-17T10:00:00Z' });
    const p = await s.preview!(bound);
    expect(p.rows).toContainEqual(['preview', '42 rows in the current time range']);
    // Variables substituted the way the page runs panels; the panel keeps $host.
    expect(mock.query).toHaveBeenCalledWith({
      query: 'host="web-1" | stats count by user',
      query_mode: 'piped',
      time_range: { start: '2026-11-17T00:00:00Z', end: '2026-11-17T01:00:00Z' },
    });
    expect(mock.update).not.toHaveBeenCalled();

    await s.run(bound);
    const [id, data] = mock.update.mock.calls[0];
    expect(id).toBe('dash_1');
    expect(data.expected_updated_at).toBe('2026-11-17T10:00:00Z');
    const added = data.panels.at(-1);
    expect(added).toMatchObject({ title: 'Top users', query: 'host=$host | stats count by user', queryMode: 'piped', visualizationType: 'bar' });
    expect(data.panels).toHaveLength(4);
    expect(data.layout.items.at(-1)).toMatchObject({ i: added.id, x: 0, y: 4 });
    expect(data.layout.variables).toEqual([{ name: 'host', label: 'Host', type: 'text' }]);
    expect(t.onChanged).toHaveBeenCalled();
  });

  it('a query error shows in the preview instead of failing the card', async () => {
    mock.query.mockRejectedValue(new Error('unknown command: statz'));
    const s = spec('dashboards.add_panel');
    const p = await s.preview!(s.bind!({ title: 't', query: 'x | statz', visualization: 'table' }));
    expect(p.rows).toContainEqual(['preview', 'query error: unknown command: statz']);
  });

  it('refuses to save over a newer version of the dashboard, or onto another dashboard', async () => {
    const s = spec('dashboards.add_panel');
    const bound = s.bind!({ title: 't', query: 'x=1', visualization: 'table' });
    mock.get.mockResolvedValue(dash({ updated_at: '2026-11-17T11:00:00Z' }));
    await expect(s.run(bound)).rejects.toThrow('changed since this card was shown');
    shown = dash({ id: 'dash_2' });
    await expect(s.run(bound)).rejects.toThrow('different dashboard');
    expect(mock.update).not.toHaveBeenCalled();
  });

  it('a preview scans at most the last 24 hours of the page window', async () => {
    expect(previewWindow({ start: '2026-10-18T00:00:00Z', end: '2026-11-17T00:00:00Z' })).toEqual({
      range: { start: '2026-11-16T00:00:00.000Z', end: '2026-11-17T00:00:00Z' },
      clamped: true,
    });
    const t = { ...target(), timeRange: () => ({ start: '2026-10-18T00:00:00Z', end: '2026-11-17T00:00:00Z' }) };
    const s = spec('dashboards.add_panel', t);
    const p = await s.preview!(s.bind!({ title: 't', query: 'x=1', visualization: 'table' }));
    expect(p.rows).toContainEqual(['preview', '42 rows in the last 24 hours of the window']);
  });

  it('refuses an empty panel or an unknown visualization', () => {
    const s = spec('dashboards.add_panel');
    expect(() => s.bind!({ title: ' ', query: 'x=1', visualization: 'table' })).toThrow(PivtRefusal);
    expect(() => s.bind!({ title: 't', query: 'x=1', visualization: 'obs_metric' })).toThrow('Unsupported visualization');
  });

  it('edit_panel changes only the named nPL panel, with a diff, and never rewrites SQL or metric panels', async () => {
    const s = spec('dashboards.edit_panel');
    expect(() => s.bind!({ panel_id: 'p_missing', title: 'x' })).toThrow('not on this dashboard');
    expect(() => s.bind!({ panel_id: 'p_sql', query: 'x=1' })).toThrow('not an nPL panel');
    expect(() => s.bind!({ panel_id: 'p_metric', title: 'x' })).toThrow('not an nPL panel');
    expect(() => s.bind!({ panel_id: 'p1' })).toThrow('Nothing to change');
    // A legacy panel with no queryMode is nPL.
    shown = dash({ panels: [panel('p_legacy', { queryMode: undefined as unknown as 'piped' })] });
    expect(s.bind!({ panel_id: 'p_legacy', title: 'renamed' })).toMatchObject({ panel_id: 'p_legacy', title: 'renamed' });
    shown = dash();

    const bound = s.bind!({ panel_id: 'p1', query: 'class_name="Authentication" | stats count by src_ip' });
    const p = await s.preview!(bound);
    expect(p.diff).toEqual({
      before: 'class_name="Authentication" | stats count by user',
      after: 'class_name="Authentication" | stats count by src_ip',
      lang: 'npl',
    });
    await s.run(bound);
    const data = mock.update.mock.calls[0][1];
    expect(data.expected_updated_at).toBe('2026-11-17T10:00:00Z');
    expect(data.panels.find((x: PanelConfig) => x.id === 'p1').query).toBe('class_name="Authentication" | stats count by src_ip');
    expect(data.panels.find((x: PanelConfig) => x.id === 'p_sql').query).toBe('SELECT 1');
  });
});

describe('dashboard view actions (read-only)', () => {
  it('set the time range from the presets and only defined variables', async () => {
    const setPreset = vi.fn();
    const setVariable = vi.fn();
    const [range, variable] = dashboardViewActions({ variables: () => ['host'], setPreset, setVariable });
    expect([range.mutates, variable.mutates]).toEqual([false, false]);
    await range.run({ preset: 'Last 7 days' });
    expect(setPreset).toHaveBeenCalledWith('Last 7 days');
    await expect(range.run({ preset: 'forever' })).rejects.toThrow('Unsupported');
    expect(() => variable.bind!({ name: 'user', value: 'x' })).toThrow('no variable user');
    await variable.run(variable.bind!({ name: 'host', value: 'db-2' }));
    expect(setVariable).toHaveBeenCalledWith('host', 'db-2');
  });
});

describe('dashboard page context', () => {
  it('sheds detail instead of losing everything when every panel is long and failing', () => {
    const d = dash({
      panels: Array.from({ length: 12 }, (_, i) =>
        panel(`panel-1794938000000-${String(i).padStart(8, '0')}`, { title: 't'.repeat(200), query: '"q"'.repeat(1300) }),
      ),
    });
    const summary = dashboardSummary(d, () => ({ status: 'error', error: '"e"'.repeat(300), sample: 'k=v'.repeat(200) }));
    expect(new TextEncoder().encode(JSON.stringify(summary)).length).toBeLessThanOrEqual(DASHBOARD_CONTEXT_BUDGET + 64);
    expect(summary.panels.length).toBeGreaterThan(0);
    const { truncated, context } = capPageContext({ pageKey: 'dashboard', title: 'Dashboard', data: { ...summary, window: { start: 'a', end: 'b' } } });
    expect(truncated).toBe(false);
    expect(context.data).toBeDefined();
  });

  it('survives a malformed (imported) layout', () => {
    const d = dash({ layout: { columns: 12, rowHeight: 80, items: [], variables: 'oops' as unknown as [] } });
    expect(dashboardSummary(d, () => undefined).dashboard.variables).toEqual([]);
  });

  it('stays under the 8 KB cap with many panels and wide results', () => {
    const wide = Object.fromEntries(Array.from({ length: 30 }, (_, i) => [`field_${i}`, 'v'.repeat(400)]));
    const d = dash({
      name: 'n'.repeat(120),
      panels: Array.from({ length: 30 }, (_, i) => panel(`panel-1794938000000-${String(i).padStart(8, '0')}`, { title: 'Top source IPs', query: 'q'.repeat(150) })),
    });
    // Typical panels, wide results: the first panels keep a one-line sample.
    const summary = dashboardSummary(d, () => ({ status: 'success', rows: 10000, sample: summarizeRows([wide, wide]) }));
    const { truncated, context } = capPageContext({
      pageKey: 'dashboard',
      title: `Dashboard · ${d.name}`,
      entity: { kind: 'dashboard', id: d.id, name: d.name },
      facts: [{ label: 'panels', value: '30' }, { label: 'window', value: 'Last 24 hours' }, { label: 'owner', value: 'you' }],
      data: { ...summary, window: { start: '2026-11-17T00:00:00Z', end: '2026-11-18T00:00:00Z' }, variables: { host: 'h'.repeat(256) } },
    });
    expect(truncated).toBe(false);
    expect((context.data?.panels as unknown[]).length).toBeGreaterThanOrEqual(8);
    expect((context.data?.panels as Array<{ sample: string | null }>)[0].sample).toMatch(/^field_0=v+…, field_1=/);
    expect((context.data?.panels as Array<{ sample: string | null }>)[5].sample).toBeNull();
  });
});
