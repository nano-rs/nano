// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5595: what pivt knows and may do on a dashboard (the shared
// `usePivtPage` contract, NAN-5571). Context comes from data the page already
// holds; edits call the REST client as the analyst (`pivtApi`, audited with
// `request_origin: pivt`).
//
// Edits are saved with the `updated_at` the card was bound against
// (`expected_updated_at`): if the dashboard changed after the analyst saw the
// card, the save is refused (409) instead of overwriting the newer version.
// Panels pivt writes are nPL ("machines → SQL, humans → nPL"); a SQL or
// metric panel is never rewritten.
import { definePivtAction, PivtRefusal, type PivtActionSpec } from '@/contexts/pivt-page';
import { pivtApi } from '@/lib/api/pivt-api';
import type {
  Dashboard,
  DashboardLayout,
  LayoutItem,
  PanelConfig,
  TimeRange,
  UpdateDashboardRequest,
  VisualizationType,
} from '@/lib/api/types';

/** Visualizations pivt may choose for a new panel. */
export const PIVT_VISUALIZATIONS: VisualizationType[] = [
  'table', 'bar', 'line', 'area', 'pie', 'single_value', 'ranked_bar', 'timeline',
];

/** Time-range presets the page understands. */
export const TIME_PRESETS = [
  'Last 15 minutes', 'Last hour', 'Last 4 hours', 'Last 12 hours', 'Last 24 hours', 'Last 7 days', 'Last 30 days',
];

const MAX_CONTEXT_PANELS = 12;
/** Panels whose current rows are sampled into the context (8 KB in total). */
const SAMPLED_PANELS = 3;
const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n)}…` : s);

/** A panel's current result, small (query output: the server fences it). */
export interface PanelResultSummary {
  status: string;
  rows?: number;
  error?: string;
  /** First row as one line (`k=v, …`); the page context allows depth 4 only. */
  sample?: string;
}

/** The first row(s) of a result as one short line. */
export function summarizeRows(rows: Record<string, unknown>[] | undefined, take = 1): string | undefined {
  const picked = (rows ?? []).slice(0, take);
  if (picked.length === 0) return undefined;
  const line = picked
    .map((row) =>
      Object.entries(row)
        .slice(0, 6)
        .map(([k, v]) => `${k}=${clip(typeof v === 'string' ? v : JSON.stringify(v) ?? '', 60)}`)
        .join(', '),
    )
    .join(' | ');
  return clip(line, 400);
}

/** Budget for the dashboard part of the page context (the whole context is
    capped at 8 KB, and over the cap the page's `data` is dropped entirely). */
export const DASHBOARD_CONTEXT_BUDGET = 6 * 1024;
const size = (v: unknown) => new TextEncoder().encode(JSON.stringify(v)).length;

/**
 * Compact view of a dashboard and what its panels show now, shaped for the
 * page context's limits (depth 4, 8 KB): `dashboard` and `panels` both sit
 * directly under `data`, and every panel field is a scalar. Over budget it
 * sheds detail in order (samples, then long text, then trailing panels) and
 * says so (`panels_truncated`), rather than losing everything.
 */
export function dashboardSummary(d: Dashboard, results: (panelId: string) => PanelResultSummary | undefined) {
  const variables = Array.isArray(d.layout?.variables) ? d.layout.variables : [];
  const allPanels = Array.isArray(d.panels) ? d.panels : [];
  const build = (textMax: number, sampled: number) =>
    allPanels.slice(0, MAX_CONTEXT_PANELS).map((p, i) => {
      const r = results(p.id);
      return {
        id: p.id,
        title: clip(p.title ?? '', Math.min(80, textMax)),
        viz: p.visualizationType,
        mode: p.queryMode ?? 'piped',
        query: clip(p.query ?? '', textMax),
        status: r?.status ?? 'not run',
        rows: r?.rows ?? null,
        error: r?.error ? clip(r.error, textMax) : null,
        sample: i < sampled ? (r?.sample ?? null) : null,
      };
    });
  const dashboard = {
    id: d.id,
    name: clip(d.name, 120),
    description: d.description ? clip(d.description, 200) : null,
    visibility: d.visibility,
    owner: d.owner_name ?? null,
    variables: variables.map((v) => clip(String(v.name), 64)),
    panel_count: allPanels.length,
  };
  let panels = build(200, SAMPLED_PANELS);
  if (size({ dashboard, panels }) > DASHBOARD_CONTEXT_BUDGET) panels = build(200, 0);
  if (size({ dashboard, panels }) > DASHBOARD_CONTEXT_BUDGET) panels = build(80, 0);
  let truncated = panels.length < allPanels.length;
  while (panels.length > 1 && size({ dashboard, panels }) > DASHBOARD_CONTEXT_BUDGET) {
    panels = panels.slice(0, -1);
    truncated = true;
  }
  return { dashboard, panels, panels_truncated: truncated };
}

export interface DashboardTarget {
  /** The dashboard on screen (null while it loads). */
  dashboard: () => Dashboard | null;
  /** The page's current window (for the preview query). */
  timeRange: () => TimeRange;
  /** Substitute the page's variables (defaults included) exactly as the page does. */
  substitute: (query: string) => string;
  /** Refresh the page after a save. */
  onChanged?: () => void;
}

function open(t: DashboardTarget): Dashboard {
  const d = t.dashboard();
  if (!d) throw new PivtRefusal('The dashboard has not loaded yet.');
  return d;
}

/** Fetch the dashboard again and refuse if it changed since the card was bound. */
async function current(id: string, expected: string): Promise<Dashboard> {
  const fresh = await pivtApi.getDashboard(id);
  if (fresh.updated_at !== expected) {
    throw new Error('The dashboard changed since this card was shown; reload it and ask pivt again.');
  }
  return fresh;
}

async function save(d: Dashboard, panels: PanelConfig[], layout: DashboardLayout, expected: string) {
  // The TS request type predates the concurrency field (as in DashboardView).
  const data = { panels, layout, expected_updated_at: expected } as unknown as UpdateDashboardRequest;
  await pivtApi.updateDashboard(d.id, data);
}

function layoutBelow(panelId: string, items: LayoutItem[]): LayoutItem {
  const maxY = items.reduce((m, it) => Math.max(m, (it.y || 0) + (it.h || 4)), 0);
  return { i: panelId, x: 0, y: maxY, w: 6, h: 4, minW: 2, minH: 2 };
}

function newPanelId(): string {
  const rand = typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID().slice(0, 8) : Math.random().toString(36).slice(2, 10);
  return `panel-${Date.now()}-${rand}`;
}

/** Longest window a preview query scans (the card renders before consent). */
export const PREVIEW_MAX_MS = 24 * 60 * 60 * 1000;

/** The page window, clamped to its last 24 hours for the preview. */
export function previewWindow(range: TimeRange): { range: TimeRange; clamped: boolean } {
  const end = Date.parse(range.end);
  const start = Date.parse(range.start);
  if (Number.isNaN(end) || Number.isNaN(start) || end - start <= PREVIEW_MAX_MS) return { range, clamped: false };
  return { range: { start: new Date(end - PREVIEW_MAX_MS).toISOString(), end: range.end }, clamped: true };
}

/** Read-only check of a proposed nPL query against (at most 24 h of) the page's window. */
async function previewRows(t: DashboardTarget, query: string): Promise<Array<[string, string]>> {
  const { range, clamped } = previewWindow(t.timeRange());
  try {
    const r = await pivtApi.panelQuery({ query: t.substitute(query), query_mode: 'piped', time_range: range });
    const where = clamped ? 'in the last 24 hours of the window' : 'in the current time range';
    return [['preview', `${r.total_count} row${r.total_count === 1 ? '' : 's'} ${where}`]];
  } catch (e) {
    return [['preview', `query error: ${clip(e instanceof Error ? e.message : String(e), 200)}`]];
  }
}

interface AddParams {
  title: string;
  query: string;
  visualization: VisualizationType;
  dashboard_id?: string;
  expected_updated_at?: string;
  panel_id?: string;
}

interface EditParams {
  panel_id: string;
  title?: string;
  query?: string;
  dashboard_id?: string;
  expected_updated_at?: string;
  before_title?: string;
  before_query?: string;
}

/**
 * Add / edit panel actions (`dashboards:edit`). Offered only where the server
 * would accept the save: the analyst owns the dashboard or holds
 * `settings:system` (`canEdit`).
 */
export function dashboardEditActions(t: DashboardTarget, opts: { canEdit: boolean }): PivtActionSpec[] {
  if (!opts.canEdit) return [];
  const add = definePivtAction<AddParams>({
    name: 'dashboards.add_panel',
    description: 'Add a panel to this dashboard: a title, an nPL query and a visualization.',
    params: {
      title: { type: 'string', description: 'Panel title', required: true, maxLength: 120 },
      query: { type: 'string', description: 'nPL query (never SQL)', required: true, maxLength: 4000 },
      visualization: { type: 'enum', description: 'How to show it', required: true, values: PIVT_VISUALIZATIONS },
    },
    // The panel's nPL runs through the search service (panel_query).
    permission: ['dashboards:edit', 'search:execute'],
    mutates: true,
    bind: (p) => {
      const d = open(t);
      const title = p.title.trim();
      const query = p.query.trim();
      if (!title || !query) throw new PivtRefusal('A panel needs a title and a query.');
      if (!PIVT_VISUALIZATIONS.includes(p.visualization)) throw new PivtRefusal('Unsupported visualization.');
      return { title, query, visualization: p.visualization, dashboard_id: d.id, expected_updated_at: d.updated_at, panel_id: newPanelId() };
    },
    preview: async (p) => ({
      summary: `Add the panel “${p.title}”`,
      rows: [['visualization', p.visualization], ['nPL', p.query], ...(await previewRows(t, p.query))],
    }),
    run: async (p) => {
      if (!p.dashboard_id || !p.expected_updated_at || !p.panel_id) throw new Error('No dashboard is bound to this card.');
      if (open(t).id !== p.dashboard_id) throw new Error('A different dashboard is open now.');
      const d = await current(p.dashboard_id, p.expected_updated_at);
      const panel: PanelConfig = {
        id: p.panel_id,
        title: p.title,
        query: p.query,
        queryMode: 'piped',
        visualizationType: p.visualization,
        visualizationConfig: {},
        timeRangeMode: 'dashboard',
        drilldownEnabled: true,
      };
      const layout = d.layout ?? { columns: 12, rowHeight: 80, items: [] };
      const items = Array.isArray(layout.items) ? layout.items : [];
      await save(d, [...(Array.isArray(d.panels) ? d.panels : []), panel], { ...layout, items: [...items, layoutBelow(panel.id, items)] }, p.expected_updated_at);
      t.onChanged?.();
      return { summary: `Added “${p.title}”. Run the dashboard to see it.` };
    },
  });

  const edit = definePivtAction<EditParams>({
    name: 'dashboards.edit_panel',
    description: "Change one nPL panel's title and/or query.",
    params: {
      panel_id: { type: 'string', description: 'The panel id (from the page context)', required: true, maxLength: 80 },
      title: { type: 'string', description: 'New title (omit to keep)', maxLength: 120 },
      query: { type: 'string', description: 'New nPL query (omit to keep; never SQL)', maxLength: 4000 },
    },
    permission: ['dashboards:edit', 'search:execute'],
    mutates: true,
    bind: (p) => {
      const d = open(t);
      const panel = (Array.isArray(d.panels) ? d.panels : []).find((x) => x.id === p.panel_id);
      if (!panel) throw new PivtRefusal(`Panel ${p.panel_id} is not on this dashboard.`);
      // A panel with no queryMode is nPL (the panel editor's default).
      if ((panel.queryMode ?? 'piped') !== 'piped' || panel.visualizationType === 'obs_metric') {
        throw new PivtRefusal(`Panel “${panel.title}” is not an nPL panel; edit it in the dashboard editor.`);
      }
      const title = p.title?.trim() || undefined;
      const query = p.query?.trim() || undefined;
      if (!title && !query) throw new PivtRefusal('Nothing to change.');
      return {
        panel_id: panel.id,
        title,
        query,
        dashboard_id: d.id,
        expected_updated_at: d.updated_at,
        before_title: panel.title,
        before_query: panel.query,
      };
    },
    preview: async (p) => ({
      summary: `Change the panel “${p.before_title}”`,
      rows: [
        ...(p.title ? ([['title', `${p.before_title} → ${p.title}`]] as Array<[string, string]>) : []),
        ...(p.query ? await previewRows(t, p.query) : []),
      ],
      ...(p.query ? { diff: { before: p.before_query ?? '', after: p.query, lang: 'npl' } } : {}),
    }),
    run: async (p) => {
      if (!p.dashboard_id || !p.expected_updated_at) throw new Error('No dashboard is bound to this card.');
      if (open(t).id !== p.dashboard_id) throw new Error('A different dashboard is open now.');
      const d = await current(p.dashboard_id, p.expected_updated_at);
      const panels = (Array.isArray(d.panels) ? d.panels : []).map((x) =>
        x.id === p.panel_id ? { ...x, ...(p.title ? { title: p.title } : {}), ...(p.query ? { query: p.query } : {}) } : x,
      );
      await save(d, panels, d.layout, p.expected_updated_at);
      t.onChanged?.();
      return { summary: `Updated “${p.title ?? p.before_title}”.` };
    },
  });
  return [add, edit];
}

/** Read-only page controls: the time range and the dashboard variables. */
export function dashboardViewActions(opts: {
  variables: () => string[];
  setPreset: (preset: string) => void;
  setVariable: (name: string, value: string) => void;
}): PivtActionSpec[] {
  return [
    definePivtAction<{ preset: string }>({
      name: 'dashboards.set_time_range',
      description: 'Set the dashboard time range.',
      params: { preset: { type: 'enum', description: 'Time range', required: true, values: TIME_PRESETS } },
      permission: 'dashboards:view',
      mutates: false,
      preview: (p) => ({ summary: `Show ${p.preset.toLowerCase()}` }),
      run: async (p) => {
        if (!TIME_PRESETS.includes(p.preset)) throw new Error('Unsupported time range.');
        opts.setPreset(p.preset);
        return { summary: `Time range: ${p.preset}` };
      },
    }),
    definePivtAction<{ name: string; value: string }>({
      name: 'dashboards.set_variable',
      description: 'Set a dashboard variable (by name) to a value.',
      params: {
        name: { type: 'string', description: 'Variable name', required: true, maxLength: 64 },
        value: { type: 'string', description: 'Value', required: true, maxLength: 256 },
      },
      permission: 'dashboards:view',
      mutates: false,
      bind: (p) => {
        if (!opts.variables().includes(p.name)) throw new PivtRefusal(`This dashboard has no variable ${p.name}.`);
        return p;
      },
      preview: (p) => ({ summary: `Set $${p.name}`, rows: [[p.name, p.value]] }),
      run: async (p) => {
        opts.setVariable(p.name, p.value);
        return { summary: `$${p.name} = ${p.value}` };
      },
    }),
  ];
}
