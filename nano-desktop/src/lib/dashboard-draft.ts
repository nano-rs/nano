import type { DashboardDetail, PanelConfig, VisualizationType } from './types';

/**
 * The dashboard pivt is building, right now, while the analyst watches.
 *
 * pivt validates one panel at a time (`dashboard_panel_query`), and each call
 * carries the panel it belongs to. So the app doesn't have to wait for the agent
 * to finish and hand over a finished object — it can place the panel the moment it
 * is proven to return rows. The analyst watches the dashboard assemble itself
 * instead of a spinner, and if panel three comes back empty they see that too,
 * before it is saved.
 *
 * The draft is a real `DashboardDetail`. It just has no id yet.
 */

/** The web app's own ideal sizes, so a draft lays out like a saved dashboard. */
const IDEAL_SIZE: Record<string, { w: number; h: number }> = {
  single_value: { w: 3, h: 2 },
  pie: { w: 4, h: 3 },
  bar: { w: 6, h: 3 },
  ranked_bar: { w: 6, h: 3 },
  line: { w: 6, h: 3 },
  area: { w: 6, h: 3 },
  timeline: { w: 6, h: 3 },
  table: { w: 6, h: 4 },
  transaction: { w: 6, h: 4 },
};

const COLUMNS = 12;

export function emptyDraft(name = 'New dashboard'): DashboardDetail {
  return {
    id: '',
    name,
    layout: { columns: COLUMNS, rowHeight: 80, items: [], autoRun: true },
    panels: [],
    visibility: 'private',
    updated_at: '',
  };
}

/**
 * Place a panel pivt just validated.
 *
 * Laid out left-to-right, wrapping — the same shape the web editor produces when
 * you append panels. pivt's own final `layout` replaces this when it saves; this
 * is only what the analyst watches being built.
 */
export function addDraftPanel(draft: DashboardDetail, panel: PanelConfig): DashboardDetail {
  // Re-validating the same panel (pivt fixing a query) updates it in place rather
  // than stacking a second copy.
  const existing = draft.panels.findIndex((candidate) => candidate.id === panel.id);
  if (existing >= 0) {
    const panels = [...draft.panels];
    panels[existing] = { ...panels[existing], ...panel };
    return { ...draft, panels };
  }

  const size = IDEAL_SIZE[panel.visualizationType] ?? { w: 6, h: 3 };
  const items = draft.layout.items;

  // Find the first row where this panel fits, scanning down. Cheap, and it keeps
  // the grid tight rather than one-panel-per-row.
  const bottom = items.reduce((lowest, item) => Math.max(lowest, item.y + item.h), 0);
  let x = 0;
  let y = bottom;

  for (let row = 0; row <= bottom; row += 1) {
    for (let column = 0; column + size.w <= COLUMNS; column += 1) {
      const overlaps = items.some(
        (item) =>
          column < item.x + item.w &&
          item.x < column + size.w &&
          row < item.y + item.h &&
          item.y < row + size.h
      );
      if (!overlaps) {
        x = column;
        y = row;
        row = bottom + 1; // break the outer loop
        break;
      }
    }
  }

  return {
    ...draft,
    panels: [...draft.panels, panel],
    layout: {
      ...draft.layout,
      items: [...items, { i: panel.id, x, y, w: size.w, h: size.h }],
    },
  };
}

/**
 * The panel described by a `dashboard_panel_query` tool call.
 *
 * The `panel` argument is optional in the tool schema — pivt may run a query
 * without one, just to look at data. Without it there is no panel to draw, and we
 * say so by returning null rather than inventing a title and a chart type.
 */
export function panelFromToolInput(input: Record<string, unknown>): PanelConfig | null {
  const hint = input.panel;
  if (typeof hint !== 'object' || hint === null) return null;

  const panel = hint as Record<string, unknown>;
  const query = typeof input.query === 'string' ? input.query : '';
  if (!query) return null;

  const id = typeof panel.id === 'string' && panel.id ? panel.id : `panel-${hashOf(query)}`;

  return {
    id,
    title: typeof panel.title === 'string' && panel.title ? panel.title : 'Panel',
    query,
    queryMode: input.query_mode === 'sql' ? 'sql' : 'piped',
    visualizationType: (typeof panel.visualizationType === 'string'
      ? panel.visualizationType
      : 'bar') as VisualizationType,
    visualizationConfig: {},
    timeRangeMode: 'dashboard',
    drilldownEnabled: true,
  };
}

/** Stable id for a panel pivt didn't name, so re-running the same query updates it. */
function hashOf(value: string): string {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) | 0;
  }
  return Math.abs(hash).toString(36);
}

/**
 * What pivt got back from `dashboard_panel_query`, as a panel result.
 *
 * The agent already RAN the query — re-running it here would double the load on
 * the analyst's own cluster to show them the same rows a second later. The tool
 * result is the data.
 */
export function panelDataFromToolResult(result: string): {
  results: Record<string, unknown>[];
  total_count: number;
  execution_time_ms: number;
  column_order?: string[];
} | null {
  try {
    const parsed = JSON.parse(result) as Record<string, unknown>;
    if (!Array.isArray(parsed.results)) return null;
    return {
      results: parsed.results as Record<string, unknown>[],
      total_count: typeof parsed.total_count === 'number' ? parsed.total_count : 0,
      execution_time_ms:
        typeof parsed.execution_time_ms === 'number' ? parsed.execution_time_ms : 0,
      column_order: Array.isArray(parsed.column_order)
        ? (parsed.column_order as string[])
        : undefined,
    };
  } catch {
    // A tool result that isn't JSON is a failure message. The caller shows it.
    return null;
  }
}

/** The dashboard id pivt just created or updated, from the tool's result. */
export function savedDashboardId(result: string): string | null {
  try {
    const parsed = JSON.parse(result) as Record<string, unknown>;
    return typeof parsed.id === 'string' ? parsed.id : null;
  } catch {
    return null;
  }
}
