import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { toApiTimeRange, type TimeRangeValue } from '@/lib/time-range';

import { api, errorMessage } from '../lib/ipc';
import type {
  DashboardDetail,
  DashboardSummary,
  PanelConfig,
} from '../lib/types';
import { Panel, type PanelState } from './Panel';
import { TimeRangePicker } from './TimeRangePicker';
import { Spinner } from './ui';

/**
 * The platform's dashboards — the same ones the web app reads and writes.
 *
 * The definition stays canonical in PostgreSQL and every panel is run through
 * `/api/dashboards/panel/query`, exactly as the web app runs it. That is the whole
 * point: a dashboard built in either client renders identically in the other, and
 * neither can drift into its own private idea of what a panel means.
 */

interface Props {
  /** A dashboard already chosen (e.g. one pivt just built), or the list. */
  dashboardId?: string;
  onOpen: (id: string) => void;
  /** Open a panel's query as a real search tab. */
  onDrill: (query: string) => void;
  /**
   * A dashboard that isn't saved yet — pivt's live draft. Rendered exactly like a
   * saved one, because it IS one; it just has no id yet.
   */
  draft?: DashboardDetail;
  /** Results pivt already got for the draft's panels. */
  draftStates?: Record<string, PanelState>;
}

export function DashboardsPane({ dashboardId, onOpen, onDrill, draft, draftStates }: Props) {
  if (draft) {
    return <DashboardView dashboard={draft} onDrill={onDrill} draft states={draftStates} />;
  }
  if (dashboardId) return <DashboardLoader id={dashboardId} onDrill={onDrill} />;
  return <DashboardList onOpen={onOpen} />;
}

function DashboardList({ onOpen }: { onOpen: (id: string) => void }) {
  const [dashboards, setDashboards] = useState<DashboardSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listDashboards()
      .then(setDashboards)
      .catch((caught) => setError(errorMessage(caught)));
  }, []);

  return (
    <div className="min-h-0 flex-1 overflow-auto p-5">
      <div className="text-[15px] font-semibold text-t1">Dashboards</div>
      <div className="mt-1 text-[11.5px] text-t4">
        The same dashboards as the web app — one definition, both clients.
      </div>

      {error && (
        <div className="mt-3 rounded-[9px] border border-danger/40 bg-danger-soft px-3.5 py-2.5 text-[12px] break-words text-danger">
          {error}
        </div>
      )}

      {!dashboards && !error && (
        <div className="mt-5 flex items-center gap-2 text-[12px] text-t3">
          <Spinner className="text-accent" /> Loading…
        </div>
      )}

      {dashboards?.length === 0 && (
        <div className="mt-5 text-[12.5px] text-t4">
          No dashboards yet. Ask pivt to build one (⌘I) — it can author, run and save it.
        </div>
      )}

      <div className="mt-4 space-y-1.5">
        {dashboards?.map((dashboard) => (
          <button
            key={dashboard.id}
            onClick={() => onOpen(dashboard.id)}
            className="flex w-full items-center gap-3 rounded-[9px] border border-line bg-inset px-3.5 py-2.5 text-left hover:bg-hover"
          >
            <div className="min-w-0 flex-1">
              {/* Dashboard names come from the data store and can contain anything —
                  this instance has one literally called `<img src=x onerror=…>`.
                  React escapes it; it renders as text, which is correct. */}
              <div className="truncate text-[12.5px] text-t1">{dashboard.name}</div>
              {dashboard.description && (
                <div className="truncate text-[11px] text-t4">{dashboard.description}</div>
              )}
            </div>
            <span className="shrink-0 font-mono text-[10.5px] text-t4">
              {dashboard.panel_count} {dashboard.panel_count === 1 ? 'panel' : 'panels'}
            </span>
            <span className="shrink-0 rounded-[20px] border border-line-strong px-2 py-0.5 font-mono text-[10px] text-t3">
              {dashboard.visibility}
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}

function DashboardLoader({ id, onDrill }: { id: string; onDrill: (query: string) => void }) {
  const [dashboard, setDashboard] = useState<DashboardDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setDashboard(null);
    setError(null);
    api
      .getDashboard(id)
      .then((found) => {
        if (!cancelled) setDashboard(found);
      })
      .catch((caught) => {
        if (!cancelled) setError(errorMessage(caught));
      });
    return () => {
      cancelled = true;
    };
  }, [id]);

  if (error) {
    return (
      <div className="m-5 rounded-[9px] border border-danger/40 bg-danger-soft px-3.5 py-2.5 text-[12px] break-words text-danger">
        {error}
      </div>
    );
  }
  if (!dashboard) {
    return (
      <div className="flex flex-1 items-center justify-center gap-2 text-[12px] text-t3">
        <Spinner className="text-accent" /> Loading dashboard…
      </div>
    );
  }
  return <DashboardView dashboard={dashboard} onDrill={onDrill} />;
}

const GRID_COLUMNS = 12;

function DashboardView({
  dashboard,
  onDrill,
  draft,
  states: incoming,
}: {
  dashboard: DashboardDetail;
  onDrill: (query: string) => void;
  draft?: boolean;
  /** Panel results handed in from outside — pivt's, for a draft it is building. */
  states?: Record<string, PanelState>;
}) {
  const layout = dashboard.layout ?? { columns: GRID_COLUMNS, rowHeight: 80, items: [] };
  const rowHeight = layout.rowHeight || 80;
  const columns = layout.columns || GRID_COLUMNS;

  const [range, setRange] = useState<TimeRangeValue>(() => initialRange(dashboard));
  const [variables, setVariables] = useState<Record<string, string>>(() =>
    Object.fromEntries(
      (layout.variables ?? []).map((variable) => [variable.name, variable.defaultValue ?? ''])
    )
  );
  const [states, setStates] = useState<Record<string, PanelState>>({});

  // pivt's results, merged in as they land. They win over anything this component
  // ran itself — the agent's rows ARE the panel, and re-fetching them would just
  // show the analyst the same numbers a second later.
  useEffect(() => {
    if (incoming) setStates((current) => ({ ...current, ...incoming }));
  }, [incoming]);

  // A draft's panels arrive one at a time as pivt validates them, so the panel set
  // is not stable — key the run on the ids, not the array identity.
  const panelIds = useMemo(
    () => (dashboard.panels ?? []).map((panel) => panel.id).join(','),
    [dashboard.panels]
  );

  // Each run gets a number. A response from an older run — a wider window the
  // analyst has already moved on from — must not land on top of a newer one.
  const generation = useRef(0);

  const runAll = useCallback(
    (bypassCache = false) => {
      const timeRange = toApiTimeRange(range);
      generation.current += 1;
      const run = generation.current;

      for (const panel of dashboard.panels ?? []) {
        // A panel pivt is still drafting may have no query yet.
        if (!panel.query) continue;

        setStates((current) => ({ ...current, [panel.id]: { status: 'running' } }));

        api
          .panelQuery(
            panel.query,
            panel.queryMode ?? 'piped',
            panel.timeRangeMode === 'custom' && panel.customTimeRange
              ? panel.customTimeRange
              : timeRange,
            variables,
            bypassCache
          )
          .then((data) => {
            if (generation.current !== run) return;
            setStates((current) => ({ ...current, [panel.id]: { status: 'done', data } }));
          })
          .catch((caught) => {
            if (generation.current !== run) return;
            const message = errorMessage(caught);
            setStates((current) => ({
              ...current,
              [panel.id]: {
                status: 'error',
                message,
                // A prevalence query with no filter is refused BY DESIGN — the
                // backend won't scan every artifact. It's a state, not a fault.
                unscopedPrevalence: /UNSCOPED_PREVALENCE|unscoped prevalence/i.test(message),
              },
            }));
          });
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [panelIds, range, variables, dashboard.panels]
  );

  // Run on open (and whenever pivt adds a panel to a draft). `autoRun: false` means
  // the dashboard's author wanted it to wait — respect that, except for a draft,
  // which exists precisely to be watched as it fills in.
  // Re-run when the panels change OR the window does. Keying only on the panels
  // meant the time picker moved and nothing happened: it read "Last 7 days" over
  // panels still showing the 24h data they loaded on open.
  const ran = useRef('');
  useEffect(() => {
    // A draft's panels are already run — pivt ran them. Running them again here
    // would double the load and change nothing.
    if (draft) return;
    if (layout.autoRun !== true) return;

    const key = `${panelIds}|${JSON.stringify(toApiTimeRange(range))}`;
    if (ran.current === key) return;
    ran.current = key;
    runAll();
  }, [panelIds, range, draft, layout.autoRun, runAll]);

  const items = new Map((layout.items ?? []).map((item) => [item.i, item]));

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex shrink-0 items-center gap-2.5 border-b border-line px-5 py-3">
        <div className="min-w-0">
          <div className="truncate text-[14px] font-semibold text-t1">{dashboard.name}</div>
          {draft && (
            <div className="font-mono text-[10.5px] text-accent">
              ✳ pivt is building this — panels appear as it validates them
            </div>
          )}
        </div>
        <span className="flex-1" />
        <TimeRangePicker value={range} onChange={setRange} />
        <button
          onClick={() => runAll(true)}
          className="shrink-0 rounded-[9px] border border-accent-line bg-accent-fill px-3.5 py-2 text-[12px] font-semibold text-accent"
        >
          Refresh
        </button>
      </div>

      {(layout.variables ?? []).length > 0 && (
        <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-line px-5 py-2">
          {(layout.variables ?? []).map((variable) => (
            <label key={variable.name} className="flex items-center gap-1.5">
              <span className="text-[11px] text-t4">{variable.label || variable.name}</span>
              {variable.type === 'dropdown' && variable.options ? (
                <select
                  value={variables[variable.name] ?? ''}
                  onChange={(event) =>
                    setVariables((current) => ({
                      ...current,
                      [variable.name]: event.target.value,
                    }))
                  }
                  className="rounded-[6px] border border-line-strong bg-input px-2 py-1 font-mono text-[11px] text-t1"
                >
                  <option value="">(any)</option>
                  {variable.options.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  value={variables[variable.name] ?? ''}
                  onChange={(event) =>
                    setVariables((current) => ({
                      ...current,
                      [variable.name]: event.target.value,
                    }))
                  }
                  placeholder="(any)"
                  className="w-[130px] rounded-[6px] border border-line-strong bg-input px-2 py-1 font-mono text-[11px] text-t1 placeholder:text-t4"
                />
              )}
            </label>
          ))}
          <button
            onClick={() => runAll()}
            className="rounded-[6px] border border-line-strong px-2 py-1 text-[11px] text-t3 hover:text-t1"
          >
            Apply
          </button>
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto p-4">
        {(dashboard.panels ?? []).length === 0 ? (
          <div className="mt-10 text-center text-[12.5px] text-t4">
            {draft ? 'pivt hasn’t added a panel yet…' : 'This dashboard has no panels.'}
          </div>
        ) : (
          // The layout is react-grid-layout's coordinate space. Rendering it as a
          // CSS grid reproduces it exactly for a read-only view, without pulling in
          // the drag-and-drop library — and it cannot disagree with the web app,
          // because both are driven off the same x/y/w/h.
          <div
            className="grid gap-3"
            style={{
              gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))`,
              gridAutoRows: `${rowHeight}px`,
            }}
          >
            {(dashboard.panels ?? []).map((panel) => (
              <PanelSlot
                key={panel.id}
                panel={panel}
                item={items.get(panel.id)}
                state={states[panel.id] ?? { status: 'idle' }}
                dashboardId={dashboard.id}
                onDrill={onDrill}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function PanelSlot({
  panel,
  item,
  state,
  dashboardId,
  onDrill,
}: {
  panel: PanelConfig;
  item?: { x: number; y: number; w: number; h: number };
  state: PanelState;
  dashboardId?: string;
  onDrill: (query: string) => void;
}) {
  // A panel with no layout item would render nowhere in the web app. Here it gets
  // a default slot rather than vanishing — an invisible panel is worse than a
  // misplaced one, and this is exactly the state pivt's drafts pass through.
  const style = item
    ? {
        gridColumn: `${item.x + 1} / span ${item.w}`,
        gridRow: `${item.y + 1} / span ${item.h}`,
      }
    : { gridColumn: 'span 6', gridRow: 'span 3' };

  return (
    <div style={style} className="min-h-0">
      <Panel
        panel={panel}
        state={state}
        onDrill={onDrill}
        onPin={
          dashboardId
            ? () => void api.pinPanel(dashboardId, panel.id).catch(() => undefined)
            : undefined
        }
      />
    </div>
  );
}

function initialRange(dashboard: DashboardDetail): TimeRangeValue {
  const preset = dashboard.layout?.defaultTimeRange;
  if (preset?.type === 'preset') return { type: 'preset', preset: preset.preset };
  if (preset?.type === 'custom') {
    return { type: 'custom', start: new Date(preset.start), end: new Date(preset.end) };
  }
  return { type: 'preset', preset: 'Last 24 hours' };
}
