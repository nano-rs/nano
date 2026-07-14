import { useEffect, useMemo, useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { SERIES_COLORS, formatLabel, preparePanelData } from '../lib/panel';
import type { PanelConfig, PanelQueryResponse } from '../lib/types';
import { Spinner } from './ui';

/**
 * One dashboard panel, drawn from the rows `/api/dashboards/panel/query` returned.
 *
 * Recharts is a direct dependency of THIS package, not an import reached through
 * the `@` alias into the web app's node_modules — that path is the duplicate-module
 * trap that once blanked the whole Search screen in a production bundle.
 *
 * Everything rendered here — panel titles, group-by values, table cells — is data
 * from the log store, which is to say it was written by whoever generated the log.
 * React escapes it, and nothing here goes near dangerouslySetInnerHTML. (The local
 * instance has dashboards literally named `<img src=x onerror=…>` from an XSS
 * probe; they render as text, which is the point.)
 */

export type PanelState =
  | { status: 'idle' }
  | { status: 'running' }
  | { status: 'done'; data: PanelQueryResponse }
  | { status: 'error'; message: string; unscopedPrevalence?: boolean };

interface Props {
  panel: PanelConfig;
  state: PanelState;
  /** Drill into the panel's query as a real search tab. */
  onDrill?: (query: string) => void;
  /** Pin this panel to the desktop as an always-on-top widget. */
  onPin?: () => void;
  /** Compact chrome — used inside a pinned widget, where there's no room for it. */
  bare?: boolean;
}

export function Panel({ panel, state, onDrill, onPin, bare }: Props) {
  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden rounded-[10px] border border-line bg-inset">
      {!bare && (
        <div className="group flex shrink-0 items-center gap-2 border-b border-line px-3 py-2">
          <span className="min-w-0 flex-1 truncate text-[12px] font-semibold text-t1">
            {panel.title}
          </span>
          {state.status === 'done' && state.data.truncated && (
            <span
              className="shrink-0 font-mono text-[10px] text-warn"
              title="The query hit the 10,000-row panel cap — this is not the whole result set"
            >
              capped
            </span>
          )}
          {state.status === 'done' && state.data.cached && (
            <span
              className="shrink-0 font-mono text-[10px] text-t4"
              title="Served from the panel cache"
            >
              cached
            </span>
          )}
          {onPin && (
            <button
              onClick={onPin}
              title="Pin this panel to the desktop"
              className="shrink-0 text-[11px] text-t4 opacity-0 group-hover:opacity-100 hover:text-t1"
            >
              📌
            </button>
          )}
          {onDrill && panel.query && (
            <button
              onClick={() => onDrill(panel.query)}
              title="Open this panel's query as a search"
              className="shrink-0 text-[11px] text-t4 opacity-0 group-hover:opacity-100 hover:text-t1"
            >
              ⌕
            </button>
          )}
        </div>
      )}

      <div className="min-h-0 flex-1 p-2.5">
        <PanelBody panel={panel} state={state} />
      </div>
    </div>
  );
}

function PanelBody({ panel, state }: { panel: PanelConfig; state: PanelState }) {
  if (state.status === 'idle') {
    return <Centered>Not run yet.</Centered>;
  }
  if (state.status === 'running') {
    return (
      <Centered>
        <Spinner className="text-accent" />
      </Centered>
    );
  }
  if (state.status === 'error') {
    // A prevalence panel with no filter fails CLOSED by design — the backend
    // refuses to scan every artifact. That's a state to explain, not an error to
    // shout about.
    if (state.unscopedPrevalence) {
      return (
        <Centered>
          <span className="text-t3">
            Apply a filter to load this panel — an unscoped prevalence query is refused.
          </span>
        </Centered>
      );
    }
    return (
      <div className="flex h-full items-center justify-center px-2 text-center text-[11.5px] break-words text-danger">
        {state.message}
      </div>
    );
  }

  return <Chart panel={panel} response={state.data} />;
}

function Chart({ panel, response }: { panel: PanelConfig; response: PanelQueryResponse }) {
  const data = useMemo(() => preparePanelData(response), [response]);
  const config = panel.visualizationConfig ?? {};

  if (data.rows.length === 0) {
    return <Centered>No results.</Centered>;
  }

  // These exist on real dashboards but are not renderable here: tree/flow need
  // commands the backend rejects, and obs_metric is fed by the metrics endpoint,
  // not this one. Say so rather than drawing an empty box.
  if (['tree', 'flow', 'obs_metric'].includes(panel.visualizationType)) {
    return <Centered>“{panel.visualizationType}” panels aren’t rendered in the desktop app yet.</Centered>;
  }

  if (panel.visualizationType === 'table' || panel.visualizationType === 'transaction') {
    return <Table panel={panel} response={response} />;
  }

  if (panel.visualizationType === 'single_value') {
    return <SingleValue data={data} config={config} />;
  }

  const rows = data.rows.map((row) => ({
    ...row,
    __label: formatLabel(row[data.labelKey], data.isTime),
  }));

  const axis = {
    dataKey: '__label',
    tick: { fill: 'rgba(235,240,246,0.5)', fontSize: 10 },
    stroke: 'rgba(255,255,255,0.12)',
  } as const;
  const yAxis = {
    tick: { fill: 'rgba(235,240,246,0.5)', fontSize: 10 },
    stroke: 'rgba(255,255,255,0.12)',
    width: 44,
  } as const;
  const tooltip = (
    <Tooltip
      contentStyle={{
        background: 'rgba(36,39,46,0.96)',
        border: '1px solid rgba(255,255,255,0.12)',
        borderRadius: 8,
        fontSize: 11,
      }}
      labelStyle={{ color: '#f2f4f7' }}
    />
  );
  const legend =
    data.valueKeys.length > 1 ? <Legend wrapperStyle={{ fontSize: 10 }} /> : null;

  // `timeline` IS an area chart — the web renderer literally delegates to one.
  const kind = panel.visualizationType === 'timeline' ? 'area' : panel.visualizationType;

  if (kind === 'pie') {
    const valueKey =
      data.valueKeys.find((key) => /^count/i.test(key)) ?? data.valueKeys[0];
    return (
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={rows}
            dataKey={valueKey}
            nameKey="__label"
            innerRadius="60%"
            outerRadius="85%"
            label={config.showLabels}
          >
            {rows.map((_, index) => (
              <Cell key={index} fill={SERIES_COLORS[index % SERIES_COLORS.length]} />
            ))}
          </Pie>
          {tooltip}
        </PieChart>
      </ResponsiveContainer>
    );
  }

  if (kind === 'line') {
    return (
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={rows}>
          <XAxis {...axis} />
          <YAxis {...yAxis} />
          {tooltip}
          {legend}
          {data.valueKeys.map((key, index) => (
            <Line
              key={key}
              dataKey={key}
              type={config.smooth ? 'monotone' : 'linear'}
              stroke={SERIES_COLORS[index % SERIES_COLORS.length]}
              strokeWidth={1.5}
              dot={config.showPoints !== false && rows.length <= 40}
              // A densified gap is null on purpose (the average of no events is
              // not zero). Don't bridge it — that would draw a value nobody measured.
              connectNulls={false}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    );
  }

  if (kind === 'area') {
    return (
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={rows}>
          <XAxis {...axis} />
          <YAxis {...yAxis} />
          {tooltip}
          {legend}
          {data.valueKeys.map((key, index) => (
            <Area
              key={key}
              dataKey={key}
              type={config.smooth === false ? 'linear' : 'monotone'}
              stroke={SERIES_COLORS[index % SERIES_COLORS.length]}
              fill={SERIES_COLORS[index % SERIES_COLORS.length]}
              fillOpacity={config.fillOpacity ?? 0.3}
              connectNulls={false}
              stackId={config.stacked ? '1' : undefined}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    );
  }

  // bar + ranked_bar
  const horizontal =
    config.orientation === 'horizontal' || panel.visualizationType === 'ranked_bar';
  // Too many bars is an unreadable smear. Keep the NEWEST for a time series, the
  // TOP for a ranking — the query already sorted it.
  const MAX_BARS = horizontal ? 15 : 20;
  const bars = data.isTime ? rows.slice(-MAX_BARS) : rows.slice(0, MAX_BARS);

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={bars} layout={horizontal ? 'vertical' : 'horizontal'}>
        {horizontal ? (
          <>
            <XAxis type="number" {...yAxis} />
            {/* `axis` already carries dataKey="__label" — the category axis is the
                label one when the bars run horizontally. */}
            <YAxis type="category" width={110} {...axis} />
          </>
        ) : (
          <>
            <XAxis {...axis} />
            <YAxis {...yAxis} />
          </>
        )}
        {tooltip}
        {legend}
        {data.valueKeys.map((key, index) => (
          <Bar
            key={key}
            dataKey={key}
            fill={SERIES_COLORS[index % SERIES_COLORS.length]}
            stackId={config.stacked ? '1' : undefined}
            radius={horizontal ? [0, 2, 2, 0] : [2, 2, 0, 0]}
          />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

function SingleValue({
  data,
  config,
}: {
  data: ReturnType<typeof preparePanelData>;
  config: PanelConfig['visualizationConfig'];
}) {
  const key = data.valueKeys[0];
  if (!key) return <Centered>No numeric value.</Centered>;

  // A time series' single value is its NEWEST point, not its first.
  const rows = data.rows;
  const current = Number(rows[rows.length - 1]?.[key] ?? 0);
  const previous = rows.length > 1 ? Number(rows[rows.length - 2]?.[key] ?? 0) : null;

  const threshold = [...(config.thresholds ?? [])]
    .sort((a, b) => b.value - a.value)
    .find((entry) => current >= entry.value);

  const trend =
    config.showTrend && previous !== null && previous !== 0
      ? ((current - previous) / previous) * 100
      : null;

  return (
    <div className="flex h-full flex-col items-center justify-center">
      <div
        className="font-mono text-[26px] leading-none font-bold"
        style={{ color: threshold?.color?.startsWith('#') ? threshold.color : undefined }}
      >
        {current.toLocaleString()}
      </div>
      {config.unit && <div className="mt-1 text-[10.5px] text-t4">{config.unit}</div>}
      {trend !== null && (
        <div className={`mt-1 font-mono text-[11px] ${trend >= 0 ? 'text-accent' : 'text-t3'}`}>
          {trend >= 0 ? '▲' : '▼'} {Math.abs(trend).toFixed(0)}%
        </div>
      )}
    </div>
  );
}

function Table({ panel, response }: { panel: PanelConfig; response: PanelQueryResponse }) {
  const [page, setPage] = useState(0);
  const size = panel.visualizationConfig?.pageSize ?? 10;

  // Paginate to page 3, then refresh into a 5-row result: the slice is empty, the
  // pager is hidden (one page), and the analyst is left staring at a blank table
  // for a panel that returned data. Reset when the rows change under us.
  useEffect(() => {
    setPage(0);
  }, [response]);

  const rows = response.results ?? [];
  // Honour the server's column order — group-bys first, aggregates last — rather
  // than serde's alphabetised key order.
  const columns =
    panel.visualizationConfig?.columns?.map((column) => column.field) ??
    response.column_order ??
    Object.keys(rows[0] ?? {});

  const pages = Math.max(1, Math.ceil(rows.length / size));
  const shown = rows.slice(page * size, page * size + size);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse text-left">
          <thead className="sticky top-0 bg-inset">
            <tr>
              {columns.map((column) => (
                <th
                  key={column}
                  className="border-b border-line px-2 py-1 text-[10px] font-bold tracking-[0.06em] whitespace-nowrap text-t4"
                >
                  {column}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((row, index) => (
              <tr key={index} className="border-b border-line/40">
                {columns.map((column) => (
                  <td
                    key={column}
                    className="max-w-[240px] truncate px-2 py-1 font-mono text-[11px] text-t2"
                    title={String(row[column] ?? '')}
                  >
                    {String(row[column] ?? '')}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {pages > 1 && (
        <div className="flex shrink-0 items-center justify-end gap-2 pt-1.5 font-mono text-[10.5px] text-t4">
          <button
            onClick={() => setPage((current) => Math.max(0, current - 1))}
            disabled={page === 0}
            className="disabled:opacity-30"
          >
            ‹
          </button>
          <span>
            {page + 1}/{pages}
          </span>
          <button
            onClick={() => setPage((current) => Math.min(pages - 1, current + 1))}
            disabled={page >= pages - 1}
            className="disabled:opacity-30"
          >
            ›
          </button>
        </div>
      )}
    </div>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-full items-center justify-center text-[11.5px] text-t4">{children}</div>
  );
}
