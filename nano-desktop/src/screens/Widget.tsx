import { useEffect, useState } from 'react';

import { IngestChart } from '../components/DashboardPane';
import { Panel, type PanelState } from '../components/Panel';
import { SEVERITY_STYLE, ago, compact, useDashboard } from '../lib/dashboard';
import { api, errorMessage } from '../lib/ipc';
import type { PanelConfig } from '../lib/types';
import { Spinner } from './../components/ui';

/**
 * A pinned dashboard panel: the same panel, from the same definition, run through
 * the same endpoint as the dashboard it was pinned from — floating above every
 * other app.
 *
 * It re-reads the dashboard on each refresh rather than caching the panel, so an
 * edit (by a human, or by pivt) shows up on the desktop without re-pinning.
 */
function PinnedPanel({ dashboardId, panelId }: { dashboardId: string; panelId: string }) {
  const [panel, setPanel] = useState<PanelConfig | null>(null);
  const [state, setState] = useState<PanelState>({ status: 'running' });
  const [locked, setLocked] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function refresh() {
      try {
        // Same rule as every widget: a locked machine shows nothing.
        if (!(await api.isAuthenticated())) {
          if (!cancelled) {
            setLocked(true);
            setPanel(null);
            setState({ status: 'idle' });
          }
          return;
        }
        if (cancelled) return;
        setLocked(false);

        const dashboard = await api.getDashboard(dashboardId);
        const found = dashboard.panels?.find((candidate) => candidate.id === panelId);
        if (cancelled) return;

        if (!found) {
          setState({ status: 'error', message: 'That panel is no longer on the dashboard.' });
          return;
        }
        setPanel(found);

        const data = await api.panelQuery(
          found.query,
          found.queryMode ?? 'piped',
          found.timeRangeMode === 'custom' && found.customTimeRange
            ? found.customTimeRange
            : toRange(dashboard.layout?.defaultTimeRange)
        );
        if (!cancelled) setState({ status: 'done', data });
      } catch (caught) {
        if (!cancelled) setState({ status: 'error', message: errorMessage(caught) });
      }
    }

    void refresh();
    const handle = window.setInterval(refresh, 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(handle);
    };
  }, [dashboardId, panelId]);

  return (
    <div className="flex h-full flex-col overflow-hidden rounded-[13px] border border-line-strong bg-window">
      <div
        data-tauri-drag-region
        className="flex shrink-0 items-center gap-2 border-b border-line px-3 py-2"
      >
        <span className="size-1.5 shrink-0 rounded-full bg-accent pulse" />
        <span className="min-w-0 flex-1 truncate text-[11.5px] font-semibold text-t1">
          {panel?.title ?? 'Panel'}
        </span>
        <button onClick={() => void api.closeWidget()} title="Unpin" className="text-t4 hover:text-t1">
          ✕
        </button>
      </div>

      <div className="min-h-0 flex-1 p-2">
        {locked ? (
          <div className="flex h-full items-center justify-center text-[11.5px] text-t4">Locked</div>
        ) : panel ? (
          <Panel panel={panel} state={state} bare />
        ) : (
          <div className="flex h-full items-center justify-center gap-2 text-[11.5px] text-t3">
            <Spinner className="text-accent" /> loading…
          </div>
        )}
      </div>
    </div>
  );
}

function toRange(
  preset?: { type: 'preset'; preset: string } | { type: 'custom'; start: string; end: string }
): { start: string; end: string } {
  if (preset?.type === 'custom') return { start: preset.start, end: preset.end };
  const end = new Date();
  const start = new Date(end.getTime() - 24 * 60 * 60 * 1000);
  return { start: start.toISOString(), end: end.toISOString() };
}

/**
 * A panel pinned to the desktop: frameless, always on top, still updating while
 * the analyst works in another app. The one thing a web SIEM cannot do.
 *
 * It reads the same `dashboard()` the SOC Overview does, so a pinned widget can
 * never disagree with the page it was pinned from — and, critically, it inherits
 * the same behaviour on Lock: when the session is locked the widget goes blank.
 * An always-on-top window still showing live detections on a locked machine would
 * be the most visible leak in the product.
 */
export function Widget() {
  // The window label is a value we chose; what it SHOWS lives in Rust. Ask.
  const [spec, setSpec] = useState<Awaited<ReturnType<typeof api.widgetSpec>> | null>(null);
  useEffect(() => {
    api.widgetSpec().then(setSpec).catch(() => undefined);
  }, []);

  // Until we know WHAT this window is, show nothing. Defaulting to the detections
  // widget meant a pinned panel flashed live alert titles on open — and showed them
  // permanently if the IPC failed.
  if (!spec) {
    return (
      <div className="flex h-full items-center justify-center rounded-[13px] border border-line-strong bg-window">
        <Spinner className="text-accent" />
      </div>
    );
  }
  if (spec.kind === 'panel' && spec.dashboard_id && spec.panel_id) {
    return <PinnedPanel dashboardId={spec.dashboard_id} panelId={spec.panel_id} />;
  }
  return <OverviewWidget kind={spec.kind} />;
}

/** The built-in overview widgets (detections / ingest), from `dashboard()`. */
function OverviewWidget({ kind }: { kind: string }) {
  const { data, error, locked } = useDashboard(20_000);

  return (
    <div className="flex h-full flex-col overflow-hidden rounded-[13px] border border-line-strong bg-window">
      {/* The whole header is the drag handle — there is no titlebar to grab. */}
      <div
        data-tauri-drag-region
        className="flex shrink-0 items-center gap-2 border-b border-line px-3 py-2"
      >
        <span className="size-1.5 rounded-full bg-accent pulse" />
        <span className="text-[11.5px] font-semibold text-t1">{TITLES[kind] ?? 'nano'}</span>
        <span className="flex-1" />
        {data && <span className="font-mono text-[10px] text-t4">{ago(data.generated_at)}</span>}
        <button
          onClick={() => void api.closeWidget()}
          title="Unpin"
          className="text-t4 hover:text-t1"
        >
          ✕
        </button>
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-3">
        {locked ? (
          <div className="flex h-full items-center justify-center text-[11.5px] text-t4">
            Locked
          </div>
        ) : error ? (
          <div className="text-[11.5px] break-words text-danger">{error}</div>
        ) : !data ? (
          <div className="flex items-center gap-2 text-[11.5px] text-t3">
            <Spinner className="text-accent" /> loading…
          </div>
        ) : kind === 'ingest' ? (
          <>
            <div className="font-mono text-[22px] leading-none font-bold text-t1">
              {compact(data.events_24h)}
            </div>
            <div className="mt-1 font-mono text-[10.5px] text-t4">
              events · 24h · {data.eps.toFixed(1)} eps avg
            </div>
            <div className="mt-3">
              <IngestChart buckets={data.ingest} height={70} />
            </div>
          </>
        ) : (
          <>
            <div className="font-mono text-[10.5px] text-t4">
              {data.alerts_new} open · {data.alerts_total} total
            </div>
            <div className="mt-2 space-y-1.5">
              {data.latest.length === 0 && (
                <div className="text-[11.5px] text-t4">Nothing yet.</div>
              )}
              {data.latest.slice(0, 5).map((alert, index) => (
                <div key={index} className="flex items-center gap-1.5">
                  <span
                    className={`shrink-0 rounded-[20px] border px-1.5 py-px font-mono text-[9.5px] ${
                      SEVERITY_STYLE[String(alert.severity ?? '').toLowerCase()] ??
                      SEVERITY_STYLE.informational
                    }`}
                  >
                    {String(alert.severity ?? '—')}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-[11.5px] text-t2">
                    {String(alert.rule_name ?? alert.title ?? 'Alert')}
                  </span>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

const TITLES: Record<string, string> = {
  detections: 'Detections',
  ingest: 'Ingest',
  agent: 'pivt',
};
