import { SEVERITIES, SEVERITY_STYLE, ago, compact, useDashboard } from '../lib/dashboard';
import { api } from '../lib/ipc';
import type { Bucket } from '../lib/types';
import { Spinner } from './ui';

/**
 * SOC Overview.
 *
 * Every number here is real and every panel can fail on its own — a missing
 * `alerts:view` costs the analyst the alert cards, not the page. What failed is
 * named. A dashboard that renders a confident 0 because the request was refused
 * is telling you the SOC is quiet when you simply aren't allowed to look.
 */
interface Props {
  /** Open the search behind a number, so a KPI is a lead rather than a fact. */
  onDrill: (query: string) => void;
}

export function DashboardPane({ onDrill }: Props) {
  const { data, error, locked } = useDashboard();

  if (locked) {
    return (
      <div className="flex flex-1 items-center justify-center text-[12.5px] text-t4">
        Locked. Unlock to see the overview.
      </div>
    );
  }

  return (
    <div className="min-h-0 flex-1 overflow-auto p-5">
      <div className="flex items-center gap-3">
        <div className="text-[15px] font-semibold text-t1">SOC Overview</div>
        <div className="font-mono text-[11px] text-t4">
          {data ? `updated ${ago(data.generated_at)} · auto-refresh 30s` : 'loading…'}
        </div>
        <span className="flex-1" />
        <PinButton kind="detections" label="Pin detections" />
        <PinButton kind="ingest" label="Pin ingest" />
      </div>

      {error && (
        <div className="mt-3 rounded-[9px] border border-danger/40 bg-danger-soft px-3.5 py-2.5 text-[12px] break-words text-danger">
          {error}
        </div>
      )}

      {data && data.degraded.length > 0 && (
        <div className="mt-3 rounded-[9px] border border-warn/40 bg-warn-soft px-3.5 py-2.5 text-[11.5px] text-warn">
          Some panels couldn't load: {data.degraded.join('; ')}
        </div>
      )}

      {!data && !error && (
        <div className="mt-6 flex items-center gap-2 text-[12px] text-t3">
          <Spinner className="text-accent" /> Loading…
        </div>
      )}

      {data && (
        <>
          <div className="mt-4 grid grid-cols-4 gap-3">
            <Kpi
              label="EVENTS 24H"
              value={compact(data.events_24h)}
              onClick={() => onDrill('*')}
            />
            {/* Explicitly an average. Calling a 24h mean "EPS" next to a live
                chart invites it to be read as the current rate. */}
            <Kpi label="AVG EPS (24H)" value={data.eps.toFixed(1)} />
            <Kpi label="OPEN ALERTS" value={data.alerts_new.toLocaleString()} />
            <Kpi label="SOURCES" value={data.sources.toLocaleString()} />
          </div>

          <div className="mt-4 grid grid-cols-3 gap-3">
            <Panel title="INGEST · EVENTS PER HOUR" className="col-span-2">
              <IngestChart buckets={data.ingest} />
            </Panel>

            <Panel title="BY SEVERITY">
              <div className="space-y-1.5">
                {SEVERITIES.filter((severity) => (data.by_severity[severity] ?? 0) > 0).map(
                  (severity) => (
                    <div key={severity} className="flex items-center gap-2">
                      <span
                        className={`w-[86px] shrink-0 rounded-[20px] border px-2 py-0.5 text-center font-mono text-[10.5px] ${SEVERITY_STYLE[severity]}`}
                      >
                        {severity}
                      </span>
                      <span className="font-mono text-[12px] text-t1">
                        {data.by_severity[severity]}
                      </span>
                    </div>
                  )
                )}
                {Object.values(data.by_severity).every((count) => count === 0) && (
                  <div className="text-[12px] text-t4">No open alerts.</div>
                )}
              </div>
            </Panel>
          </div>

          <div className="mt-3 grid grid-cols-2 gap-3">
            <Panel title="LATEST DETECTIONS">
              {data.latest.length === 0 && <div className="text-[12px] text-t4">Nothing yet.</div>}
              <div className="space-y-1.5">
                {data.latest.map((alert, index) => (
                  <div key={index} className="flex items-center gap-2">
                    <span
                      className={`shrink-0 rounded-[20px] border px-1.5 py-0.5 font-mono text-[10px] ${
                        SEVERITY_STYLE[String(alert.severity ?? '').toLowerCase()] ??
                        SEVERITY_STYLE.informational
                      }`}
                    >
                      {String(alert.severity ?? '—')}
                    </span>
                    <span className="min-w-0 flex-1 truncate text-[12px] text-t2">
                      {String(alert.rule_name ?? alert.title ?? 'Alert')}
                    </span>
                    {typeof alert.created_at === 'string' && (
                      <span className="shrink-0 font-mono text-[10.5px] text-t4">
                        {ago(alert.created_at)}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </Panel>

            <Panel title="TOP TALKERS · 24H">
              {data.top_talkers.length === 0 && (
                <div className="text-[12px] text-t4">No source IPs in the window.</div>
              )}
              <div className="space-y-1">
                {data.top_talkers.map((talker) => {
                  const most = data.top_talkers[0]?.hits || 1;
                  return (
                    <div
                      key={talker.asset}
                      onClick={() => onDrill(`src_ip="${talker.asset}"`)}
                      className="flex cursor-default items-center gap-2 rounded-[5px] px-1 py-0.5 hover:bg-hover"
                    >
                      <span className="w-[120px] shrink-0 truncate font-mono text-[11.5px] text-t2">
                        {talker.asset}
                      </span>
                      <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-inset">
                        <span
                          className="block h-full bg-accent"
                          style={{ width: `${Math.max(4, (talker.hits / most) * 100)}%` }}
                        />
                      </span>
                      <span className="w-[52px] shrink-0 text-right font-mono text-[11px] text-t3">
                        {compact(talker.hits)}
                      </span>
                    </div>
                  );
                })}
              </div>
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}

/** The thing only a native app can do. */
function PinButton({ kind, label }: { kind: 'detections' | 'ingest'; label: string }) {
  return (
    <button
      onClick={() => void api.pinWidget(kind)}
      title="Keeps showing on top of other apps"
      className="shrink-0 rounded-[7px] border border-line-strong px-2 py-1 text-[11px] text-t3 hover:text-t1"
    >
      📌 {label}
    </button>
  );
}

function Kpi({ label, value, onClick }: { label: string; value: string; onClick?: () => void }) {
  return (
    <div
      onClick={onClick}
      className={`rounded-[10px] border border-line bg-inset px-3.5 py-3 ${
        onClick ? 'cursor-default hover:bg-hover' : ''
      }`}
    >
      <div className="text-[10.5px] font-bold tracking-[0.06em] text-t4">{label}</div>
      <div className="mt-1 font-mono text-[26px] leading-none font-bold text-t1">{value}</div>
    </div>
  );
}

function Panel({
  title,
  children,
  className = '',
}: {
  title: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`rounded-[10px] border border-line bg-inset p-3.5 ${className}`}>
      <div className="text-[10.5px] font-bold tracking-[0.06em] text-t4">{title}</div>
      <div className="mt-2.5">{children}</div>
    </div>
  );
}

/**
 * Hand-drawn bars rather than a charting library: Recharts lives in the web app's
 * node_modules, and pulling it in through the `@` alias is exactly the
 * second-copy trap that already cost us a blank Search screen in the bundle. A bar
 * chart is twenty lines.
 */
export function IngestChart({ buckets, height = 92 }: { buckets: Bucket[]; height?: number }) {
  if (buckets.length === 0) {
    return <div className="text-[12px] text-t4">No events in the last 24 hours.</div>;
  }
  const most = Math.max(...buckets.map((bucket) => bucket.count), 1);

  return (
    <div className="flex items-end gap-[2px]" style={{ height }}>
      {buckets.map((bucket) => (
        <div
          key={bucket.at}
          title={`${new Date(bucket.at).toLocaleString()} · ${bucket.count.toLocaleString()} events`}
          className="min-w-[3px] flex-1 rounded-t-[2px] bg-accent"
          style={{
            // A bucket with events must never render as nothing — a 1-event hour
            // and a 0-event hour have to be distinguishable.
            height: `${bucket.count === 0 ? 0 : Math.max(3, (bucket.count / most) * height)}px`,
          }}
        />
      ))}
    </div>
  );
}
