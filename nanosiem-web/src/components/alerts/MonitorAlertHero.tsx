// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-1547 — alert detail hero for OBSERVABILITY monitor alerts
// (metric_monitor / slo / synthetic). The detection AlertHero is rule-centric
// (latency, entities, MITRE, detection context) and rendered monitor alerts as
// "Unknown Rule" / no value. This hero renders the breach instead, from the
// normalized monitor payload (see monitorAlert.ts). The detection path is left
// untouched — AlertDetail branches on `kind` and picks the right hero.

import { useNavigate } from 'react-router-dom';
import {
  Activity,
  ArrowLeft,
  Clock,
  Gauge,
  Globe,
  TimerReset,
} from 'lucide-react';

import { cn } from '@/lib/utils';
import { SEV_META, normalizeSeverity } from '@/components/matches/helpers';
import {
  MONITOR_KIND_LABEL,
  comparatorSymbol,
  formatMetricValue,
  formatWindow,
  monitorScope,
  type MonitorAlertView,
} from '@/components/alerts/monitorAlert';

interface MonitorHeroAlert {
  id: string;
  severity: string;
  status: 'open' | 'acknowledged' | 'closed';
  disposition?: 'true_positive' | 'false_positive' | 'benign';
  timestamp: Date;
  acknowledgedAt?: Date;
  acknowledgedBy?: string;
  closedAt?: Date;
  closedBy?: string;
  triageVerdict?: string;
}

interface MonitorAlertHeroProps {
  alert: MonitorHeroAlert;
  monitor: MonitorAlertView;
}

const VERDICT_LABEL: Record<string, string> = {
  true_positive: 'True positive',
  likely_true_positive: 'Likely TP',
  false_positive: 'False positive',
  likely_false_positive: 'Likely FP',
  needs_investigation: 'Needs review',
  benign: 'Benign',
};

const VERDICT_TONE: Record<string, string> = {
  true_positive: 'var(--destructive)',
  likely_true_positive: 'var(--destructive)',
  false_positive: 'var(--success)',
  likely_false_positive: 'var(--success)',
  needs_investigation: 'var(--warning)',
  benign: 'var(--muted-foreground)',
};

const DISPOSITION_LABEL: Record<string, string> = {
  true_positive: 'True positive',
  false_positive: 'False positive',
  benign: 'Benign',
};

function fmtTimeShort(d: Date): string {
  return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

function fmtEvaluatedAt(iso?: string): string | null {
  if (!iso) return null;
  const t = new Date(iso);
  if (Number.isNaN(t.getTime())) return null;
  return fmtTimeShort(t);
}

export function MonitorAlertHero({ alert, monitor }: MonitorAlertHeroProps) {
  const navigate = useNavigate();
  const handleBack = () => {
    if (globalThis.window?.history?.length > 1) navigate(-1);
    else navigate('/observability/alerts');
  };

  const sev = SEV_META[normalizeSeverity(alert.severity)];
  const isOpen = alert.status === 'open';
  const isAcked = alert.status === 'acknowledged';
  const isClosed = alert.status === 'closed';
  const statusTone = isOpen
    ? 'var(--destructive)'
    : isAcked
      ? 'var(--warning)'
      : 'var(--success)';
  const statusLabel = isOpen ? 'Open' : isAcked ? 'Acknowledged' : 'Closed';

  const isSynthetic = monitor.kind === 'synthetic';
  const evaluatedAt = fmtEvaluatedAt(monitor.evaluatedAt);

  // The breach subtitle reads as a sentence, e.g.
  // "avg(http.server.active_requests) = 32.24, breached > 20 over 15m".
  const breachSummary = isSynthetic
    ? `Expected HTTP ${monitor.expectedStatus ?? '—'}, observed ${
        monitor.observedStatus && monitor.observedStatus > 0
          ? monitor.observedStatus
          : 'no response'
      }`
    : `${monitorScope(monitor)} = ${formatMetricValue(monitor.value)}, breached ${comparatorSymbol(
        monitor.comparator,
      )} ${formatMetricValue(monitor.threshold)} over ${formatWindow(monitor.windowSecs)}`;

  return (
    <div className="flex flex-col gap-2.5">
      {/* Title row */}
      <div className="flex items-start gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2.5 flex-wrap">
            <button
              type="button"
              onClick={handleBack}
              className="text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1 h-6 px-1.5 rounded hover:bg-foreground/5"
            >
              <ArrowLeft className="w-3 h-3" strokeWidth={2} />
              Back
            </button>
            <span className="text-muted-foreground/60">/</span>

            <div className="flex items-center gap-1.5">
              <span
                className={cn('w-[6px] h-[6px] rounded-full', isOpen && 'animate-pulse')}
                style={{ background: statusTone }}
              />
              <span className="text-[11px] text-foreground">{statusLabel}</span>
            </div>

            <div className="flex items-center gap-1.5">
              <span className="w-[6px] h-[6px] rounded-full" style={{ background: sev.color }} />
              <span className="text-[11px] text-foreground">{sev.label} severity</span>
            </div>

            <span
              className="font-mono text-[9.5px] uppercase tracking-[0.08em] h-[18px] inline-flex items-center px-1.5 rounded-sm"
              style={{
                background: 'color-mix(in srgb, var(--primary) 12%, transparent)',
                color: 'var(--primary)',
              }}
            >
              {MONITOR_KIND_LABEL[monitor.kind]}
            </span>
          </div>

          <h1 className="text-[22px] font-semibold tracking-[-0.01em] text-foreground mt-1.5 font-mono leading-none truncate">
            {monitor.title}
          </h1>
          <p className="text-[12px] text-muted-foreground mt-1.5 max-w-[760px] leading-[1.55]">
            {breachSummary}
          </p>

          <div className="mt-2 flex items-center gap-3 font-mono text-[10.5px] text-muted-foreground flex-wrap">
            <span>
              alert: <span className="text-foreground">{alert.id}</span>
            </span>
            {monitor.sourceId && (
              <>
                <span className="text-muted-foreground/60">·</span>
                <span>
                  source: <span className="text-foreground">{monitor.sourceId}</span>
                </span>
              </>
            )}
            <span className="text-muted-foreground/60">·</span>
            <span>
              triggered: <span className="text-foreground">{fmtTimeShort(alert.timestamp)}</span>
            </span>
          </div>
        </div>
      </div>

      {/* Analytics strip — 4 tiles */}
      <div className="rounded-lg border border-border overflow-hidden bg-card">
        <div className="grid grid-cols-[1.2fr_1.4fr_1.4fr_1fr] @max-[1100px]:grid-cols-2 @max-[640px]:grid-cols-1 divide-x divide-border @max-[1100px]:divide-x-0 @max-[1100px]:divide-y">
          {/* Tile 1 — Breach */}
          <div className="p-3.5 flex flex-col">
            <div className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              <Gauge className="w-3 h-3" strokeWidth={2} />
              Breach
            </div>
            {isSynthetic ? (
              <>
                <div className="mt-1.5 flex items-baseline gap-1.5">
                  <span className="text-[26px] font-semibold text-destructive tabular-nums leading-none">
                    {monitor.observedStatus && monitor.observedStatus > 0
                      ? monitor.observedStatus
                      : 'down'}
                  </span>
                  <span className="text-[11px] text-muted-foreground">observed</span>
                </div>
                <div className="mt-2 font-mono text-[10.5px] flex items-center justify-between">
                  <span className="text-muted-foreground">expected</span>
                  <span className="text-foreground tabular-nums">
                    {monitor.expectedStatus ?? '—'}
                  </span>
                </div>
                {monitor.error && (
                  <div className="mt-1.5 font-mono text-[10px] text-destructive/90 break-words leading-snug">
                    {monitor.error}
                  </div>
                )}
              </>
            ) : (
              <>
                <div className="mt-1.5 flex items-baseline gap-1.5">
                  <span className="text-[26px] font-semibold text-destructive tabular-nums leading-none">
                    {formatMetricValue(monitor.value)}
                  </span>
                  <span className="text-[11px] text-muted-foreground">{monitor.agg ?? 'value'}</span>
                </div>
                <div className="mt-2 font-mono text-[10.5px] flex items-center justify-between">
                  <span className="text-muted-foreground">threshold</span>
                  <span className="text-foreground tabular-nums">
                    {comparatorSymbol(monitor.comparator)} {formatMetricValue(monitor.threshold)}
                  </span>
                </div>
                <div className="mt-1 font-mono text-[10.5px] flex items-center justify-between">
                  <span className="text-muted-foreground">window</span>
                  <span className="text-foreground tabular-nums">
                    {formatWindow(monitor.windowSecs)}
                  </span>
                </div>
              </>
            )}
          </div>

          {/* Tile 2 — Triage */}
          <div className="p-3.5 flex flex-col">
            <div className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              <Clock className="w-3 h-3" strokeWidth={2} />
              Triage
            </div>
            <div className="mt-1.5 flex items-center gap-1.5">
              <span className="w-[6px] h-[6px] rounded-full" style={{ background: statusTone }} />
              <span className="text-[14px] text-foreground capitalize">{statusLabel}</span>
            </div>

            {alert.triageVerdict && (
              <div className="mt-2 flex items-center gap-2 text-[10.5px]">
                <span className="text-muted-foreground">AI verdict</span>
                <span
                  className="font-mono uppercase tracking-[0.08em] text-[9.5px] font-semibold px-1.5 py-[1px] rounded-sm"
                  style={{
                    background: `color-mix(in srgb, ${VERDICT_TONE[alert.triageVerdict] ?? 'var(--muted-foreground)'} 14%, transparent)`,
                    color: VERDICT_TONE[alert.triageVerdict] ?? 'var(--muted-foreground)',
                  }}
                >
                  {VERDICT_LABEL[alert.triageVerdict] ?? alert.triageVerdict}
                </span>
              </div>
            )}

            <div className="mt-2 flex flex-col gap-1 font-mono text-[10.5px]">
              {alert.acknowledgedAt && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">acked</span>
                  <span className="text-foreground tabular-nums truncate">
                    {alert.acknowledgedAt.toISOString().slice(0, 19).replace('T', ' ')}
                  </span>
                </div>
              )}
              {alert.acknowledgedBy && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">by</span>
                  <span className="text-foreground truncate">{alert.acknowledgedBy}</span>
                </div>
              )}
              {alert.closedAt && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">closed</span>
                  <span className="text-foreground tabular-nums truncate">
                    {alert.closedAt.toISOString().slice(0, 19).replace('T', ' ')}
                  </span>
                </div>
              )}
              {alert.closedBy && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">by</span>
                  <span className="text-foreground truncate">{alert.closedBy}</span>
                </div>
              )}
              {isClosed && alert.disposition && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">disposition</span>
                  <span className="text-foreground">
                    {DISPOSITION_LABEL[alert.disposition] ?? alert.disposition}
                  </span>
                </div>
              )}
              {!alert.acknowledgedAt && !alert.closedAt && (
                <div className="text-muted-foreground/60">No triage actions yet.</div>
              )}
            </div>
          </div>

          {/* Tile 3 — Scope */}
          <div className="p-3.5 flex flex-col">
            <div className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              {isSynthetic ? (
                <Globe className="w-3 h-3" strokeWidth={2} />
              ) : (
                <Activity className="w-3 h-3" strokeWidth={2} />
              )}
              {isSynthetic ? 'Target' : 'Metric'}
            </div>
            <div className="mt-2 flex flex-col gap-1.5 font-mono text-[10.5px]">
              {isSynthetic ? (
                <div className="text-foreground break-words leading-snug">
                  {monitor.targetUrl ?? '—'}
                </div>
              ) : (
                <>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted-foreground">metric</span>
                    <span className="text-foreground truncate max-w-[180px]">
                      {monitor.metricName ?? '—'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted-foreground">aggregation</span>
                    <span className="text-foreground">{monitor.agg ?? '—'}</span>
                  </div>
                  {monitor.groupBy && (
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-muted-foreground">group by</span>
                      <span className="text-foreground truncate max-w-[160px]">
                        {monitor.groupBy}
                      </span>
                    </div>
                  )}
                  {monitor.seriesKey && (
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-muted-foreground">series</span>
                      <span className="text-foreground truncate max-w-[160px]">
                        {monitor.seriesKey}
                      </span>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>

          {/* Tile 4 — Evaluation */}
          <div className="p-3.5 flex flex-col">
            <div className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              <TimerReset className="w-3 h-3" strokeWidth={2} />
              Evaluation
            </div>
            <div className="mt-2 flex flex-col gap-1.5 font-mono text-[10.5px]">
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">kind</span>
                <span className="text-foreground">{MONITOR_KIND_LABEL[monitor.kind]}</span>
              </div>
              {!isSynthetic && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">window</span>
                  <span className="text-foreground tabular-nums">
                    {formatWindow(monitor.windowSecs)}
                  </span>
                </div>
              )}
              {evaluatedAt && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">evaluated</span>
                  <span className="text-foreground tabular-nums truncate max-w-[160px]">
                    {evaluatedAt}
                  </span>
                </div>
              )}
              {monitor.sourceId && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">source id</span>
                  <span className="text-foreground truncate max-w-[160px]">{monitor.sourceId}</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default MonitorAlertHero;
