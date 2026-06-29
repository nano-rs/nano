// SPDX-License-Identifier: AGPL-3.0-or-later

// ServiceDetail (NAN-1536) — single-service RED drill-in inside the console.
//
// Ported from the design handoff's obs-services.jsx (ServiceDetail + RedPanel +
// EndpointsTable + ExemplarTraces). Data is REAL:
//   api.observability.getServiceDetail(service, apiTimeRange) → RED timeseries,
//   endpoints (by span_name), exemplar traces.
// The SLO strip is rendered only when api.observability.listSlos() returns an
// SLO bound to this service (no synthetic owner/runbook/deploy metadata — the
// mock's TagSpotlight / ServiceMetaStrip rely on data the wire contract does not
// carry, so they're omitted rather than faked).

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowLeft,
  Box,
  AreaChart,
  AlertTriangle,
  LineChart,
  List as ListIcon,
  GitBranch,
  ChevronRight,
  Target,
  RefreshCw,
} from 'lucide-react';
import { api } from '@/lib/api';
import type { CacheMeta } from '@/lib/api';
import { cn } from '@/lib/utils';
import { CachedNotice } from '@/components/search/CachedNotice';
import { useReportPhase2Status } from '@/components/search/footer-reporter';
import { useIsLiveRun } from '@/components/search/live-run-context';
import { useCapabilities } from '@/hooks/use-capabilities';
import { REDChart, LatencyScatter, BudgetBar, type RedSeries, type ScatterTrace } from '@/components/observability/charts';
import { ServiceSecuritySignals } from '@/components/observability/ServiceSecuritySignals';
import { HEALTH, fmtNum, fmtMs, fmtPct, type DesignHealth } from '@/components/observability/format';
import type { ServiceDetailResponse, Slo } from '@/lib/api/observability';
import type { TimeRange } from '@/lib/api/types';

export interface ServiceDetailProps {
  service: string;
  apiTimeRange: TimeRange;
  onBack: () => void;
  onOpenTrace: (traceId: string) => void;
}

const HealthDot = ({ h, pulse }: { h: DesignHealth; pulse?: boolean }) => (
  <span
    className={cn(
      'inline-block w-[7px] h-[7px] rounded-full shrink-0',
      HEALTH[h].dot,
      pulse && h !== 'good' && 'animate-pulse'
    )}
  />
);

// ---------------------------------------------------------------------------
// RED panel — header metric + chart
// ---------------------------------------------------------------------------

interface RedPanelProps {
  title: string;
  icon: React.ReactNode;
  value: string;
  unit?: string;
  sub?: string;
  subTone?: string;
  children: React.ReactNode;
}

function RedPanel({ title, icon, value, unit, sub, subTone, children }: RedPanelProps) {
  return (
    <div className="rounded-lg border border-border bg-card flex flex-col overflow-hidden">
      <div className="px-3.5 pt-3 pb-1.5">
        <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.12em] text-fg-3">
          {icon}
          {title}
        </div>
        <div className="flex items-baseline gap-1.5 mt-2">
          <span className="text-[26px] font-semibold font-mono tabular-nums text-fg leading-none">{value}</span>
          {unit && <span className="text-[11px] text-fg-3">{unit}</span>}
        </div>
        {sub && <div className={cn('text-[11px] mt-1', subTone || 'text-fg-3')}>{sub}</div>}
      </div>
      <div className="px-2 pb-2 mt-1">{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Endpoints — per span_name breakdown
// ---------------------------------------------------------------------------

function EndpointsTable({ endpoints }: { endpoints: ServiceDetailResponse['endpoints'] }) {
  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="px-3.5 py-2.5 border-b border-border font-mono text-[10.5px] uppercase tracking-[0.12em] text-fg-2 font-semibold flex items-center gap-2">
        <ListIcon className="w-[13px] h-[13px] text-brand" /> Endpoints
      </div>
      <div className="grid grid-cols-[1fr_80px_80px_90px] gap-2 px-3.5 py-1.5 border-b border-border font-mono text-[9px] uppercase tracking-[0.1em] text-fg-4">
        <span>Operation</span>
        <span className="text-right">Rate</span>
        <span className="text-right">Errors</span>
        <span className="text-right">p95</span>
      </div>
      {endpoints.length === 0 ? (
        <div className="px-3.5 py-6 text-center text-[11.5px] text-fg-3">No endpoints in range.</div>
      ) : (
        endpoints.map((e) => {
          const errPct = e.error_rate * 100;
          return (
            <div
              key={e.span_name}
              className="grid grid-cols-[1fr_80px_80px_90px] gap-2 px-3.5 py-2 border-b border-border/50 hover:bg-foreground/5 items-center"
            >
              <span className="font-mono text-[11.5px] text-fg truncate" title={e.span_name}>
                {e.span_name}
              </span>
              <span className="font-mono text-[11.5px] text-fg-2 tabular-nums text-right">
                {fmtNum(e.request_count)}
              </span>
              <span
                className={cn(
                  'font-mono text-[11.5px] tabular-nums text-right',
                  errPct >= 5 ? 'text-danger' : errPct >= 1 ? 'text-warn' : 'text-fg-3'
                )}
              >
                {fmtPct(errPct)}
              </span>
              <span
                className={cn(
                  'font-mono text-[11.5px] tabular-nums text-right',
                  e.p95_ms >= 600 ? 'text-warn' : 'text-fg-2'
                )}
              >
                {fmtMs(e.p95_ms)}
              </span>
            </div>
          );
        })
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Exemplar traces — latency scatter + slowest/errored list
// ---------------------------------------------------------------------------

function ExemplarTraces({
  exemplars,
  onOpenTrace,
}: {
  exemplars: ServiceDetailResponse['exemplars'];
  onOpenTrace: (traceId: string) => void;
}) {
  const scatter: ScatterTrace[] = useMemo(
    () =>
      exemplars.map((e) => ({
        id: e.trace_id,
        startTs: Date.parse(e.start_time) || 0,
        durationMs: e.duration_ms,
        errors: e.error ? 1 : 0,
        root: e.span_name,
      })),
    [exemplars]
  );

  const ranked = useMemo(
    () =>
      exemplars
        .slice()
        .sort((a, b) => Number(b.error) - Number(a.error) || b.duration_ms - a.duration_ms)
        .slice(0, 8),
    [exemplars]
  );

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="px-3.5 py-2.5 border-b border-border flex items-center gap-2">
        <GitBranch className="w-[13px] h-[13px] text-brand" />
        <span className="font-mono text-[10.5px] uppercase tracking-[0.12em] text-fg-2 font-semibold">
          Exemplar traces
        </span>
        <span className="text-[10.5px] text-fg-4">slowest · errored</span>
      </div>
      {exemplars.length === 0 ? (
        <div className="px-3.5 py-10 text-center text-[11.5px] text-fg-3">No exemplar traces in range.</div>
      ) : (
        <>
          <div className="px-2 pt-2">
            <LatencyScatter traces={scatter} height={180} onPick={(t) => onOpenTrace(t.id)} />
          </div>
          {ranked.map((t) => (
            <button
              key={t.trace_id}
              onClick={() => onOpenTrace(t.trace_id)}
              className="group w-full text-left px-3.5 py-2 border-b border-border/50 hover:bg-foreground/5 flex items-center gap-2.5"
            >
              <span
                className={cn(
                  'w-1.5 h-1.5 rounded-full shrink-0',
                  t.error ? 'bg-danger' : t.duration_ms >= 600 ? 'bg-warn' : 'bg-good'
                )}
              />
              <span className="font-mono text-[11px] text-fg-3 truncate w-[88px] shrink-0">
                {t.trace_id.slice(0, 10)}…
              </span>
              <span className="font-mono text-[11px] text-fg truncate flex-1">{t.span_name}</span>
              {t.error && <span className="font-mono text-[10px] text-danger shrink-0">err</span>}
              <span
                className={cn(
                  'font-mono text-[11px] tabular-nums shrink-0',
                  t.duration_ms >= 600 ? 'text-warn' : 'text-fg-2'
                )}
              >
                {fmtMs(t.duration_ms)}
              </span>
              <ChevronRight className="w-3 h-3 text-fg-4 group-hover:text-fg-2 shrink-0" />
            </button>
          ))}
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// SLO strip — real SLOs bound to this service (rendered only if present)
// ---------------------------------------------------------------------------

function SloStrip({ slos }: { slos: Slo[] }) {
  // Surface the SLO under most budget pressure.
  const worst = slos.slice().sort((a, b) => a.budget_remaining_pct - b.budget_remaining_pct)[0];
  if (!worst) return null;
  const consumed = 100 - worst.budget_remaining_pct;
  const statusTone: Record<Slo['status'], string> =
    {
      ok: 'text-good',
      at_risk: 'text-warn',
      breaching: 'text-danger',
    };
  return (
    <div className="rounded-lg border border-border bg-card px-3.5 py-2.5 flex items-center gap-x-4 gap-y-2 flex-wrap text-[11.5px]">
      <div className="flex items-center gap-1.5">
        <Target className="w-[13px] h-[13px] text-brand" />
        <span className="font-mono text-[10.5px] uppercase tracking-[0.12em] text-fg-2 font-semibold">SLO</span>
      </div>
      <span className="font-mono text-fg truncate max-w-[220px]">{worst.name}</span>
      <span className="px-1.5 py-0.5 rounded border border-border font-mono text-[10px] text-fg-3">
        {worst.sli_kind === 'latency' ? `latency < ${fmtMs(worst.latency_threshold_ms ?? 0)}` : 'availability'}
      </span>
      <div className="flex items-center gap-2">
        <span className="text-fg-4">current</span>
        <span className="font-mono text-fg-2 tabular-nums">{(worst.current * 100).toFixed(2)}%</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-fg-4">target</span>
        <span className="font-mono text-fg-2 tabular-nums">{(worst.target * 100).toFixed(2)}%</span>
      </div>
      <div className="flex-1 min-w-[120px]" />
      <div className="flex items-center gap-2.5">
        <div className="w-28">
          <BudgetBar consumedPct={consumed} />
        </div>
        <span
          className={cn(
            'font-mono text-[10.5px] tabular-nums',
            consumed >= 100 ? 'text-danger' : consumed >= 75 ? 'text-warn' : 'text-fg-3'
          )}
        >
          {Math.max(0, worst.budget_remaining_pct).toFixed(0)}% budget
        </span>
        <span className={cn('font-mono text-[10.5px] uppercase tracking-wider', statusTone[worst.status])}>
          {worst.status.replace('_', ' ')}
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Aggregate helpers — collapse RED timeseries into header summary figures
// ---------------------------------------------------------------------------

function summarize(detail: ServiceDetailResponse) {
  const { rate, errors, latency } = detail.red;
  const totalReq = rate.reduce((s, p) => s + p.v, 0);
  const totalErr = errors.reduce((s, p) => s + p.v, 0);
  const errPct = totalReq > 0 ? (totalErr / totalReq) * 100 : 0;
  const avgRate = rate.length ? rate.reduce((s, p) => s + p.v, 0) / rate.length : 0;
  const worstP95 = latency.length ? Math.max(...latency.map((p) => p.p95)) : 0;
  const worstP99 = latency.length ? Math.max(...latency.map((p) => p.p99)) : 0;
  const lastP50 = latency.length ? latency[latency.length - 1].p50 : 0;
  const health: DesignHealth = errPct >= 5 || worstP95 >= 1800 ? 'danger' : errPct >= 1 || worstP95 >= 600 ? 'warn' : 'good';
  return { totalReq, totalErr, errPct, avgRate, worstP95, worstP99, lastP50, health };
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ServiceDetail({ service, apiTimeRange, onBack, onOpenTrace }: ServiceDetailProps) {
  const [detail, setDetail] = useState<ServiceDetailResponse | null>(null);
  const [slos, setSlos] = useState<Slo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // NAN-1595: server cache status of the displayed RED detail.
  const [cacheMeta, setCacheMeta] = useState<CacheMeta | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  // NAN-1544: the convergence strip is enterprise-only — its backing route is
  // absent (404) on open builds, so gate the render on the capability flag.
  const { capabilities } = useCapabilities();

  // NAN-1602: a user-initiated search's first detail fetch is live (no "cached"
  // badge); later window changes read cache. No-op in the console.
  const liveOnceRef = useRef(useIsLiveRun());

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setCacheMeta(null); // clear stale badge while the fresh detail loads
    const bypass = liveOnceRef.current;
    liveOnceRef.current = false;
    api.observability
      .getServiceDetail(service, apiTimeRange, { onMeta: (m) => !cancelled && setCacheMeta(m), bypass })
      .then((res) => {
        if (!cancelled) setDetail(res);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [service, apiTimeRange]);

  // NAN-1595: force a live re-fetch of the detail, bypassing the server cache.
  const refresh = () => {
    if (refreshing) return;
    setRefreshing(true);
    setError(null);
    api.observability
      .getServiceDetail(service, apiTimeRange, { onMeta: setCacheMeta, bypass: true })
      .then((res) => setDetail(res))
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setRefreshing(false));
  };

  // SLOs are best-effort decoration — never block / error the detail on them.
  useEffect(() => {
    let cancelled = false;
    api.observability
      .listSlos()
      .then((res) => {
        if (!cancelled) setSlos(res.slos.filter((s) => s.service === service));
      })
      .catch(() => {
        if (!cancelled) setSlos([]);
      });
    return () => {
      cancelled = true;
    };
  }, [service]);

  const Header = (
    <div className="flex items-center gap-3 flex-wrap">
      <button
        onClick={onBack}
        className="inline-flex items-center gap-1.5 h-7 px-2 rounded-md text-[11px] text-fg-3 hover:text-fg hover:bg-foreground/5"
      >
        <ArrowLeft className="w-[13px] h-[13px]" /> Services
      </button>
      <span className="w-7 h-7 rounded-md bg-foreground/5 flex items-center justify-center text-fg-2">
        <Box className="w-[15px] h-[15px]" />
      </span>
      <h2 className="text-[18px] font-semibold text-fg font-mono tracking-tight">{service}</h2>
      {detail && (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[10.5px] font-medium',
            HEALTH[summarize(detail).health].bg,
            HEALTH[summarize(detail).health].text
          )}
        >
          <HealthDot h={summarize(detail).health} pulse />
          {HEALTH[summarize(detail).health].label}
        </span>
      )}
      <span className="flex-1" />
      <CachedNotice meta={cacheMeta} onRefresh={refresh} refreshing={refreshing} />
    </div>
  );

  // NAN-1600: when embedded in the search page (`| service <name>`), report the
  // real RED-detail fetch to the footer (spinner → endpoint count · query time).
  // No-op in the Observability console.
  useReportPhase2Status({
    loading,
    settled: detail != null || error != null,
    error,
    totalCount: detail?.endpoints.length,
  });

  if (loading && !detail) {
    return (
      <div className="flex flex-col gap-3">
        {Header}
        <div className="flex items-center justify-center py-16 text-fg-3">
          <RefreshCw className="w-4 h-4 animate-spin" />
        </div>
      </div>
    );
  }

  if (error || !detail) {
    return (
      <div className="flex flex-col gap-3">
        {Header}
        <div className="rounded-lg border border-danger/30 bg-danger/5 px-4 py-6 text-[12.5px] text-danger">
          {error ? `Failed to load service: ${error}` : 'No data for this service in range.'}
        </div>
      </div>
    );
  }

  const sum = summarize(detail);
  const buckets = detail.red.rate.map((p) => p.t);
  const rateSeries: RedSeries[] = [
    { points: detail.red.rate.map((p) => p.v), color: 'var(--color-brand)', label: 'req/s', fill: true },
  ];
  const errSeries: RedSeries[] = [
    { points: detail.red.errors.map((p) => p.v), color: 'var(--color-danger)', label: 'errors', fill: true },
  ];
  const latencyBuckets = detail.red.latency.map((p) => p.t);
  const latencySeries: RedSeries[] = [
    { points: detail.red.latency.map((p) => p.p99), color: 'var(--color-warn)', label: 'p99' },
    { points: detail.red.latency.map((p) => p.p95), color: 'var(--color-brand)', label: 'p95' },
    { points: detail.red.latency.map((p) => p.p50), color: 'var(--color-fg-3)', label: 'p50', dashed: true },
  ];

  return (
    <div className="flex flex-col gap-3">
      {Header}

      {slos.length > 0 && <SloStrip slos={slos} />}

      {/* Convergence cross-link (NAN-1542): security detections on this service's
          hosts. Enterprise-only (NAN-1544) — hidden on open builds where the route
          is absent. */}
      {capabilities.observabilityConvergence && (
        <ServiceSecuritySignals service={service} apiTimeRange={apiTimeRange} />
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-2.5">
        <RedPanel
          title="Request rate"
          icon={<AreaChart className="w-[12px] h-[12px] text-brand" />}
          value={fmtNum(sum.avgRate)}
          unit="req/s"
          sub={`${fmtNum(sum.totalReq)} requests in range`}
        >
          <REDChart buckets={buckets} height={132} unit=" rps" series={rateSeries} yFmt={fmtNum} />
        </RedPanel>

        <RedPanel
          title="Error rate"
          icon={<AlertTriangle className="w-[12px] h-[12px] text-danger" />}
          value={fmtPct(sum.errPct)}
          sub={`${fmtNum(sum.totalErr)} errors in range`}
          subTone={sum.errPct >= 1 ? 'text-danger' : 'text-fg-3'}
        >
          <REDChart buckets={buckets} height={132} unit="" series={errSeries} yFmt={fmtNum} />
        </RedPanel>

        <RedPanel
          title="Latency"
          icon={<LineChart className="w-[12px] h-[12px] text-brand" />}
          value={fmtMs(sum.worstP95)}
          unit="p95"
          sub={`p50 ${fmtMs(sum.lastP50)} · p99 ${fmtMs(sum.worstP99)}`}
        >
          <REDChart
            buckets={latencyBuckets}
            height={132}
            unit="ms"
            series={latencySeries}
            yFmt={(v) => fmtMs(v).replace('ms', '').replace('s', '')}
          />
        </RedPanel>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1.5fr_1fr] gap-2.5">
        <EndpointsTable endpoints={detail.endpoints} />
        <ExemplarTraces exemplars={detail.exemplars} onOpenTrace={onOpenTrace} />
      </div>
    </div>
  );
}

export default ServiceDetail;
