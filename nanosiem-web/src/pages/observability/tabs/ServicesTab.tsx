// SPDX-License-Identifier: AGPL-3.0-or-later

// ServicesTab (NAN-1536) — RED overview across all services, health-sorted.
//
// Ported from the design handoff's obs-services.jsx (ServicesOverview +
// SummaryStrip + list/grid views). Data is REAL: api.observability.listServices
// returns RED aggregates per service_name over the shared time window. Each row
// / card drills into the service detail via onOpenService(service).
//
// Deviations from the mock: the dependency "map" view + the per-service
// kind/lang/version/deps decoration aren't in the wire contract (the backend
// groups by service_name only), so this renders the list + grid views and omits
// the topology map and synthetic metadata rather than faking it.

import { useEffect, useState } from 'react';
import { Search, ChevronRight, Box, List as ListIcon, LayoutGrid, RefreshCw } from 'lucide-react';
import { api } from '@/lib/api';
import { useReportPhase2Status } from '@/components/search/footer-reporter';
import type { CacheMeta } from '@/lib/api';
import { cn } from '@/lib/utils';
import { CachedNotice } from '@/components/search/CachedNotice';
import { Sparkline } from '@/components/observability/charts';
import { HEALTH, fmtNum, fmtRate, fmtMs, fmtPct, toDesignHealth, type DesignHealth } from '@/components/observability/format';
import type { ServiceSummary, ServiceHealth, ServicesSort } from '@/lib/api/observability';
import type { ObservabilityTabProps } from '../types';

type ViewMode = 'list' | 'grid';

// One page of services pulled per fetch; "Load more" appends the next page.
const PAGE_SIZE = 50;

const HEALTH_FILTERS: Array<{ key: ServiceHealth | 'all'; label: string }> = [
  { key: 'all', label: 'All' },
  { key: 'bad', label: 'Critical' },
  { key: 'warn', label: 'Degraded' },
  { key: 'good', label: 'Healthy' },
];

const SORTS: Array<{ key: ServicesSort; label: string }> = [
  { key: 'rate', label: 'Rate' },
  { key: 'error_rate', label: 'Errors' },
  { key: 'p95', label: 'p95' },
  { key: 'name', label: 'Name' },
];

const HealthDot = ({ h, pulse }: { h: DesignHealth; pulse?: boolean }) => (
  <span
    className={cn(
      'inline-block w-[7px] h-[7px] rounded-full shrink-0',
      HEALTH[h].dot,
      pulse && h !== 'good' && 'animate-pulse'
    )}
  />
);

const spark = (s: ServiceSummary): number[] => s.sparkline.map((p) => p.v);

// ---------------------------------------------------------------------------
// Summary strip — aggregate request rate / error rate / worst p95 / healthy
// ---------------------------------------------------------------------------

function SummaryStrip({ services, total }: { services: ServiceSummary[]; total: number }) {
  const totalRate = services.reduce((s, x) => s + x.rate_per_sec, 0);
  const totalErr = services.reduce((s, x) => s + x.rate_per_sec * x.error_rate, 0);
  const weightedErrPct = totalRate > 0 ? (totalErr / totalRate) * 100 : 0;
  const worstP95 = services.length ? Math.max(...services.map((s) => s.p95_ms)) : 0;
  const healthy = services.filter((s) => s.health === 'good').length;

  const cards: Array<{ label: string; value: string; unit: string; tone: DesignHealth }> = [
    { label: 'Request rate', value: fmtRate(totalRate), unit: 'req/s', tone: 'good' },
    {
      label: 'Error rate',
      value: fmtPct(weightedErrPct),
      unit: '',
      tone: weightedErrPct >= 5 ? 'danger' : weightedErrPct >= 1 ? 'warn' : 'good',
    },
    {
      label: 'Latency p95',
      value: fmtMs(worstP95),
      unit: 'worst',
      tone: worstP95 >= 1800 ? 'danger' : worstP95 >= 600 ? 'warn' : 'good',
    },
    {
      label: 'Services',
      value: total > services.length ? `${services.length}/${total}` : `${healthy}/${services.length}`,
      unit: total > services.length ? 'loaded' : 'healthy',
      tone: healthy === services.length ? 'good' : 'warn',
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5">
      {cards.map((c) => (
        <div key={c.label} className="rounded-lg border border-border bg-card px-3.5 py-3 flex flex-col gap-1.5">
          <div className="flex items-center gap-2">
            <span className={cn('w-1.5 h-1.5 rounded-full', HEALTH[c.tone].dot)} />
            <span className="text-[10px] uppercase tracking-[0.1em] text-fg-3 font-medium">{c.label}</span>
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-[24px] text-fg font-semibold leading-none tracking-tight font-mono tabular-nums">
              {c.value}
            </span>
            {c.unit && <span className="text-[10.5px] text-fg-3">{c.unit}</span>}
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// List view
// ---------------------------------------------------------------------------

const LIST_COLS = 'grid-cols-[22px_minmax(180px,1.4fr)_1fr_1fr_1.5fr_18px]';

function ServiceListRow({ s, onOpen }: { s: ServiceSummary; onOpen: (svc: string) => void }) {
  const h = toDesignHealth(s.health);
  const errPct = s.error_rate * 100;
  const errPerSec = s.rate_per_sec * s.error_rate;
  return (
    <button
      onClick={() => onOpen(s.service)}
      className={cn(
        'group w-full grid items-center gap-3 px-3 py-2.5 text-left border-b border-border/60 hover:bg-foreground/5 transition-colors',
        LIST_COLS
      )}
    >
      <span className="flex items-center justify-center">
        <HealthDot h={h} pulse />
      </span>
      <div className="min-w-0 flex items-center gap-2">
        <span className="w-6 h-6 rounded-md bg-foreground/5 flex items-center justify-center text-fg-3 shrink-0">
          <Box className="w-[13px] h-[13px]" />
        </span>
        <div className="min-w-0">
          <div className="text-[13px] text-fg font-medium truncate leading-tight font-mono">{s.service}</div>
          <div className="text-[10px] text-fg-4 truncate">{fmtNum(s.request_count)} spans</div>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <div className="min-w-0">
          <div className="text-[12.5px] font-mono text-fg tabular-nums">
            {fmtRate(s.rate_per_sec)}
            <span className="text-fg-4 text-[10px]"> rps</span>
          </div>
        </div>
        <Sparkline data={spark(s)} color="var(--color-brand)" w={64} h={20} />
      </div>
      <div className="flex items-center gap-2">
        <div className="min-w-0">
          <div
            className={cn(
              'text-[12.5px] font-mono tabular-nums',
              errPct >= 5 ? 'text-danger' : errPct >= 1 ? 'text-warn' : 'text-fg'
            )}
          >
            {fmtPct(errPct)}
          </div>
          <div className="text-[10px] text-fg-4">{fmtRate(errPerSec)} err/s</div>
        </div>
      </div>
      <div className="flex items-center gap-3.5 font-mono tabular-nums">
        {(
          [
            ['p50', s.p50_ms, 'text-fg-2'],
            ['p95', s.p95_ms, s.p95_ms >= 600 ? 'text-warn' : 'text-fg'],
            ['p99', s.p99_ms, s.p99_ms >= 1800 ? 'text-danger' : 'text-fg-2'],
          ] as Array<[string, number, string]>
        ).map(([k, v, cls]) => (
          <div key={k} className="leading-tight">
            <div className="text-[9px] text-fg-4 uppercase tracking-wider">{k}</div>
            <div className={cn('text-[12px]', cls)}>{fmtMs(v)}</div>
          </div>
        ))}
      </div>
      <ChevronRight className="w-3.5 h-3.5 text-fg-4 group-hover:text-fg-2" />
    </button>
  );
}

function ServicesList({ services, onOpen }: { services: ServiceSummary[]; onOpen: (svc: string) => void }) {
  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div
        className={cn(
          'grid gap-3 px-3 py-2 border-b border-border bg-panel/50 font-mono text-[9.5px] uppercase tracking-[0.1em] text-fg-3 font-semibold',
          LIST_COLS
        )}
      >
        <span />
        <span>Service</span>
        <span>Request rate</span>
        <span>Errors</span>
        <span>Latency</span>
        <span />
      </div>
      {services.map((s) => (
        <ServiceListRow key={s.service} s={s} onOpen={onOpen} />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Grid view
// ---------------------------------------------------------------------------

function ServiceCard({ s, onOpen }: { s: ServiceSummary; onOpen: (svc: string) => void }) {
  const h = toDesignHealth(s.health);
  const errPct = s.error_rate * 100;
  const metrics: Array<{ k: string; v: string; series: number[]; color: string; cls: string }> = [
    { k: 'rps', v: fmtRate(s.rate_per_sec), series: spark(s), color: 'var(--color-brand)', cls: 'text-fg' },
    {
      k: 'err',
      v: fmtPct(errPct),
      series: spark(s),
      color: errPct >= 1 ? 'var(--color-danger)' : 'var(--color-fg-3)',
      cls: errPct >= 5 ? 'text-danger' : errPct >= 1 ? 'text-warn' : 'text-fg',
    },
    {
      k: 'p95',
      v: fmtMs(s.p95_ms),
      series: spark(s),
      color: 'var(--color-brand)',
      cls: s.p95_ms >= 600 ? 'text-warn' : 'text-fg',
    },
  ];
  return (
    <button
      onClick={() => onOpen(s.service)}
      className="group text-left rounded-lg border border-border bg-card p-3.5 hover:border-border-2 transition-colors flex flex-col gap-3"
    >
      <div className="flex items-center gap-2">
        <span className="w-6 h-6 rounded-md bg-foreground/5 flex items-center justify-center text-fg-3 shrink-0">
          <Box className="w-[13px] h-[13px]" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-[13px] text-fg font-medium truncate font-mono leading-tight">{s.service}</div>
          <div className="text-[10px] text-fg-4">{fmtNum(s.request_count)} spans</div>
        </div>
        <span
          className={cn(
            'inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[9.5px] font-medium',
            HEALTH[h].bg,
            HEALTH[h].text
          )}
        >
          <HealthDot h={h} />
          {HEALTH[h].label}
        </span>
      </div>
      <div className="grid grid-cols-3 gap-2">
        {metrics.map((m) => (
          <div key={m.k} className="flex flex-col gap-1 [&>svg]:w-full">
            <span className="text-[9px] uppercase tracking-wider text-fg-4">{m.k}</span>
            <span className={cn('text-[14px] font-mono tabular-nums leading-none', m.cls)}>{m.v}</span>
            <Sparkline data={m.series} color={m.color} fill w={80} h={18} />
          </div>
        ))}
      </div>
    </button>
  );
}

function ServicesGrid({ services, onOpen }: { services: ServiceSummary[]; onOpen: (svc: string) => void }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
      {services.map((s) => (
        <ServiceCard key={s.service} s={s} onOpen={onOpen} />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab
// ---------------------------------------------------------------------------

export function ServicesTab({ apiTimeRange, onOpenService }: ObservabilityTabProps) {
  const [services, setServices] = useState<ServiceSummary[] | null>(null);
  const [total, setTotal] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<ViewMode>('list');
  // NAN-1595: server cache status of the displayed (first-page) services list.
  const [cacheMeta, setCacheMeta] = useState<CacheMeta | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  // Filter / sort controls — pushed to the backend (NAN-1543). `q` is debounced
  // into `debouncedQ` so each keystroke doesn't fire a fetch.
  const [q, setQ] = useState('');
  const [debouncedQ, setDebouncedQ] = useState('');
  const [health, setHealth] = useState<ServiceHealth | 'all'>('all');
  const [sort, setSort] = useState<ServicesSort>('rate');

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(q.trim()), 250);
    return () => clearTimeout(t);
  }, [q]);

  // Reset + reload whenever the window or any filter/sort changes.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setCacheMeta(null); // clear stale badge while the fresh (page-0) list loads
    api.observability
      .listServices(
        apiTimeRange,
        {
          q: debouncedQ || undefined,
          health: health === 'all' ? undefined : health,
          sort,
          limit: PAGE_SIZE,
          offset: 0,
        },
        { onMeta: (m) => !cancelled && setCacheMeta(m) }
      )
      .then((res) => {
        if (cancelled) return;
        setServices(res.services);
        setTotal(res.total ?? res.services.length);
        setHasMore(res.has_more ?? false);
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
  }, [apiTimeRange, debouncedQ, health, sort]);

  // NAN-1595: force a live re-fetch of the first page, bypassing the server cache.
  const refresh = () => {
    if (refreshing) return;
    setRefreshing(true);
    setError(null);
    api.observability
      .listServices(
        apiTimeRange,
        {
          q: debouncedQ || undefined,
          health: health === 'all' ? undefined : health,
          sort,
          limit: PAGE_SIZE,
          offset: 0,
        },
        { onMeta: setCacheMeta, bypass: true }
      )
      .then((res) => {
        setServices(res.services);
        setTotal(res.total ?? res.services.length);
        setHasMore(res.has_more ?? false);
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setRefreshing(false));
  };

  const loadMore = () => {
    if (loadingMore || !hasMore) return;
    const offset = services?.length ?? 0;
    setLoadingMore(true);
    api.observability
      .listServices(apiTimeRange, {
        q: debouncedQ || undefined,
        health: health === 'all' ? undefined : health,
        sort,
        limit: PAGE_SIZE,
        offset,
      })
      .then((res) => {
        setServices((prev) => [...(prev ?? []), ...res.services]);
        setTotal(res.total ?? offset + res.services.length);
        setHasMore(res.has_more ?? false);
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoadingMore(false));
  };

  // Health filter is post-aggregation server-side; for the loaded slice the
  // backend has already applied it, so the rows render as-returned.
  const rows = services ?? [];

  // NAN-1600: when embedded in the search page (`| services`), report the real
  // fetch to the footer (spinner → service count · query time). No-op in the
  // Observability console, which owns its own loading UI.
  useReportPhase2Status({
    loading,
    settled: services != null || error != null,
    error,
    totalCount: total,
  });

  if (loading && services == null) {
    return (
      <div className="flex items-center justify-center py-16 text-fg-3">
        <RefreshCw className="w-4 h-4 animate-spin" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-danger/30 bg-danger/5 px-4 py-6 text-[12.5px] text-danger">
        Failed to load services: {error}
      </div>
    );
  }

  const filtersActive = debouncedQ !== '' || health !== 'all';
  const empty = rows.length === 0;

  return (
    <div className="flex flex-col gap-3.5">
      <SummaryStrip services={rows} total={total} />

      <div className="flex items-center gap-2 flex-wrap">
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-fg-3 tabular-nums">
          {total} {total === 1 ? 'service' : 'services'}
        </span>
        <CachedNotice meta={cacheMeta} onRefresh={refresh} refreshing={refreshing} />
        <div className="flex-1" />

        {/* sort */}
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] uppercase tracking-wider text-fg-4 font-mono">sort</span>
          <div className="flex items-center gap-px rounded-md bg-foreground/5 border border-border p-0.5">
            {SORTS.map((s) => (
              <button
                key={s.key}
                type="button"
                onClick={() => setSort(s.key)}
                className={cn(
                  'px-2 py-0.5 rounded-[3px] text-[10.5px] font-mono transition-colors',
                  s.key === sort ? 'bg-brand/18 text-brand font-semibold' : 'text-fg-3 hover:text-fg'
                )}
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        {/* health */}
        <div className="flex items-center gap-px rounded-md bg-foreground/5 border border-border p-0.5">
          {HEALTH_FILTERS.map((h) => (
            <button
              key={h.key}
              type="button"
              onClick={() => setHealth(h.key)}
              className={cn(
                'px-2 py-0.5 rounded-[3px] text-[10.5px] font-mono transition-colors',
                h.key === health ? 'bg-brand/18 text-brand font-semibold' : 'text-fg-3 hover:text-fg'
              )}
            >
              {h.label}
            </button>
          ))}
        </div>

        <div className="relative">
          <Search className="w-[13px] h-[13px] text-fg-4 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter services"
            className="h-8 w-[200px] rounded-md border border-border bg-transparent pl-8 pr-2.5 text-[12px] font-mono outline-none focus:border-brand/50 placeholder:text-fg-4"
          />
        </div>
        <div className="flex items-center gap-px rounded-md bg-foreground/5 border border-border p-0.5">
          {(
            [
              ['list', ListIcon],
              ['grid', LayoutGrid],
            ] as Array<[ViewMode, typeof ListIcon]>
          ).map(([mode, Icon]) => (
            <button
              key={mode}
              onClick={() => setView(mode)}
              aria-label={`${mode} view`}
              className={cn(
                'inline-flex items-center justify-center w-7 h-7 rounded-[4px] transition-colors',
                view === mode ? 'bg-brand/18 text-brand' : 'text-fg-3 hover:text-fg'
              )}
            >
              <Icon className="w-[14px] h-[14px]" />
            </button>
          ))}
        </div>
      </div>

      {empty ? (
        <div className="rounded-lg border border-border bg-card px-4 py-12 text-center text-[12.5px] text-fg-3">
          {filtersActive
            ? 'No services match the current filters.'
            : 'No service spans in the selected range. Send OpenTelemetry traces to populate this view.'}
        </div>
      ) : view === 'grid' ? (
        <ServicesGrid services={rows} onOpen={onOpenService} />
      ) : (
        <ServicesList services={rows} onOpen={onOpenService} />
      )}

      {hasMore && !empty && (
        <div className="flex justify-center">
          <button
            type="button"
            onClick={loadMore}
            disabled={loadingMore}
            className="inline-flex items-center gap-1.5 h-8 px-3 rounded-md border border-border text-[11.5px] font-mono text-fg-2 hover:border-border-2 hover:text-foreground disabled:opacity-50"
          >
            {loadingMore ? <RefreshCw className="w-3 h-3 animate-spin" /> : null}
            Load more · {rows.length}/{total}
          </button>
        </div>
      )}
    </div>
  );
}

export default ServicesTab;
