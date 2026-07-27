// SPDX-License-Identifier: AGPL-3.0-or-later

// InfraTab (NAN-1537) — host inventory waffle + per-host snapshot.
//
// Ported from the design handoff's obs-infra.jsx (host waffle) + obs-charts.jsx
// (heatColor, in components/observability/infra-waffle.tsx). One tile per host,
// shaded by a selectable metric (CPU / mem / load / net), grouped by host.group,
// with a legend + summary line and a right-side detail panel + "hottest" list.
//
// Data is REAL: api.observability.getInfraHosts returns the latest-snapshot
// CPU/mem/load/net per host over the shared window. A metric a host never
// reported is null and renders as a faint "unreported" tile (not a hot 0).
//
// Deviations from the mock: the wire contract carries no per-host time series,
// zone/pods metadata, or a `service` field distinct from the group, so the
// detail panel shows the latest snapshot + status (no per-host CPU sparkline)
// and pivots to search rather than faking history.

import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { Server, Box, BarChart3, RefreshCw, Search } from 'lucide-react';
import { api } from '@/lib/api';
import type { CacheMeta } from '@/lib/api';
import { toApiTimeRange } from '@/hooks/use-api';
import type { TimeRange } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { CachedNotice } from '@/components/search/CachedNotice';
import { HEALTH, toDesignHealth } from '@/components/observability/format';
import {
  INFRA_METRICS,
  InfraWaffle,
  InfraLegend,
  heatColor,
  metricScaleMax,
  type InfraMetric,
  type InfraMetricKey,
} from '@/components/observability/infra-waffle';
import type { InfraHost, HostStatus } from '@/lib/api/observability';
import type { ObservabilityTabProps } from '../types';
import { nplQuotedBody } from '@/lib/npl-quote';

// One page of hosts pulled per fetch; "Load more" appends the next page.
const PAGE_SIZE = 100;

const STATUS_FILTERS: Array<{ key: HostStatus | 'all'; label: string }> = [
  { key: 'all', label: 'All' },
  { key: 'bad', label: 'Critical' },
  { key: 'warn', label: 'Degraded' },
  { key: 'good', label: 'Healthy' },
];

// ---------------------------------------------------------------------------
// detail panel — latest snapshot for the selected host
// ---------------------------------------------------------------------------

function HostDetail({ host, metric }: { host: InfraHost | null; metric: InfraMetric }) {
  if (!host) {
    return (
      <div className="rounded-lg border border-border bg-card p-5 flex flex-col items-center justify-center text-center min-h-[220px]">
        <Box className="w-6 h-6 text-fg-4 mb-2" />
        <div className="text-[12.5px] text-fg-2">Select a host</div>
        <div className="text-[11px] text-fg-4 mt-1 max-w-[200px]">
          Each tile is one host, shaded by {metric.label.toLowerCase()}. Click to inspect.
        </div>
      </div>
    );
  }

  const tone = toDesignHealth(host.status);
  // O34 (NAN-1721): pivot on the real UDM/OCSF host columns via an OR-query
  // (mirrors ServiceSecuritySignals). The old `host.name="…"` resolved to
  // `ext.host.name` on the logs table, which UDM/OCSF parsers never populate —
  // so "Explore in search" always came back empty.
  const hq = nplQuotedBody(host.host);
  const hostSearchQuery = `src_host="${hq}" OR dest_host="${hq}" OR hostname="${hq}" OR device.hostname="${hq}"`;
  const fmtCell = (v: number | null, fmt: (n: number) => string) => (v == null ? '–' : fmt(v));
  const stats: Array<{ k: string; v: string; hot: boolean }> = [
    { k: 'CPU', v: fmtCell(host.cpu_pct, (n) => Math.round(n) + '%'), hot: (host.cpu_pct ?? 0) >= 90 },
    { k: 'Memory', v: fmtCell(host.mem_pct, (n) => Math.round(n) + '%'), hot: (host.mem_pct ?? 0) >= 90 },
    { k: 'Load avg', v: fmtCell(host.load, (n) => n.toFixed(2)), hot: false },
    {
      k: 'Net',
      v: fmtCell(host.net_bytes_per_sec, (n) =>
        n >= 1e6 ? (n / 1e6).toFixed(1) + ' MB/s' : n >= 1e3 ? (n / 1e3).toFixed(1) + ' KB/s' : Math.round(n) + ' B/s'
      ),
      hot: false,
    },
  ];

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="px-3.5 py-3 border-b border-border flex items-center gap-2">
        <span className="w-6 h-6 rounded-md bg-foreground/5 flex items-center justify-center text-fg-2 shrink-0">
          <Box className="w-[14px] h-[14px]" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="font-mono text-[12.5px] text-fg truncate">{host.host}</div>
          <div className="text-[10px] text-fg-4 truncate">{host.group ?? 'ungrouped'}</div>
        </div>
        <span
          className={cn(
            'inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[9.5px] font-medium shrink-0',
            HEALTH[tone].bg,
            HEALTH[tone].text
          )}
        >
          <span className={cn('w-1.5 h-1.5 rounded-full', HEALTH[tone].dot)} />
          {HEALTH[tone].label}
        </span>
      </div>
      <div className="p-3.5 grid grid-cols-2 gap-y-2.5 gap-x-4">
        {stats.map((s) => (
          <div key={s.k} className="flex flex-col">
            <span className="text-[9.5px] uppercase tracking-wider text-fg-4">{s.k}</span>
            <span className={cn('font-mono text-[15px] tabular-nums', s.hot ? 'text-danger' : 'text-fg')}>
              {s.v}
            </span>
          </div>
        ))}
      </div>
      <div className="p-3 border-t border-border">
        <Link
          to={`/search?q=${encodeURIComponent(hostSearchQuery)}`}
          className="inline-flex items-center gap-1.5 h-8 px-2.5 rounded-md border border-border text-[11.5px] text-fg-2 hover:border-border-2 hover:text-foreground"
        >
          <Search className="w-[12px] h-[12px] text-fg-3" />
          Explore in search
        </Link>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// hottest list — top hosts by the active metric
// ---------------------------------------------------------------------------

function HottestList({
  hosts,
  metric,
  scaleMax,
  onSelect,
}: {
  hosts: InfraHost[];
  metric: InfraMetric;
  scaleMax: number;
  onSelect: (h: InfraHost) => void;
}) {
  const ranked = useMemo(
    () =>
      hosts
        .filter((h) => metric.value(h) != null)
        .sort((a, b) => (metric.value(b) ?? 0) - (metric.value(a) ?? 0))
        .slice(0, 6),
    [hosts, metric]
  );

  if (ranked.length === 0) return null;

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="px-3.5 py-2.5 border-b border-border font-mono text-[10px] uppercase tracking-[0.12em] text-fg-3 font-semibold flex items-center gap-2">
        <BarChart3 className="w-[12px] h-[12px] text-brand" /> Hottest · {metric.label}
      </div>
      {ranked.map((h) => {
        const v = metric.value(h) ?? 0;
        const hot = v >= scaleMax * 0.8;
        return (
          <button
            key={h.host}
            type="button"
            onClick={() => onSelect(h)}
            className="w-full flex items-center gap-2 px-3.5 py-1.5 border-b border-border/40 hover:bg-foreground/5 text-left"
          >
            <span
              className="w-2 h-2 rounded-[2px] shrink-0"
              style={{ background: heatColor(Math.min(1, v / scaleMax)) }}
            />
            <span className="font-mono text-[11px] text-fg truncate flex-1">{h.host}</span>
            <span className={cn('font-mono text-[11px] tabular-nums', hot ? 'text-danger' : 'text-fg-2')}>
              {metric.fmt(v)}
            </span>
          </button>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// tab
// ---------------------------------------------------------------------------

export function InfraTab({ timeRange }: ObservabilityTabProps) {
  const [hosts, setHosts] = useState<InfraHost[] | null>(null);
  const [total, setTotal] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [metricKey, setMetricKey] = useState<InfraMetricKey>('cpu');
  const [selected, setSelected] = useState<string | null>(null);
  // NAN-1595: server cache status of the displayed (first-page) host inventory.
  const [cacheMeta, setCacheMeta] = useState<CacheMeta | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  // Filter controls — pushed to the backend (NAN-1543). `q` and `env` are
  // debounced into their `debounced*` mirrors so typing doesn't fire per key.
  const [q, setQ] = useState('');
  const [debouncedQ, setDebouncedQ] = useState('');
  const [group, setGroup] = useState('');
  const [env, setEnv] = useState('');
  const [debouncedEnv, setDebouncedEnv] = useState('');
  const [status, setStatus] = useState<HostStatus | 'all'>('all');

  // O30 (NAN-1721): resolve the window fresh at fetch time so presets track
  // "now" across filter changes and manual refreshes rather than reusing the
  // absolute window frozen when the console first mounted. The window used by
  // the current page-0 fetch is captured so "Load more" pages stay inside it.
  const windowRef = useRef<TimeRange>(toApiTimeRange(timeRange));

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(q.trim()), 250);
    return () => clearTimeout(t);
  }, [q]);
  useEffect(() => {
    const t = setTimeout(() => setDebouncedEnv(env.trim()), 250);
    return () => clearTimeout(t);
  }, [env]);

  const filterArgs = useMemo(
    () => ({
      q: debouncedQ || undefined,
      group: group || undefined,
      env: debouncedEnv || undefined,
      status: status === 'all' ? undefined : status,
    }),
    [debouncedQ, group, debouncedEnv, status]
  );

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setCacheMeta(null); // clear stale badge while the fresh (page-0) list loads
    const resolved = toApiTimeRange(timeRange);
    windowRef.current = resolved;
    api.observability
      .getInfraHosts(
        resolved,
        { ...filterArgs, limit: PAGE_SIZE, offset: 0 },
        { onMeta: (m) => !cancelled && setCacheMeta(m) }
      )
      .then((res) => {
        if (cancelled) return;
        setHosts(res.hosts);
        setTotal(res.total ?? res.hosts.length);
        setHasMore(res.has_more ?? false);
        setSelected(null);
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
  }, [timeRange, filterArgs]);

  // NAN-1595: force a live re-fetch of the first page, bypassing the server cache.
  const refresh = () => {
    if (refreshing) return;
    setRefreshing(true);
    setError(null);
    const resolved = toApiTimeRange(timeRange);
    windowRef.current = resolved;
    api.observability
      .getInfraHosts(
        resolved,
        { ...filterArgs, limit: PAGE_SIZE, offset: 0 },
        { onMeta: setCacheMeta, bypass: true }
      )
      .then((res) => {
        setHosts(res.hosts);
        setTotal(res.total ?? res.hosts.length);
        setHasMore(res.has_more ?? false);
        setSelected(null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setRefreshing(false));
  };

  const loadMore = () => {
    if (loadingMore || !hasMore) return;
    const offset = hosts?.length ?? 0;
    setLoadingMore(true);
    api.observability
      .getInfraHosts(windowRef.current, { ...filterArgs, limit: PAGE_SIZE, offset })
      .then((res) => {
        setHosts((prev) => [...(prev ?? []), ...res.hosts]);
        setTotal(res.total ?? offset + res.hosts.length);
        setHasMore(res.has_more ?? false);
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoadingMore(false));
  };

  // Group options are derived from the loaded slice (best-effort — the wire
  // contract has no distinct-groups endpoint). A selected group survives even
  // if the current slice no longer contains it.
  const groupOptions = useMemo(() => {
    const set = new Set<string>();
    for (const h of hosts ?? []) if (h.group) set.add(h.group);
    if (group) set.add(group);
    return [...set].sort();
  }, [hosts, group]);

  const metric = INFRA_METRICS.find((m) => m.key === metricKey) ?? INFRA_METRICS[0];
  const scaleMax = useMemo(() => metricScaleMax(metric, hosts ?? []), [metric, hosts]);

  // Summary: reported-host count + average of the active metric over reporters.
  const summary = useMemo(() => {
    const xs = (hosts ?? []).map((h) => metric.value(h)).filter((v): v is number => v != null);
    const avg = xs.length ? xs.reduce((s, v) => s + v, 0) / xs.length : null;
    return { reporters: xs.length, avg };
  }, [hosts, metric]);

  const selectedHost = useMemo(
    () => (hosts ?? []).find((h) => h.host === selected) ?? null,
    [hosts, selected]
  );

  if (loading && hosts == null) {
    return (
      <div className="flex items-center justify-center py-16 text-fg-3">
        <RefreshCw className="w-4 h-4 animate-spin" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-danger/30 bg-danger/5 px-4 py-6 text-[12.5px] text-danger">
        Failed to load hosts: {error}
      </div>
    );
  }

  const rows = hosts ?? [];
  const filtersActive = debouncedQ !== '' || group !== '' || debouncedEnv !== '' || status !== 'all';
  const empty = rows.length === 0;

  return (
    <div className="flex flex-col gap-3">
      {/* color-metric selector + count + legend */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] uppercase tracking-wider text-fg-4 font-mono">color</span>
          <div className="flex items-center gap-px rounded-md bg-foreground/5 border border-border p-0.5">
            {INFRA_METRICS.map((m) => (
              <button
                key={m.key}
                type="button"
                onClick={() => setMetricKey(m.key)}
                className={cn(
                  'px-2 py-0.5 rounded-[3px] text-[10.5px] font-mono transition-colors',
                  m.key === metricKey ? 'bg-brand/18 text-brand font-semibold' : 'text-fg-3 hover:text-fg'
                )}
              >
                {m.label}
              </button>
            ))}
          </div>
        </div>
        <div className="flex-1" />
        <span className="font-mono text-[11px] text-fg-3 tabular-nums">
          {total > rows.length ? `${rows.length}/${total}` : rows.length} {total === 1 ? 'host' : 'hosts'}
          {summary.avg != null && ` · avg ${metric.label} ${metric.fmt(summary.avg)}`}
        </span>
        <CachedNotice meta={cacheMeta} onRefresh={refresh} refreshing={refreshing} />
        <InfraLegend metric={metric} scaleMax={scaleMax} />
      </div>

      {/* filters — hostname / group / env / status (pushed to backend, NAN-1543) */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative">
          <Search className="w-[13px] h-[13px] text-fg-4 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter hosts"
            className="h-8 w-[180px] rounded-md border border-border bg-transparent pl-8 pr-2.5 text-[12px] font-mono outline-none focus:border-brand/50 placeholder:text-fg-4"
          />
        </div>
        <select
          value={group}
          onChange={(e) => setGroup(e.target.value)}
          aria-label="Filter by host group"
          className="h-8 rounded-md border border-border bg-transparent px-2 text-[11.5px] font-mono text-fg-2 outline-none focus:border-brand/50"
        >
          <option value="">All groups</option>
          {groupOptions.map((g) => (
            <option key={g} value={g}>
              {g}
            </option>
          ))}
        </select>
        <input
          value={env}
          onChange={(e) => setEnv(e.target.value)}
          placeholder="env"
          aria-label="Filter by deployment environment"
          className="h-8 w-[120px] rounded-md border border-border bg-transparent px-2.5 text-[12px] font-mono outline-none focus:border-brand/50 placeholder:text-fg-4"
        />
        <div className="flex items-center gap-px rounded-md bg-foreground/5 border border-border p-0.5">
          {STATUS_FILTERS.map((s) => (
            <button
              key={s.key}
              type="button"
              onClick={() => setStatus(s.key)}
              className={cn(
                'px-2 py-0.5 rounded-[3px] text-[10.5px] font-mono transition-colors',
                s.key === status ? 'bg-brand/18 text-brand font-semibold' : 'text-fg-3 hover:text-fg'
              )}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {empty ? (
        <div className="rounded-lg border border-border bg-card px-4 py-12 text-center text-[12.5px] text-fg-3">
          <Server className="w-6 h-6 text-fg-4 mb-2 mx-auto" />
          {filtersActive
            ? 'No hosts match the current filters.'
            : 'No host metrics in the selected range. Send OpenTelemetry system metrics (system.cpu.utilization, system.memory.utilization, …) to populate this view.'}
        </div>
      ) : (
        <div className="grid grid-cols-[1fr_300px] gap-2.5 items-start">
          <InfraWaffle
            hosts={rows}
            metric={metric}
            selectedHost={selected}
            onSelect={(h) => setSelected(h.host)}
          />
          <div className="flex flex-col gap-2.5">
            <HostDetail host={selectedHost} metric={metric} />
            <HottestList hosts={rows} metric={metric} scaleMax={scaleMax} onSelect={(h) => setSelected(h.host)} />
          </div>
        </div>
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

export default InfraTab;
