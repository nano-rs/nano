// SPDX-License-Identifier: AGPL-3.0-or-later

// TracesTab (NAN-1536) — the Observability console's Traces surface. Ported from
// the design handoff's obs-traces.jsx (TracesExplorer) and wired to REAL data:
//
//   • api.observability.listTraces(...) drives the latency scatter + the dense
//     trace table. Filters: service dropdown, min-duration (ms), errors-only.
//   • Clicking a trace (scatter dot or table row) opens an INLINE drill-in:
//     api.observability.getTrace(id) → the upgraded TraceWaterfall + SpanDrawer
//     (components/observability/TraceWaterfall). The drawer carries an
//     "Explore in search" pivot keyed on trace_id.
//
// The inline waterfall (rather than the shell's route-to-/trace/:id pivot) keeps
// the design's filter→scatter→waterfall flow on one screen; the standalone
// /trace/:id page still backs the log→trace pivot.
//
// Dense conventions: mono for ids/durations/counts, 11–13px text, 1px borders.

import { useMemo, useRef, useState } from 'react';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { ScatterChart, AlertTriangle, ChevronRight, Search } from 'lucide-react';
import { Link } from 'react-router-dom';
import { api } from '@/lib/api';
import type { CacheMeta } from '@/lib/api';
import { cn } from '@/lib/utils';
import { CachedNotice } from '@/components/search/CachedNotice';
import { formatTimeUTC, parseUTCTimestamp } from '@/lib/date-utils';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from '@/components/ui/dropdown-menu';
import { LatencyScatter, type ScatterTrace } from '@/components/observability/charts';
import { TraceWaterfall } from '@/components/observability/TraceWaterfall';
import type { ObservabilityTabProps } from '../types';
import type { RecentTrace } from '@/lib/api/types';

const NS_PER_MS = 1_000_000;

// Page size for keyset pagination (NAN-1539). One page is fetched at a time and
// appended via the cursor (the previous page's last trace start_time). A page
// shorter than this signals the end of the list (no further cursor).
const TRACE_PAGE_SIZE = 200;

function fmtMs(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '—';
  if (ms < 1) return `${(ms * 1000).toFixed(0)}µs`;
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`;
  return `${ms.toFixed(ms < 10 ? 2 : 1)}ms`;
}

export function TracesTab({ apiTimeRange }: ObservabilityTabProps) {
  const [svc, setSvc] = useState('');
  const [minDurMs, setMinDurMs] = useState('');
  const [errOnly, setErrOnly] = useState(false);

  // Inline drill-in: when set, the tab body swaps to the trace waterfall.
  const [openTraceId, setOpenTraceId] = useState<string | null>(null);

  // NAN-1595: server cache status of the displayed first page of traces. The
  // list paginates via useInfiniteQuery, so only the page-0 fetch drives the
  // badge; "load more" pages leave it untouched. `bypassRef` is read inside the
  // queryFn so a refresh forces the next page-0 fetch live (bypassing the cache).
  const [cacheMeta, setCacheMeta] = useState<CacheMeta | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const bypassRef = useRef(false);

  // Server-side filters (service / errors-only / min-duration) go on the list
  // request so the scatter+table reflect the filtered set without over-fetching.
  // Keyset pagination (NAN-1539): each page is fetched with a `before` cursor =
  // the previous page's last trace start_time. A short page ends the list.
  const tracesQuery = useInfiniteQuery({
    queryKey: [
      'obs-traces',
      apiTimeRange.start,
      apiTimeRange.end,
      svc,
      errOnly,
      minDurMs,
    ],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => {
      // Only the first page (no `before` cursor) drives the cache badge; "load
      // more" pages are appends and shouldn't change it. A pending refresh
      // bypasses the server cache for this page-0 fetch, then clears the flag.
      const isFirstPage = pageParam == null;
      const bypass = isFirstPage && bypassRef.current;
      if (isFirstPage) bypassRef.current = false;
      const cacheOpts = isFirstPage ? { onMeta: setCacheMeta, bypass } : undefined;
      return api.observability.listTraces(
        {
          time_range: apiTimeRange,
          service: svc || undefined,
          errors_only: errOnly || undefined,
          min_duration_ns: minDurMs ? Number(minDurMs) * NS_PER_MS : undefined,
          limit: TRACE_PAGE_SIZE,
          before: pageParam,
        },
        cacheOpts
      );
    },
    getNextPageParam: (lastPage) => {
      const rows = lastPage.traces ?? [];
      // A full page implies there may be more; the next cursor is the oldest
      // (last, since most-recent-first) row's start_time.
      if (rows.length < TRACE_PAGE_SIZE) return undefined;
      return rows[rows.length - 1]?.start_time;
    },
  });

  const traces: RecentTrace[] = useMemo(
    () => tracesQuery.data?.pages.flatMap((p) => p.traces ?? []) ?? [],
    [tracesQuery.data]
  );

  // NAN-1595: force a live re-fetch, bypassing the server cache. Setting the
  // bypass flag then refetching makes the page-0 queryFn re-request fresh; the
  // refreshing flag drives the badge's spinner state until React Query settles.
  const refresh = () => {
    if (refreshing) return;
    bypassRef.current = true;
    setRefreshing(true);
    void tracesQuery.refetch().finally(() => setRefreshing(false));
  };

  // The service dropdown is populated from the root services actually present in
  // the (unfiltered-by-service window's) returned traces — no extra endpoint.
  const serviceOptions = useMemo(() => {
    const set = new Set<string>();
    for (const t of traces) if (t.root_service) set.add(t.root_service);
    if (svc) set.add(svc); // keep the active filter selectable even if filtered out
    return [...set].sort();
  }, [traces, svc]);

  // The scatter plots one dot per trace. After several "load more" pages the
  // trace list can grow large; cap the plotted dots to a bounded sample
  // (NAN-1539) so the SVG stays responsive — the table still shows every loaded
  // row. Errored traces are kept preferentially (the scatter's whole point is
  // spotting outliers), then filled with the most recent.
  const SCATTER_CAP = 1500;
  const scatter: ScatterTrace[] = useMemo(() => {
    const toPoint = (t: RecentTrace): ScatterTrace => ({
      id: t.trace_id,
      startTs: parseUTCTimestamp(t.start_time).getTime(),
      durationMs: t.duration_ns / NS_PER_MS,
      errors: t.error_count,
      root: t.root_service,
    });
    if (traces.length <= SCATTER_CAP) return traces.map(toPoint);
    const errored = traces.filter((t) => t.error_count > 0);
    const ok = traces.filter((t) => t.error_count === 0);
    return [...errored, ...ok].slice(0, SCATTER_CAP).map(toPoint);
  }, [traces]);

  const erroredCount = useMemo(() => traces.filter((t) => t.error_count > 0).length, [traces]);

  // "Explore in search" → the spans dataset, carrying the active filters as real
  // nPL (the mock's literal `| trace` was a placeholder, not valid syntax).
  const exploreTo = useMemo(() => {
    const q = [
      svc ? `service_name="${svc}"` : '',
      errOnly ? `status_code="ERROR"` : '',
      minDurMs ? `duration_ns>${Number(minDurMs) * NS_PER_MS}` : '',
    ]
      .filter(Boolean)
      .join(' ');
    return `/search?dataset=spans${q ? `&q=${encodeURIComponent(q)}` : ''}`;
  }, [svc, errOnly, minDurMs]);

  // Fetch the selected trace's spans for the inline waterfall.
  const traceQuery = useQuery({
    queryKey: ['obs-trace', openTraceId],
    queryFn: () => api.observability.getTrace(openTraceId as string),
    enabled: !!openTraceId,
  });

  // ---- inline drill-in view ----
  if (openTraceId) {
    if (traceQuery.isLoading) {
      return (
        <div className="text-[12.5px] text-fg-3 py-16 text-center">Loading trace…</div>
      );
    }
    if (traceQuery.error || !traceQuery.data) {
      return (
        <div className="flex flex-col items-center gap-3 py-16">
          <div className="text-[12.5px] text-fg-3">Failed to load trace.</div>
          <button
            type="button"
            onClick={() => setOpenTraceId(null)}
            className="h-7 px-2.5 rounded-md border border-border text-[11px] text-fg-2 hover:border-border-2"
          >
            Back to traces
          </button>
        </div>
      );
    }
    return (
      <TraceWaterfall
        traceId={openTraceId}
        spans={traceQuery.data.spans}
        onBack={() => setOpenTraceId(null)}
      />
    );
  }

  // ---- list view ----
  return (
    <div className="flex flex-col gap-3">
      {/* filter bar */}
      <div className="flex items-center gap-2 flex-wrap">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              className="inline-flex items-center gap-1.5 h-8 px-2.5 rounded-md border border-border text-[12px] text-fg-2 hover:border-border-2"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-brand shrink-0" />
              <span className="font-mono">{svc || 'all services'}</span>
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-[200px] max-h-[300px] overflow-y-auto scrollbar-thin">
            <DropdownMenuItem onClick={() => setSvc('')}>
              <span className="font-mono text-[11.5px]">all services</span>
            </DropdownMenuItem>
            {serviceOptions.map((s) => (
              <DropdownMenuItem key={s} onClick={() => setSvc(s)} className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-brand shrink-0" />
                <span className="font-mono text-[11.5px] truncate">{s}</span>
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        <input
          value={minDurMs}
          onChange={(e) => setMinDurMs(e.target.value.replace(/\D/g, ''))}
          placeholder="min duration (ms)"
          inputMode="numeric"
          className="h-8 w-[150px] rounded-md border border-border bg-transparent px-2.5 text-[12px] font-mono outline-none focus:border-brand/50 placeholder:text-fg-4"
        />

        <button
          type="button"
          onClick={() => setErrOnly((v) => !v)}
          className={cn(
            'inline-flex items-center gap-1.5 h-8 px-2.5 rounded-md border text-[12px] transition-colors',
            errOnly
              ? 'border-danger/50 bg-danger/10 text-danger'
              : 'border-border text-fg-2 hover:border-border-2'
          )}
        >
          <span
            className={cn(
              'w-3 h-3 rounded-[3px] border flex items-center justify-center',
              errOnly ? 'bg-danger border-danger' : 'border-border-2'
            )}
          >
            {errOnly && <span className="w-1.5 h-1.5 rounded-[1px] bg-brand-ink" />}
          </span>
          Errors only
        </button>

        <span className="flex-1" aria-hidden />

        <span className="font-mono text-[11px] text-fg-3 tabular-nums">
          {traces.length} traces · <span className="text-danger">{erroredCount} errored</span>
        </span>
        <CachedNotice meta={cacheMeta} onRefresh={refresh} refreshing={refreshing} />
        <Link
          to={exploreTo}
          className="inline-flex items-center gap-1.5 h-8 px-2.5 rounded-md border border-border text-[11.5px] text-fg-2 hover:border-border-2 hover:text-foreground"
        >
          <Search className="w-[12px] h-[12px] text-fg-3" />
          Explore in search
        </Link>
      </div>

      {/* latency scatter */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <div className="px-3.5 py-2.5 border-b border-border flex items-center gap-2">
          <ScatterChart className="w-[13px] h-[13px] text-brand" />
          <span className="font-mono text-[10.5px] uppercase tracking-[0.12em] text-fg-2 font-semibold">
            Latency distribution
          </span>
          <span className="text-[10.5px] text-fg-4 hidden sm:inline">
            each dot is a trace · y = duration · click to open
          </span>
          <span className="flex-1" aria-hidden />
          <span className="flex items-center gap-3 text-[10px] font-mono text-fg-3">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-brand" /> ok
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-danger" /> error
            </span>
          </span>
        </div>
        <div className="p-3">
          {tracesQuery.isLoading ? (
            <div className="flex items-center justify-center h-[200px] text-[12px] text-fg-3">
              Loading traces…
            </div>
          ) : (
            <LatencyScatter traces={scatter} onPick={(t) => setOpenTraceId(t.id)} />
          )}
        </div>
      </div>

      {/* table */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <div className="grid grid-cols-[1.5fr_1fr_1.3fr_60px_70px_90px_110px_18px] gap-3 px-3.5 py-2 border-b border-border font-mono text-[9.5px] uppercase tracking-[0.1em] text-fg-3 font-semibold">
          <span>Trace ID</span>
          <span>Root service</span>
          <span>Operation</span>
          <span className="text-right">Spans</span>
          <span className="text-right">Errors</span>
          <span className="text-right">Duration</span>
          <span className="text-right">Start (UTC)</span>
          <span />
        </div>
        {!tracesQuery.isLoading && traces.length === 0 ? (
          <div className="text-center py-12 text-[12px] text-fg-3">No traces in range.</div>
        ) : (
          traces.map((t) => {
            const durMs = t.duration_ns / NS_PER_MS;
            return (
              <button
                type="button"
                key={t.trace_id}
                onClick={() => setOpenTraceId(t.trace_id)}
                className="group w-full grid grid-cols-[1.5fr_1fr_1.3fr_60px_70px_90px_110px_18px] gap-3 px-3.5 py-2 border-b border-border/50 hover:bg-foreground/[0.03] items-center text-left"
              >
                <span className="font-mono text-[11.5px] text-brand truncate">{t.trace_id}</span>
                <span className="font-mono text-[11.5px] text-fg-2 flex items-center gap-1.5 min-w-0">
                  <span className="w-1.5 h-1.5 rounded-full bg-brand shrink-0" />
                  <span className="truncate">{t.root_service || '—'}</span>
                </span>
                <span className="font-mono text-[11.5px] text-foreground truncate">
                  {t.root_name || '—'}
                </span>
                <span className="font-mono text-[11.5px] text-fg-2 tabular-nums text-right">
                  {t.span_count}
                </span>
                <span
                  className={cn(
                    'font-mono text-[11.5px] tabular-nums text-right flex items-center justify-end gap-1',
                    t.error_count > 0 ? 'text-danger' : 'text-fg-4'
                  )}
                >
                  {t.error_count > 0 && <AlertTriangle className="w-[11px] h-[11px]" />}
                  {t.error_count}
                </span>
                <span
                  className={cn(
                    'font-mono text-[11.5px] tabular-nums text-right',
                    durMs >= 600 ? 'text-warn' : 'text-foreground'
                  )}
                >
                  {fmtMs(durMs)}
                </span>
                <span className="font-mono text-[11px] text-fg-3 tabular-nums text-right">
                  {formatTimeUTC(t.start_time)}
                </span>
                <ChevronRight className="w-3.5 h-3.5 text-fg-4 group-hover:text-fg-2" />
              </button>
            );
          })
        )}

        {/* Load more — keyset pagination (NAN-1539). Appends the next page via
            the oldest visible trace's start_time cursor. */}
        {!tracesQuery.isLoading && traces.length > 0 && (
          <div className="flex items-center justify-center px-3.5 py-2.5">
            {tracesQuery.hasNextPage ? (
              <button
                type="button"
                onClick={() => tracesQuery.fetchNextPage()}
                disabled={tracesQuery.isFetchingNextPage}
                className="h-7 px-3 rounded-md border border-border text-[11.5px] text-fg-2 hover:border-border-2 hover:text-foreground disabled:opacity-50 font-mono tabular-nums"
              >
                {tracesQuery.isFetchingNextPage
                  ? 'Loading…'
                  : `Load more (${traces.length} shown)`}
              </button>
            ) : (
              <span className="text-[10.5px] font-mono text-fg-4 tabular-nums">
                end of results · {traces.length} traces
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default TracesTab;
