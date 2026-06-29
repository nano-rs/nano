// SPDX-License-Identifier: AGPL-3.0-or-later

// RumTab (NAN-1538) — real-user-monitoring: web vitals, page views, JS errors.
//
// Ported from the design handoff's obs-rum.jsx (RUMView) + the WebVital gauge in
// obs-charts2.jsx. Data is REAL: api.observability.getRum returns p75 Core Web
// Vitals, page-view count + per-bucket series, JS-error count + recent errors,
// and a top-pages breakdown over the shared time window.
//
// Deviations from the mock: the wire contract has no sessions / Apdex / per-page
// INP+error% / browser-on-error / dedicated error-rate series, so those are
// omitted rather than faked. LCP arrives in ms and is shown in seconds on the
// gauge (good ≤ 2.5s, poor > 4.0s); INP stays ms; CLS is unitless. A web-vital
// the page never reported (null) renders a muted "no data" gauge.

import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Globe, AlertTriangle, RefreshCw, MonitorSmartphone, Search } from 'lucide-react';
import { api } from '@/lib/api';
import type { CacheMeta } from '@/lib/api';
import { cn } from '@/lib/utils';
import { CachedNotice } from '@/components/search/CachedNotice';
import { useCapabilities } from '@/hooks/use-capabilities';
import { REDChart } from '@/components/observability/charts';
import { WebVital } from '@/components/observability/web-vital';
import { fmtNum, fmtMs } from '@/components/observability/format';
import type { RumResponse, RumRecentError } from '@/lib/api/observability';
import type { ObservabilityTabProps } from '../types';

// NAN-1553: enterprise RUM→investigation pivot. Each non-empty entity on an
// error span (user / client IP / session) links to the unified search, tying a
// client-side error to that identity's security activity. Gated on
// `observabilityConvergence` (the same convergence capability as the Service-
// detail security-signals strip) — the core RUM drill-in stays open.
function ErrorEntityPivots({
  e,
  onPivot,
}: {
  e: RumRecentError;
  onPivot: (query: string) => void;
}) {
  const chips: Array<{ label: string; value: string; query: string }> = [];
  if (e.user) chips.push({ label: 'user', value: e.user, query: `user="${e.user}"` });
  if (e.src_ip) chips.push({ label: 'ip', value: e.src_ip, query: `src_ip="${e.src_ip}"` });
  if (e.session)
    chips.push({ label: 'session', value: e.session, query: `session_id="${e.session}"` });
  if (chips.length === 0) return null;
  return (
    <div className="flex items-center gap-1.5 mt-1 flex-wrap">
      {chips.map((c) => (
        <button
          key={c.label}
          type="button"
          onClick={() => onPivot(c.query)}
          title={`Investigate this ${c.label} in search`}
          className="inline-flex items-center gap-1 h-[18px] px-1.5 rounded-sm border border-border bg-foreground/[0.02] font-mono text-[9.5px] hover:border-brand/50 hover:text-brand cursor-pointer"
        >
          <span className="text-fg-4 uppercase tracking-wider">{c.label}</span>
          <span className="text-fg-2 truncate max-w-[120px]">{c.value}</span>
        </button>
      ))}
    </div>
  );
}

// Short relative-time label for the recent-errors strip ("38s ago", "4m ago").
const timeAgo = (ts: string): string => {
  const t = new Date(ts).getTime();
  if (Number.isNaN(t)) return '';
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
};

// ---------------------------------------------------------------------------
// Counts card — page views + JS errors (the two scalars the wire carries)
// ---------------------------------------------------------------------------

function CountsCard({ rum }: { rum: RumResponse }) {
  const cells: Array<[string, string, string]> = [
    ['Page views', fmtNum(rum.page_views), 'text-fg'],
    ['JS errors', fmtNum(rum.js_errors), rum.js_errors > 0 ? 'text-danger' : 'text-fg'],
  ];
  return (
    <div className="rounded-lg border border-border bg-card px-3.5 py-3 grid grid-cols-2 gap-y-2.5 content-center">
      {cells.map(([k, v, cls]) => (
        <div key={k} className="flex flex-col">
          <span className="text-[9px] uppercase tracking-wider text-fg-4">{k}</span>
          <span className={cn('font-mono text-[16px] tabular-nums leading-none mt-1', cls)}>{v}</span>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Top pages — path · views · LCP
// ---------------------------------------------------------------------------

const TOP_COLS = 'grid-cols-[1fr_90px_80px]';

function TopPages({ rum, onPickPage }: { rum: RumResponse; onPickPage: (page: string) => void }) {
  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="px-3.5 py-2.5 border-b border-border font-mono text-[10.5px] uppercase tracking-[0.12em] text-fg-2 font-semibold">
        Top pages
      </div>
      <div
        className={cn(
          'grid gap-2 px-3.5 py-1.5 border-b border-border font-mono text-[9px] uppercase tracking-[0.1em] text-fg-4',
          TOP_COLS
        )}
      >
        <span>Path</span>
        <span className="text-right">Views</span>
        <span className="text-right">LCP p75</span>
      </div>
      {rum.top_pages.length === 0 ? (
        <div className="px-3.5 py-6 text-center text-[11.5px] text-fg-3">No page views in range.</div>
      ) : (
        rum.top_pages.map((p) => (
          <button
            key={p.page}
            type="button"
            onClick={() => onPickPage(p.page)}
            title="Filter this tab to this page"
            className={cn(
              'group w-full text-left grid gap-2 px-3.5 py-2 border-b border-border/50 hover:bg-foreground/[0.03] items-center cursor-pointer',
              TOP_COLS
            )}
          >
            <span className="font-mono text-[11.5px] text-fg truncate group-hover:text-brand">{p.page}</span>
            <span className="font-mono text-[11.5px] text-fg-2 tabular-nums text-right">{fmtNum(p.views)}</span>
            <span
              className={cn(
                'font-mono text-[11.5px] tabular-nums text-right',
                p.lcp_ms != null && p.lcp_ms > 2500 ? 'text-warn' : 'text-fg-2'
              )}
            >
              {fmtMs(p.lcp_ms)}
            </span>
          </button>
        ))
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Recent JS errors
// ---------------------------------------------------------------------------

function RecentErrors({ rum, onPickPage }: { rum: RumResponse; onPickPage: (page: string) => void }) {
  const navigate = useNavigate();
  const { capabilities } = useCapabilities();
  const pivot = (query: string) => navigate(`/search?q=${encodeURIComponent(query)}`);
  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="px-3.5 py-2.5 border-b border-border font-mono text-[10.5px] uppercase tracking-[0.12em] text-fg-2 font-semibold flex items-center gap-2">
        <AlertTriangle className="w-[12px] h-[12px] text-danger" /> Recent JS errors
      </div>
      {rum.recent_errors.length === 0 ? (
        <div className="px-3.5 py-6 text-center text-[11.5px] text-fg-3">No client errors in range.</div>
      ) : (
        rum.recent_errors.map((e, i) => (
          <div key={i} className="px-3.5 py-2 border-b border-border/50 hover:bg-foreground/[0.03]">
            <div className="flex items-start gap-2">
              <span className="font-mono text-[11px] text-fg leading-snug flex-1 break-words">{e.message}</span>
              <span className="font-mono text-[10px] text-fg-4 tabular-nums shrink-0 mt-px">{timeAgo(e.ts)}</span>
            </div>
            <button
              type="button"
              onClick={() => onPickPage(e.page)}
              title="Filter this tab to this page"
              className="block max-w-full text-left text-[10px] text-fg-4 mt-0.5 font-mono truncate hover:text-brand cursor-pointer"
            >
              {e.page}
            </button>
            {capabilities.observabilityConvergence && <ErrorEntityPivots e={e} onPivot={pivot} />}
          </div>
        ))
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab
// ---------------------------------------------------------------------------

export function RumTab({ apiTimeRange }: ObservabilityTabProps) {
  const [rum, setRum] = useState<RumResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // NAN-1595: server cache status of the displayed RUM payload.
  const [cacheMeta, setCacheMeta] = useState<CacheMeta | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  // Filters — page/route substring + browser + env, pushed to the backend
  // (NAN-1543). Text inputs are debounced into their `debounced*` mirrors.
  const [page, setPage] = useState('');
  const [debouncedPage, setDebouncedPage] = useState('');
  const [browser, setBrowser] = useState('');
  const [debouncedBrowser, setDebouncedBrowser] = useState('');
  const [env, setEnv] = useState('');
  const [debouncedEnv, setDebouncedEnv] = useState('');

  useEffect(() => {
    const t = setTimeout(() => setDebouncedPage(page.trim()), 250);
    return () => clearTimeout(t);
  }, [page]);
  useEffect(() => {
    const t = setTimeout(() => setDebouncedBrowser(browser.trim()), 250);
    return () => clearTimeout(t);
  }, [browser]);
  useEffect(() => {
    const t = setTimeout(() => setDebouncedEnv(env.trim()), 250);
    return () => clearTimeout(t);
  }, [env]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setCacheMeta(null); // clear stale badge while the fresh payload loads
    api.observability
      .getRum(
        apiTimeRange,
        {
          page: debouncedPage || undefined,
          browser: debouncedBrowser || undefined,
          env: debouncedEnv || undefined,
        },
        { onMeta: (m) => !cancelled && setCacheMeta(m) }
      )
      .then((res) => {
        if (!cancelled) setRum(res);
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
  }, [apiTimeRange, debouncedPage, debouncedBrowser, debouncedEnv]);

  // NAN-1595: force a live re-fetch of the RUM payload, bypassing the server cache.
  const refresh = () => {
    if (refreshing) return;
    setRefreshing(true);
    setError(null);
    api.observability
      .getRum(
        apiTimeRange,
        {
          page: debouncedPage || undefined,
          browser: debouncedBrowser || undefined,
          env: debouncedEnv || undefined,
        },
        { onMeta: setCacheMeta, bypass: true }
      )
      .then((res) => setRum(res))
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setRefreshing(false));
  };

  // Page-views series → REDChart inputs (buckets + values), memoized.
  const pv = useMemo(() => {
    const series = rum?.page_views_series ?? [];
    return {
      buckets: series.map((p) => p.t),
      points: series.map((p) => p.v),
    };
  }, [rum]);

  const filtersActive = debouncedPage !== '' || debouncedBrowser !== '' || debouncedEnv !== '';

  // Filter bar — always rendered so filters stay reachable across loading /
  // empty / data states (NAN-1543).
  const filterBar = (
    <div className="flex items-center gap-2 flex-wrap">
      <div className="relative">
        <Search className="w-[13px] h-[13px] text-fg-4 absolute left-2.5 top-1/2 -translate-y-1/2" />
        <input
          value={page}
          onChange={(e) => setPage(e.target.value)}
          placeholder="Filter by page/route"
          className="h-8 w-[200px] rounded-md border border-border bg-transparent pl-8 pr-2.5 text-[12px] font-mono outline-none focus:border-brand/50 placeholder:text-fg-4"
        />
      </div>
      <input
        value={browser}
        onChange={(e) => setBrowser(e.target.value)}
        placeholder="browser"
        aria-label="Filter by browser"
        className="h-8 w-[130px] rounded-md border border-border bg-transparent px-2.5 text-[12px] font-mono outline-none focus:border-brand/50 placeholder:text-fg-4"
      />
      <input
        value={env}
        onChange={(e) => setEnv(e.target.value)}
        placeholder="env"
        aria-label="Filter by deployment environment"
        className="h-8 w-[120px] rounded-md border border-border bg-transparent px-2.5 text-[12px] font-mono outline-none focus:border-brand/50 placeholder:text-fg-4"
      />
      {loading && rum != null && <RefreshCw className="w-3.5 h-3.5 text-fg-4 animate-spin" />}
      <span className="flex-1" />
      <CachedNotice meta={cacheMeta} onRefresh={refresh} refreshing={refreshing} />
    </div>
  );

  if (loading && rum == null) {
    return (
      <div className="flex flex-col gap-3.5">
        {filterBar}
        <div className="flex items-center justify-center py-16 text-fg-3">
          <RefreshCw className="w-4 h-4 animate-spin" />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col gap-3.5">
        {filterBar}
        <div className="rounded-lg border border-danger/30 bg-danger/5 px-4 py-6 text-[12.5px] text-danger">
          Failed to load RUM data: {error}
        </div>
      </div>
    );
  }

  const hasData =
    rum != null &&
    (rum.page_views > 0 ||
      rum.js_errors > 0 ||
      rum.web_vitals.lcp_ms != null ||
      rum.web_vitals.inp_ms != null ||
      rum.web_vitals.cls != null);

  if (!rum || !hasData) {
    return (
      <div className="flex flex-col gap-3.5">
        {filterBar}
        <div className="rounded-lg border border-border bg-card px-4 py-12 text-center text-[12.5px] text-fg-3">
          <MonitorSmartphone className="w-5 h-5 text-fg-4 mx-auto mb-2" />
          {filtersActive
            ? 'No real-user-monitoring data matches the current filters.'
            : 'No real-user-monitoring data in the selected range. Send web-vitals metrics and pageview spans to populate this view.'}
        </div>
      </div>
    );
  }

  const v = rum.web_vitals;

  return (
    <div className="flex flex-col gap-3.5">
      {filterBar}

      {/* web vitals + counts */}
      <div className="grid grid-cols-1 md:grid-cols-[1fr_1fr_1fr_1.1fr] gap-2.5">
        <WebVital
          label="LCP"
          value={v.lcp_ms == null ? null : v.lcp_ms / 1000}
          unit="s"
          good={2.5}
          poor={4.0}
          fmt={(x) => x.toFixed(2)}
        />
        <WebVital label="INP" value={v.inp_ms} unit="ms" good={200} poor={500} fmt={(x) => String(Math.round(x))} />
        <WebVital label="CLS" value={v.cls} unit="" good={0.1} poor={0.25} fmt={(x) => x.toFixed(2)} />
        <CountsCard rum={rum} />
      </div>

      {/* page-views series */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <div className="px-3.5 py-2.5 border-b border-border font-mono text-[10px] uppercase tracking-[0.12em] text-fg-3 flex items-center gap-2">
          <Globe className="w-[12px] h-[12px] text-brand" /> Page views
        </div>
        <div className="px-2 py-2">
          {pv.points.length === 0 ? (
            <div className="flex items-center justify-center text-[12px] text-fg-3" style={{ height: 130 }}>
              No page-view samples in range.
            </div>
          ) : (
            <REDChart
              buckets={pv.buckets}
              height={130}
              unit=""
              yFmt={fmtNum}
              series={[{ points: pv.points, color: 'var(--color-brand)', label: 'page views', fill: true }]}
            />
          )}
        </div>
      </div>

      {/* top pages + recent errors */}
      <div className="grid grid-cols-1 lg:grid-cols-[1.3fr_1fr] gap-2.5">
        <TopPages rum={rum} onPickPage={setPage} />
        <RecentErrors rum={rum} onPickPage={setPage} />
      </div>
    </div>
  );
}

export default RumTab;
