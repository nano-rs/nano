// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * IOC retro-hunt view (NAN-1580) — front door to the value-sorted observables
 * projection. One engine, three pivot axes:
 *   ioc=<value> | retro              → single-indicator hunt summary
 *   ioc in [..]|feed() | retro       → campaign list, rarest-first
 *   … | retro by asset|user          → IR-shaped rollup, oldest first-seen first
 *
 * The initial /api/search response is a marker carrying `_retro_*` fields; the
 * actual data is fetched from POST /api/search/retro via useRetro. View-switcher
 * picks rewrite the `| retro` segment of the query and re-run through the
 * standard search path; drill-downs set `ioc=<value> | retro` (or pivot to
 * events). Verdict = prevalence band (rare/uncommon/common).
 */

import { useEffect, useMemo } from 'react';
import { Crosshair, Clock, Download, ChevronRight, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import type {
  TimeRange,
  RetroAxis,
  RetroSubmode,
  RetroListRow,
  RetroPivotRow,
  RetroIndicator,
} from '@/lib/api/types';
import { useRetro, readRetroMarker, prefetchRetro } from './useRetro';
import { CachedNotice } from '../CachedNotice';
import { RetroSummary } from './RetroSummary';
import { RetroCampaign } from './RetroCampaign';
import { RetroPivot } from './RetroPivot';

/** Local row shape — matches the sibling special views' `SearchResult`. */
interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

export interface RetroViewProps {
  /** The /api/search marker rows — results[0].fields carries the `_retro_*` marker. */
  results: SearchResult[];
  /** The executed query string (carries the `| retro` command). */
  query?: string;
  /** Time window the query was evaluated over. */
  timeRange?: TimeRange;
  /** Whether the Fields panel is collapsed (shows a restore pill). */
  fieldsCollapsed?: boolean;
  /** Current visible-fields count (for the Fields restore pill). */
  fieldsCount?: number;
  /** Expand the collapsed Fields panel. */
  onExpandFields?: () => void;
  /** Replace the running query and re-run (view-switcher + drill-down). */
  onSetQuery?: (query: string) => void;
  /** Replace the running query AND jump the time window, then re-run in one search. */
  onSetQueryWithTime?: (query: string, startIso: string, endIso: string) => void;
  /** Add a field=value filter to the running query (drill-down fallback). */
  onAddToQuery?: (field: string, value: string, exclude: boolean) => void;
}

type ViewId = 'summary' | 'list' | 'asset' | 'user';

const VIEWS: { id: ViewId; label: string }[] = [
  { id: 'summary', label: 'Summary' },
  { id: 'list', label: 'Campaign' },
  { id: 'asset', label: 'By asset' },
  { id: 'user', label: 'By user' },
];

/**
 * Rewrite the `| retro` segment of the running query for a view-switcher pick.
 * - summary: drop any `in [..]`/`feed()` source AND the `by …` axis suffix.
 * - list:    keep the source (or fall back to ioc=<indicator>), drop `by …`.
 * - asset/user: keep everything, set the `by <axis>` suffix.
 */
function rewriteRetroQuery(
  query: string | undefined,
  pick: ViewId,
  indicator: string | null
): string | null {
  if (!query) return null;
  const m = query.match(/\|\s*retro\b/i);
  if (!m) return null;

  // head = everything before `| retro` (the ioc source clause).
  const head = query.slice(0, m.index).trim();

  if (pick === 'summary') {
    // Collapse to a single-indicator hunt. Prefer the known indicator; else the
    // existing `ioc=…` clause; else leave the head as-is (server resolves).
    const iocEq = head.match(/ioc\s*=\s*"?([^"\s|]+)"?/i);
    const value = indicator || (iocEq ? iocEq[1] : null);
    const base = value ? `ioc=${value}` : head || 'ioc';
    return `${base} | retro`;
  }

  // list / asset / user keep the source clause from the head.
  const base = head || (indicator ? `ioc=${indicator}` : 'ioc');
  if (pick === 'list') return `${base} | retro`;
  return `${base} | retro by ${pick}`;
}

function RetroHeader({
  scope,
  count,
  active,
  views,
  fieldsCollapsed,
  fieldsCount,
  onExpandFields,
  onPick,
  cacheNotice,
}: {
  scope: React.ReactNode;
  count?: string;
  active: ViewId;
  views: { id: ViewId; label: string }[];
  fieldsCollapsed?: boolean;
  fieldsCount?: number;
  onExpandFields?: () => void;
  onPick: (id: ViewId) => void;
  cacheNotice?: React.ReactNode;
}) {
  return (
    <div className="py-2 px-3 border-b border-border flex items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-fg/70 font-semibold whitespace-nowrap">
      <span className="flex items-center gap-1.5 shrink-0">
        <Crosshair className="w-[13px] h-[13px] text-brand" />
        Retro hunt
      </span>
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-border text-[10px] normal-case tracking-normal font-semibold text-fg">
        <Clock className="w-[10px] h-[10px] text-fg-3" />
        <span className="text-fg-3">retention</span>
        <span className="text-brand">all history</span>
      </span>
      {scope && <span className="normal-case tracking-normal text-fg-2 truncate">{scope}</span>}
      {fieldsCollapsed && typeof fieldsCount === 'number' && onExpandFields && (
        <button
          onClick={onExpandFields}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-brand/40 text-[10px] normal-case tracking-normal font-semibold text-brand hover:bg-brand/10 transition-colors"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-brand/70" />
          Fields <span className="font-mono">{fieldsCount}</span>
          <ChevronRight className="w-3 h-3" />
        </button>
      )}
      <span className="flex-1" />
      {cacheNotice && <span className="normal-case tracking-normal">{cacheNotice}</span>}
      {count && <span className="text-fg-3 font-mono normal-case tracking-normal">{count}</span>}
      {/* view switcher */}
      <div className="flex items-center gap-0.5 p-0.5 rounded-md border border-border bg-fg/3 normal-case tracking-normal">
        {views.map((v) => (
          <button
            key={v.id}
            onClick={() => onPick(v.id)}
            className={cn(
              'px-2 py-0.5 rounded-[4px] text-[10.5px] font-semibold transition-colors',
              active === v.id ? 'bg-brand/15 text-brand' : 'text-fg-3 hover:text-fg'
            )}
          >
            {v.label}
          </button>
        ))}
      </div>
      <span className="text-fg-3 p-1">
        <Download className="w-[12px] h-[12px]" />
      </span>
    </div>
  );
}

export function RetroView({
  results,
  query,
  timeRange,
  fieldsCollapsed,
  fieldsCount,
  onExpandFields,
  onSetQuery,
  onSetQueryWithTime,
  onAddToQuery,
}: RetroViewProps) {
  const marker = useMemo(() => readRetroMarker(results?.[0]?.fields), [results]);
  const { data, loading, loadingMore, error, hasMore, loadMore, cacheMeta, refresh } = useRetro(query ?? '', timeRange, marker);

  const submode: RetroSubmode = data?.submode ?? marker.submode;
  const axis: RetroAxis = data?.axis ?? marker.axis;
  const active: ViewId = submode === 'pivot' ? (axis === 'user' ? 'user' : 'asset') : (submode as ViewId);

  // NAN-1594: once the active view has loaded, background-prefetch the other
  // pivot axes (by asset / by user) so switching tabs is instant. Non-blocking
  // and best-effort; uses the exact rewritten query the pivot will run so the
  // prefetch cache key matches the live fetch (and warms the backend cache too).
  useEffect(() => {
    if (!data || loading || !timeRange) return;
    for (const ax of ['asset', 'user'] as const) {
      if (submode === 'pivot' && axis === ax) continue; // already showing this axis
      prefetchRetro(rewriteRetroQuery(query, ax, marker.indicator), timeRange, ax);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, loading, query, axis, submode, timeRange?.start, timeRange?.end]);

  // Summary (one indicator) and Campaign (a list/feed of indicators) are
  // mutually exclusive on the source — you can't toggle a single IOC into a
  // campaign — so show whichever applies. By asset / By user work for both.
  const isMultiSource = /\bioc\s+in\b/i.test((query ?? '').split(/\|\s*retro/i)[0] ?? '');
  const views = VIEWS.filter((v) =>
    v.id === 'summary' ? !isMultiSource : v.id === 'list' ? isMultiSource : true
  );

  const pick = (id: ViewId) => {
    const rewritten = rewriteRetroQuery(query, id, marker.indicator);
    if (rewritten && onSetQuery) onSetQuery(rewritten);
  };

  // Quote an IOC value for the nPL `ioc=…` term. Raw values break the unquoted
  // value grammar (no `@`, `&`, `=`, …), so emails/URLs must be quoted. Prefer
  // double quotes; fall back to single quotes (stripping any embedded ') when
  // the value already contains a double quote.
  const quoteIoc = (v: string) => (v.includes('"') ? `'${v.replace(/'/g, '')}'` : `"${v}"`);

  // Drill-down: set `ioc=<value> | retro` and reuse the standard search path.
  const openIndicator = (value: string) => {
    if (onSetQuery) onSetQuery(`ioc=${quoteIoc(value)} | retro`);
    else onAddToQuery?.('ioc', value, false);
  };
  // Run `q` over the exposure window (first→last seen, padded ±1h so a
  // single-point hit stays viewable) in one search; falls back to no time jump.
  const drillToEvents = (q: string, firstSeen?: string | null, lastSeen?: string | null) => {
    const last = lastSeen ? new Date(lastSeen) : new Date();
    const first = firstSeen ? new Date(firstSeen) : last;
    const padMs = 60 * 60 * 1000;
    const startIso = new Date(Math.min(first.getTime(), last.getTime()) - padMs).toISOString();
    const endIso = new Date(last.getTime() + padMs).toISOString();
    if (onSetQueryWithTime) onSetQueryWithTime(q, startIso, endIso);
    else if (onSetQuery) onSetQuery(q);
  };

  // Drill into a hostname/user ENTITY's own events (an asset/user is not an
  // observable to sweep — `ioc="<host>"` matches nothing).
  const openEntity = (
    name: string,
    kind: 'asset' | 'user',
    firstSeen?: string | null,
    lastSeen?: string | null
  ) => {
    const q =
      kind === 'user'
        ? `user=${quoteIoc(name)}`
        : `src_host=${quoteIoc(name)} OR dest_host=${quoteIoc(name)} OR src_ip=${quoteIoc(name)} OR dest_ip=${quoteIoc(name)}`;
    drillToEvents(q, firstSeen, lastSeen);
  };

  // Pivot the INDICATOR itself to its raw events — the observable matchset (NOT
  // `| retro`) so the analyst sees the actual hits across all hosts — scoped to
  // its exposure window.
  const openIndicatorEvents = (value: string) =>
    drillToEvents(`ioc=${quoteIoc(value)}`, data?.indicator?.first_seen, data?.indicator?.last_seen);

  const campaignLabel =
    marker.feed && marker.feedArg
      ? `${marker.feed} · ${marker.feedArg}`
      : marker.feed
        ? marker.feed
        : marker.indicator ?? 'campaign';

  let scope: React.ReactNode;
  let count: string | undefined;
  if (submode === 'summary') {
    scope = (
      <span>
        indicator <span className="font-mono text-fg">{marker.indicator ?? data?.indicator?.value ?? ''}</span>
      </span>
    );
    count = '1 indicator';
  } else if (submode === 'pivot') {
    scope = (
      <span>
        <span className="font-mono text-fg">{campaignLabel}</span> · by {axis === 'user' ? 'user' : 'asset'}
      </span>
    );
    const n = data?.rows?.length ?? 0;
    count = `${n}${hasMore ? '+' : ''} ${axis === 'user' ? 'users' : 'assets'}`;
  } else {
    scope = (
      <span>
        list <span className="font-mono text-fg">{campaignLabel}</span>
      </span>
    );
    if (data) {
      count = `${data.rows?.length ?? 0} hit · ${data.total_indicators ?? data.rows?.length ?? 0} total`;
    }
  }

  return (
    <div className="flex-1 min-h-0 flex flex-col overflow-hidden">
      <RetroHeader
        scope={scope}
        count={count}
        active={active}
        views={views}
        fieldsCollapsed={fieldsCollapsed}
        fieldsCount={fieldsCount}
        onExpandFields={onExpandFields}
        onPick={pick}
        cacheNotice={<CachedNotice meta={cacheMeta} onRefresh={refresh} refreshing={loading} />}
      />

      {error && (
        <div className="m-4 rounded-lg border border-[oklch(62%_0.18_28/0.4)] p-4 text-[12px] text-[oklch(72%_0.17_28)]">
          Failed to load retro hunt: {error.message}
        </div>
      )}

      {!data && loading && (
        <div className="flex items-center justify-center py-12 text-[12px] font-mono text-fg-3">
          <Loader2 className="w-4 h-4 animate-spin mr-2" /> Running retro hunt…
        </div>
      )}

      {data && submode === 'summary' && data.indicator && (
        <RetroSummary
          indicator={data.indicator as RetroIndicator}
          totalHosts={data.total_hosts}
          onPivot={(id) => openEntity(id, 'asset', data?.indicator?.first_seen, data?.indicator?.last_seen)}
          onOpenIndicator={openIndicatorEvents}
        />
      )}

      {data && submode === 'summary' && !data.indicator && (
        <div className="flex items-center justify-center py-12 text-[12px] font-mono text-fg-3">
          No retention hits for this indicator.
        </div>
      )}

      {data && submode === 'list' && (
        <RetroCampaign
          rows={(data.rows ?? []) as RetroListRow[]}
          totalIndicators={data.total_indicators ?? data.rows?.length ?? 0}
          noHits={data.no_hits ?? []}
          totalHosts={data.total_hosts}
          hasMore={hasMore}
          loadingMore={loadingMore}
          onLoadMore={loadMore}
          onOpenIndicator={openIndicator}
        />
      )}

      {data && submode === 'pivot' && (
        <RetroPivot
          axis={axis}
          rows={(data.rows ?? []) as RetroPivotRow[]}
          hasMore={hasMore}
          loadingMore={loadingMore}
          onLoadMore={loadMore}
          onOpenEntity={(row) => openEntity(row.name, axis === 'user' ? 'user' : 'asset', row.first_seen, row.last_seen)}
        />
      )}
    </div>
  );
}
