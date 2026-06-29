// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Retro-hunt data hook (NAN-1580).
 *
 * Reads the marker fields the backend stamped on `results[0].fields`
 * (`_retro_submode` / `_retro_axis` / `_retro_indicator` / `_retro_feed`) to
 * know what to fetch, then calls `POST /api/search/retro`. The summary is
 * single-shot; the campaign + pivot tables paginate server-side via
 * `offset`/`limit` and accumulate rows for a "load more" button.
 *
 * NAN-1594: a module-level page-0 cache lets us background-prefetch the other
 * pivot axes (by asset / by user) while the analyst reads the active view, so
 * pivoting is instant. The cache is module-level (not React state) on purpose:
 * the view switcher pivots by rewriting the `| retro` query and re-running the
 * whole search, which unmounts + remounts RetroView — component state wouldn't
 * survive that, but this cache (and the warmed Dragonfly entry behind it) does.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '@/lib/api';
import type { CacheMeta } from '@/lib/api';
import type {
  RetroResponse,
  RetroAxis,
  RetroListRow,
  RetroPivotRow,
  RetroSubmode,
  TimeRange,
} from '@/lib/api/types';

const PAGE_SIZE = 50;

/** How long a prefetched/loaded page-0 stays usable. Kept short because SIEM
 * data is live; long enough to cover "read the summary, then pivot". */
const PAGE_CACHE_TTL_MS = 120_000;

export interface RetroMarker {
  submode: RetroSubmode;
  axis: RetroAxis;
  indicator: string | null;
  feed: string | null;
  feedArg: string | null;
}

/** Extract the retro marker from the initial /api/search marker row. */
export function readRetroMarker(fields: Record<string, unknown> | undefined): RetroMarker {
  const submode = (fields?._retro_submode as RetroSubmode) || 'summary';
  const axis = (fields?._retro_axis as RetroAxis) || (submode === 'pivot' ? 'asset' : 'indicator');
  const indicator = (fields?._retro_indicator as string | null) ?? null;
  const feed = (fields?._retro_feed as string | null) ?? null;
  const feedArg = (fields?._retro_feed_arg as string | null) ?? null;
  return { submode, axis, indicator, feed, feedArg };
}

// ── Module-level page-0 cache + in-flight dedup (NAN-1594) ──────────────────

interface RetroPageParams {
  query: string;
  axis: RetroAxis;
  offset: number | undefined;
  limit: number | undefined;
}

interface CachedPage {
  at: number;
  data: RetroResponse;
}

const pageCache = new Map<string, CachedPage>();
const inflight = new Map<string, Promise<RetroResponse>>();

/** Bound the cache so a long session with many distinct retro queries can't
 * grow it without limit. Entries are evicted on stale-read (TTL) but ones never
 * read again wouldn't be, so cap by count and drop the oldest (Map preserves
 * insertion order). 48 ≈ 16 queries × 3 axes — comfortably more than a session. */
const PAGE_CACHE_MAX = 48;

function pageKey(p: RetroPageParams): string {
  return `${p.query} ${p.axis} ${p.offset ?? ''} ${p.limit ?? ''}`;
}

/** Insert, evicting the oldest entry first if at capacity. */
function cacheSet(key: string, data: RetroResponse): void {
  // Refresh insertion order on re-set so a re-read entry isn't the eviction victim.
  pageCache.delete(key);
  if (pageCache.size >= PAGE_CACHE_MAX) {
    const oldest = pageCache.keys().next().value;
    if (oldest !== undefined) pageCache.delete(oldest);
  }
  pageCache.set(key, { at: Date.now(), data });
}

/** Read a still-fresh cached entry (incl. its write time), evicting if stale. */
function readFresh(key: string): CachedPage | null {
  const entry = pageCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.at > PAGE_CACHE_TTL_MS) {
    pageCache.delete(key);
    return null;
  }
  return entry;
}

/** Pivot rows arrive under `pivot_rows`; normalize both submodes onto `rows`
 * (NAN-1580) using the response's own submode so cached + live paths agree. */
function normalize(resp: RetroResponse): RetroResponse {
  return resp.submode === 'pivot' ? { ...resp, rows: resp.pivot_rows ?? [] } : resp;
}

/** Fetch one retro page, deduping concurrent identical requests and populating
 * the module cache. Shared by the live hook and the background prefetcher so
 * their cache keys (and therefore hits) line up exactly. */
function fetchRetroPage(
  p: RetroPageParams,
  timeRange: TimeRange,
  cacheOpts?: import('@/lib/api').CacheRequestOpts
): Promise<RetroResponse> {
  const key = pageKey(p);
  // A bypass (refresh) must hit the server fresh — don't ride a non-bypass
  // in-flight request, and drop any stale client entry so it re-warms clean.
  if (cacheOpts?.bypass) {
    pageCache.delete(key);
  } else {
    const existing = inflight.get(key);
    if (existing) return existing;
  }

  const promise = api
    .getRetro(
      {
        query: p.query,
        time_range: timeRange,
        axis: p.axis,
        offset: p.offset,
        limit: p.limit,
      },
      cacheOpts
    )
    .then((resp) => {
      const norm = normalize(resp);
      cacheSet(key, norm);
      return norm;
    })
    .finally(() => {
      inflight.delete(key);
    });

  if (!cacheOpts?.bypass) inflight.set(key, promise);
  return promise;
}

/**
 * Background-warm a pivot axis' first page (NAN-1594). Fire-and-forget and
 * non-blocking: deduped against the cache + in-flight map, errors swallowed
 * (a failed warm just means the real pivot fetches normally). `query` must be
 * the already-rewritten `… | retro by <axis>` string the pivot will run, so the
 * cache key matches the live fetch.
 */
export function prefetchRetro(
  query: string | null,
  timeRange: TimeRange | undefined,
  axis: RetroAxis
): void {
  if (!query || !timeRange) return;
  const p: RetroPageParams = { query, axis, offset: 0, limit: PAGE_SIZE };
  const key = pageKey(p);
  if (readFresh(key) || inflight.has(key)) return;
  void fetchRetroPage(p, timeRange).catch(() => {});
}

export interface UseRetroResult {
  data: RetroResponse | null;
  loading: boolean;
  /** True while a "load more" page is in flight (not the initial load). */
  loadingMore: boolean;
  error: Error | null;
  hasMore: boolean;
  loadMore: () => void;
  /** Server/client cache status of the displayed page-0 (NAN-1595). */
  cacheMeta: CacheMeta | null;
  /** Force a live re-fetch of page-0, bypassing both client + server caches. */
  refresh: () => void;
}

/**
 * Fetch retro data for the given marker + query. For list/pivot submodes the
 * returned `data.rows` accumulates across pages; `loadMore` advances the offset.
 */
export function useRetro(
  query: string,
  timeRange: TimeRange | undefined,
  marker: RetroMarker
): UseRetroResult {
  const [data, setData] = useState<RetroResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [cacheMeta, setCacheMeta] = useState<CacheMeta | null>(null);
  const offsetRef = useRef(0);
  // NAN-1595: drop stale out-of-order page-0 responses (query/axis/window change
  // or refresh racing the in-flight load) so the badge/data match the latest request.
  const reqSeq = useRef(0);

  const isPaged = marker.submode !== 'summary';

  const fetchPage = useCallback(
    async (offset: number, append: boolean, bypass = false) => {
      // Bump first so even a no-timeRange call invalidates any older in-flight response.
      const seq = ++reqSeq.current;
      if (!timeRange) {
        setLoading(false);
        setLoadingMore(false);
        return;
      }
      const params: RetroPageParams = {
        query,
        axis: marker.axis,
        offset: isPaged ? offset : undefined,
        limit: isPaged ? PAGE_SIZE : undefined,
      };

      // Initial load: serve a prefetched/cached page-0 instantly (no spinner,
      // no network) so a pivot the analyst already warmed renders immediately.
      // That counts as cached too — surface it with the client-side age.
      if (!append && !bypass) {
        const cached = readFresh(pageKey(params));
        if (cached) {
          setData(cached.data);
          setCacheMeta({ hit: true, ageSecs: Math.floor((Date.now() - cached.at) / 1000) });
          offsetRef.current = offset;
          setError(null);
          setLoading(false);
          return;
        }
      }

      if (append) {
        setLoadingMore(true);
      } else {
        setLoading(true);
        setCacheMeta(null); // clear stale badge while the fresh page loads
      }
      setError(null);
      try {
        // page-0 captures the server cache status; appends don't affect the badge.
        const norm = await fetchRetroPage(
          params,
          timeRange,
          append ? undefined : { onMeta: (m) => { if (seq === reqSeq.current) setCacheMeta(m); }, bypass }
        );
        if (seq !== reqSeq.current) return; // a newer request superseded this one
        offsetRef.current = offset;
        setData((prev) => {
          if (!append || !prev) return norm;
          // Merge the new page's rows into the accumulated list.
          const prevRows = (prev.rows ?? []) as (RetroListRow | RetroPivotRow)[];
          const nextRows = (norm.rows ?? []) as (RetroListRow | RetroPivotRow)[];
          return { ...norm, rows: [...prevRows, ...nextRows] as RetroResponse['rows'] };
        });
      } catch (err) {
        if (seq === reqSeq.current) setError(err instanceof Error ? err : new Error(String(err)));
      } finally {
        if (seq === reqSeq.current) {
          if (append) setLoadingMore(false);
          else setLoading(false);
        }
      }
    },
    [query, timeRange, marker.axis, isPaged]
  );

  // Reset + load whenever the query / axis / window changes.
  useEffect(() => {
    offsetRef.current = 0;
    fetchPage(0, false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, marker.axis, timeRange?.start, timeRange?.end]);

  const loadMore = useCallback(() => {
    if (loadingMore || loading) return;
    if (!data?.has_more) return;
    fetchPage(offsetRef.current + PAGE_SIZE, true);
  }, [data?.has_more, loadingMore, loading, fetchPage]);

  // NAN-1595: force a live re-fetch of page-0, bypassing client + server caches.
  const refresh = useCallback(() => {
    offsetRef.current = 0;
    fetchPage(0, false, true);
  }, [fetchPage]);

  return {
    data,
    loading,
    loadingMore,
    error,
    hasMore: Boolean(data?.has_more),
    loadMore,
    cacheMeta,
    refresh,
  };
}
