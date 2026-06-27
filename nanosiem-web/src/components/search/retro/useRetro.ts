// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Retro-hunt data hook (NAN-1580).
 *
 * Reads the marker fields the backend stamped on `results[0].fields`
 * (`_retro_submode` / `_retro_axis` / `_retro_indicator` / `_retro_feed`) to
 * know what to fetch, then calls `POST /api/search/retro`. The summary is
 * single-shot; the campaign + pivot tables paginate server-side via
 * `offset`/`limit` and accumulate rows for a "load more" button.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '@/lib/api';
import type {
  RetroResponse,
  RetroAxis,
  RetroListRow,
  RetroPivotRow,
  RetroSubmode,
  TimeRange,
} from '@/lib/api/types';

const PAGE_SIZE = 50;

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

export interface UseRetroResult {
  data: RetroResponse | null;
  loading: boolean;
  /** True while a "load more" page is in flight (not the initial load). */
  loadingMore: boolean;
  error: Error | null;
  hasMore: boolean;
  loadMore: () => void;
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
  const offsetRef = useRef(0);

  const isPaged = marker.submode !== 'summary';

  const fetchPage = useCallback(
    async (offset: number, append: boolean) => {
      if (!timeRange) return;
      if (append) setLoadingMore(true);
      else setLoading(true);
      setError(null);
      try {
        const resp = await api.getRetro({
          query,
          time_range: timeRange,
          axis: marker.axis,
          offset: isPaged ? offset : undefined,
          limit: isPaged ? PAGE_SIZE : undefined,
        });
        offsetRef.current = offset;
        // Backend serializes pivot rows under `pivot_rows` (list+pivot row
        // shapes differ); normalize both submodes onto `rows` so the views and
        // the pagination merge below read a single field. (NAN-1580)
        const norm: RetroResponse =
          marker.submode === 'pivot' ? { ...resp, rows: resp.pivot_rows ?? [] } : resp;
        setData((prev) => {
          if (!append || !prev) return norm;
          // Merge the new page's rows into the accumulated list.
          const prevRows = (prev.rows ?? []) as (RetroListRow | RetroPivotRow)[];
          const nextRows = (norm.rows ?? []) as (RetroListRow | RetroPivotRow)[];
          return { ...norm, rows: [...prevRows, ...nextRows] as RetroResponse['rows'] };
        });
      } catch (err) {
        setError(err instanceof Error ? err : new Error(String(err)));
      } finally {
        if (append) setLoadingMore(false);
        else setLoading(false);
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

  return {
    data,
    loading,
    loadingMore,
    error,
    hasMore: Boolean(data?.has_more),
    loadMore,
  };
}
