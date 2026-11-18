// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5575: machines run SQL, people read nPL. Converts agent-written Agent
 * Lane SQL into nPL for display and for "Open in Search".
 *
 * Conversions are lazy and cheap: a component asks only once it is visible,
 * every conversion is cached by (SQL, window) for the session, and requests
 * made in the same tick go out as ONE batch call (a sweep trail with 30 SQL
 * steps is one request, not 30). The AI fallback is never called from here
 * automatically: it is a separate, explicit action.
 */
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { SearchDataset, SqlToNplRequest, SqlToNplResponse } from '@/lib/api/types';

/** Server cap per batch call. */
export const SQL_TO_NPL_BATCH_MAX = 50;
/** How long requests gather before a batch goes out. */
const BATCH_WINDOW_MS = 15;

type Pending = {
  request: SqlToNplRequest;
  resolve: (r: SqlToNplResponse) => void;
  reject: (e: unknown) => void;
};

type BatchFn = (items: SqlToNplRequest[]) => Promise<{ results: SqlToNplResponse[] }>;

/**
 * Collects conversion requests for one tick and sends them in batches.
 * Exported (with an injectable transport) for tests.
 */
export function createSqlToNplBatcher(send: BatchFn, windowMs = BATCH_WINDOW_MS) {
  let queue: Pending[] = [];
  let timer: ReturnType<typeof setTimeout> | null = null;

  const flush = () => {
    timer = null;
    const pending = queue;
    queue = [];
    for (let i = 0; i < pending.length; i += SQL_TO_NPL_BATCH_MAX) {
      const chunk = pending.slice(i, i + SQL_TO_NPL_BATCH_MAX);
      send(chunk.map((p) => p.request)).then(
        ({ results }) => {
          chunk.forEach((p, j) => {
            const r = results[j];
            if (r) p.resolve(r);
            else p.reject(new Error('conversion missing from the batch response'));
          });
        },
        (e) => chunk.forEach((p) => p.reject(e)),
      );
    }
  };

  return (request: SqlToNplRequest): Promise<SqlToNplResponse> =>
    new Promise((resolve, reject) => {
      queue.push({ request, resolve, reject });
      if (!timer) timer = setTimeout(flush, windowMs);
    });
}

const convert = createSqlToNplBatcher((items) => api.sqlToNplBatch(items));

/** The cache key for one conversion. */
export function sqlToNplKey(request: SqlToNplRequest, ai = false) {
  return ['sql-to-npl', ai ? 'ai' : 'static', request.sql, request.window_start ?? null, request.window_end ?? null] as const;
}

/** The static conversion of `request`, fetched only while `enabled`. */
export function useSqlToNpl(request: SqlToNplRequest, enabled: boolean) {
  return useQuery({
    queryKey: sqlToNplKey(request),
    queryFn: () => convert(request),
    enabled: enabled && request.sql.trim().length > 0,
    staleTime: Infinity,
    gcTime: 30 * 60 * 1000,
    retry: 1,
  });
}

/**
 * The Search URL for a converted query over its time range, on the dataset
 * the SQL read (NAN-5612: `dataset=signals` for SQL over the detections).
 */
export function sqlNplSearchUrl(
  npl: string,
  earliest?: string | null,
  latest?: string | null,
  dataset?: SearchDataset | null,
): string {
  const params = new URLSearchParams();
  params.set('q', npl);
  params.set('mode', 'piped');
  if (dataset && dataset !== 'logs') params.set('dataset', dataset);
  const valid = (iso?: string | null) => (iso && Number.isFinite(Date.parse(iso)) ? new Date(iso).toISOString() : null);
  const start = valid(earliest);
  const end = valid(latest);
  if (start) params.set('start', start);
  if (end) params.set('end', end);
  return `/search#${params.toString()}`;
}
