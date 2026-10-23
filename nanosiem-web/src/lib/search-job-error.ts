import type { SearchJobStatus } from './api/types';

/**
 * NAN-3911: a durable search too large to ever run (query memory or scan
 * capacity). Retrying the same search cannot help, so this code gets no
 * Retry button and no AI query correction; the message says what to change.
 */
export const QUERY_TOO_LARGE = 'QUERY_TOO_LARGE';

const QUERY_TOO_LARGE_FALLBACK =
  'This search is too large to run. Narrow the time range, add filters, or reduce distinct-count fields.';

/** The search error for a failed async job's status. */
export function searchJobFailure(
  status: Pick<SearchJobStatus, 'error' | 'error_code'>,
  fallbackCode = 'JOB_FAILED',
): { code: string; message: string } {
  if (status.error_code === 'query_too_large') {
    return { code: QUERY_TOO_LARGE, message: status.error || QUERY_TOO_LARGE_FALLBACK };
  }
  return { code: fallbackCode, message: status.error || 'Search job failed' };
}
