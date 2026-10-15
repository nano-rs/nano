// SPDX-License-Identifier: AGPL-3.0-or-later

import { abortableDelay } from './abortable-delay';
import { ApiClientError } from '@/lib/api';

/**
 * Was this failure the search service's 5-concurrent-per-user admission gate?
 * (NAN-2361: over-limit requests 429 IMMEDIATELY — no queueing.)
 */
export function isAdmissionDenied(err: unknown): boolean {
  return err instanceof ApiClientError && (err.status === 429 || err.code === 'ADMISSION_DENIED');
}

/**
 * Retry a search-service call that was refused by admission control
 * (429 / ADMISSION_DENIED). Mirrors TimelineVisualization's `searchWithRetry`:
 * the refusal is instantaneous, so a short backoff while sibling queries drain
 * almost always succeeds; anything else (real errors) is NOT retried.
 *
 * Used by the `| cloud` view, where rapid facet clicks + infinite scroll +
 * open pivot sheets can stack concurrent /api/search-family calls past the
 * admission limit — a path that previously degraded silently to "no data".
 */
export async function retryOnAdmissionDenied<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    signal?.throwIfAborted();
    try {
      return await fn();
    } catch (err) {
      if (!isAdmissionDenied(err) || attempt >= 3) throw err;
      await abortableDelay(350 * 2 ** attempt + Math.random() * 250, signal);
    }
  }
}
