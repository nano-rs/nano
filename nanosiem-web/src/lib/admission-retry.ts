// SPDX-License-Identifier: AGPL-3.0-or-later

import { abortableDelay } from './abortable-delay';
import { ApiClientError } from '@/lib/api';

/**
 * Was this failure a search admission refusal (429 / ADMISSION_DENIED)?
 * NAN-4664: the search service queues overflow fairly and refuses only when
 * the request's wait budget ends or the queue is full, with Retry-After: 2.
 */
export function isAdmissionDenied(err: unknown): boolean {
  return err instanceof ApiClientError && (err.status === 429 || err.code === 'ADMISSION_DENIED');
}

/**
 * NAN-3077: a product view route refused for momentary memory pressure
 * (503 VIEW_MEMORY_BUSY, Retry-After: 2) is transient like an admission
 * refusal; 413 VIEW_TOO_LARGE is not and is never retried.
 */
export function isViewMemoryBusy(err: unknown): boolean {
  return err instanceof ApiClientError && err.code === 'VIEW_MEMORY_BUSY';
}

/**
 * Retry a search-service call that was refused by admission control
 * (429 / ADMISSION_DENIED) with a short backoff; anything else (real errors)
 * is NOT retried. Used by the views that stack concurrent /api/search-family
 * calls (the `| cloud` view's facet clicks, infinite scroll and pivot
 * sheets), which previously degraded silently to "no data".
 */
export async function retryOnAdmissionDenied<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    signal?.throwIfAborted();
    try {
      return await fn();
    } catch (err) {
      if (!(isAdmissionDenied(err) || isViewMemoryBusy(err)) || attempt >= 3) throw err;
      await abortableDelay(350 * 2 ** attempt + Math.random() * 250, signal);
    }
  }
}
