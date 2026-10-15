// SPDX-License-Identifier: AGPL-3.0-or-later

import { abortableDelay } from '@/lib/abortable-delay';
import type { ProductViewProgress } from '@/lib/api/types';

/** Longest a panel keeps polling one progressive view. */
const MAX_POLL_MS = 5 * 60 * 1000;
const DEFAULT_RETRY_MS = 1500;

/**
 * NAN-3094: fetch a lean product view that may answer before it is final.
 *
 * The server builds the Asset page's dossier / artifacts / summary from one
 * shared snapshot and answers each request within a few seconds with what it
 * covers so far plus `progress`. This renders every partial answer through
 * `onUpdate` and asks again (never with the cache bypass: that would restart
 * a finished snapshot) until `progress.complete`, the view goes stale
 * (`isCurrent()` false), or `MAX_POLL_MS` passes. Resolves with the last
 * response. The first request carries `firstBypass`.
 */
export async function fetchProgressive<T extends { progress?: ProductViewProgress | null }>(
  fetchOnce: (bypass: boolean) => Promise<T>,
  onUpdate: (response: T) => void,
  isCurrent: () => boolean,
  firstBypass = false,
  signal?: AbortSignal,
): Promise<T> {
  const started = Date.now();
  signal?.throwIfAborted();
  let response = await fetchOnce(firstBypass);
  for (;;) {
    signal?.throwIfAborted();
    if (!isCurrent()) return response;
    onUpdate(response);
    const progress = response.progress;
    if (!progress || progress.complete || Date.now() - started > MAX_POLL_MS) return response;
    await abortableDelay(progress.retry_after_ms ?? DEFAULT_RETRY_MS, signal);
    signal?.throwIfAborted();
    if (!isCurrent()) return response;
    response = await fetchOnce(false);
  }
}

/**
 * Short label for an incomplete view (NAN-3252). Partial data is painted, so
 * this is a subtle "refining" marker, not a loading state:
 * - no coverage yet → "reading events…"
 * - the whole window is covered (`windowStart` given and reached) → "refining…"
 * - otherwise → "refining · covers since 12:04:31Z"
 * A complete view shows its note (why it covers less), if any.
 */
export function progressLabel(
  progress: ProductViewProgress | null | undefined,
  windowStart?: string | null,
): string | null {
  if (!progress) return null;
  if (progress.complete) return progress.note ? humanizeNote(progress.note) : null;
  if (!progress.covered_start) return 'reading events…';
  const covered = Date.parse(progress.covered_start);
  const start = windowStart ? Date.parse(windowStart) : NaN;
  if (Number.isFinite(covered) && Number.isFinite(start) && covered <= start) return 'refining…';
  const since = Number.isFinite(covered) ? new Date(covered).toISOString().slice(11, 19) : null;
  return since ? `refining · covers since ${since}Z` : 'refining…';
}

const NOTE_TIMESTAMP = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})/g;

/**
 * NAN-3291: server notes name times as RFC 3339 UTC
 * ("since 2026-10-08T10:50:00Z"); show them as the analyst's local
 * wall-clock time ("since 06:50").
 */
export function humanizeNote(note: string): string {
  return note.replace(NOTE_TIMESTAMP, (stamp) => {
    const time = new Date(stamp);
    if (Number.isNaN(time.getTime())) return stamp;
    return time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
  });
}

/**
 * What the Rarity panel is waiting on while its view is incomplete
 * (NAN-3252), so it never sits on a bare spinner: the events are still being
 * read, or they are read and the host counts are being refined.
 */
export function rarityWaitLabel(progress: ProductViewProgress | null | undefined): string | null {
  if (!progress || progress.complete) return null;
  return progress.covered_start ? 'refining host counts…' : 'reading events…';
}
