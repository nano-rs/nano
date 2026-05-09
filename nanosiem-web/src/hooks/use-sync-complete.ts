// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef } from 'react';

/**
 * Repo-sync edge-detect hook. Fires `onComplete(repo)` exactly once when the
 * active repository's `last_sync_status` transitions out of `'syncing'` (to
 * `'success'`, `'failed'`, or anything else).
 *
 * Repo management pages poll the repo list every ~1.5s while a sync is
 * running, so the panel knows when the backend marks it done — but the panel's
 * *content* (rules / parsers / playbooks) lives in a separate query that
 * doesn't auto-refetch on poll. Without this edge trigger users have to
 * manually reload to see fresh content. With it, each page's own `onComplete`
 * refetches its content + shows a toast.
 *
 * @param repos       — the polled repo list
 * @param activeId    — currently selected repo
 * @param onComplete  — callback invoked with the now-completed repo. Stable
 *                      ref not required — the hook captures the latest via
 *                      ref so callers can pass an inline arrow.
 */
export function useSyncCompleteEffect<
  R extends { id: string; last_sync_status?: string | null },
>(repos: readonly R[], activeId: string | null, onComplete: (repo: R) => void) {
  // Track `(id, status)` together so switching `activeId` mid-sync doesn't
  // carry the prior repo's `'syncing'` state into the new repo's first tick
  // and fire a false "complete" callback. We only fire when the same repo
  // transitions out of syncing.
  const prevRef = useRef<{ id: string | null; status: string | null }>({
    id: null,
    status: null,
  });
  const callbackRef = useRef(onComplete);
  callbackRef.current = onComplete;

  useEffect(() => {
    const active = repos.find((r) => r.id === activeId);
    const curr = active?.last_sync_status ?? null;
    const prev = prevRef.current;
    prevRef.current = { id: activeId, status: curr };
    if (
      active &&
      prev.id === activeId &&
      prev.status === 'syncing' &&
      curr &&
      curr !== 'syncing'
    ) {
      callbackRef.current(active);
    }
  }, [repos, activeId]);
}
