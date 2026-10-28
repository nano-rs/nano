// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef } from 'react';

/** Minimum spacing between refetches; later events schedule a trailing refresh. */
export const REFETCH_ON_FOCUS_MIN_INTERVAL_MS = 2_000;

/**
 * NAN-4779: refetch when the tab regains focus or becomes visible again.
 *
 * The use-api `useQuery` fetches on mount only. A page that tracks state the
 * user changes elsewhere — the Getting Started checklist, completed in another
 * tab or window — otherwise shows the answer from when it mounted until a
 * full reload.
 */
export function useRefetchOnFocus(refetch: () => void, enabled = true): void {
  const latest = useRef(refetch);
  latest.current = refetch;

  useEffect(() => {
    if (!enabled || typeof window === 'undefined') return;
    let last = 0;
    let pending: ReturnType<typeof setTimeout> | undefined;
    const refresh = () => {
      pending = undefined;
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;
      last = Date.now();
      latest.current();
    };
    const run = () => {
      if (document.visibilityState === 'hidden') return;
      if (pending !== undefined) clearTimeout(pending);
      const remaining = REFETCH_ON_FOCUS_MIN_INTERVAL_MS - (Date.now() - last);
      // Keep a trailing refresh: the user may have completed a step between
      // two focus events inside the cooldown. Dropping that event leaves the
      // checklist stale until another focus or reload.
      if (remaining > 0) pending = setTimeout(refresh, remaining);
      else refresh();
    };
    window.addEventListener('focus', run);
    document.addEventListener('visibilitychange', run);
    return () => {
      if (pending !== undefined) clearTimeout(pending);
      window.removeEventListener('focus', run);
      document.removeEventListener('visibilitychange', run);
    };
  }, [enabled]);
}
