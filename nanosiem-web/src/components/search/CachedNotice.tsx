// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Cache-transparency badge (NAN-1595).
 *
 * Rendered in a view's header whenever its data was served from the server
 * cache. Intent is awareness, not alarm — analysts (and anyone opening a shared
 * link) should know the result is cached and be able to force a live refresh.
 * Driven by the `x-nano-cache` / `x-nano-cache-age` response headers surfaced
 * through the api client, so it shows on a cold-client-cache shared-link follow.
 */

import type { CacheMeta } from '@/lib/api';

/** Compact age: "12s", "4m", "1h" — matches the dense mono meta style. */
function formatAge(ageSecs: number | null): string {
  if (ageSecs == null || ageSecs < 0) return 'just now';
  if (ageSecs < 60) return `${ageSecs}s`;
  if (ageSecs < 3600) return `${Math.floor(ageSecs / 60)}m`;
  return `${Math.floor(ageSecs / 3600)}h`;
}

export interface CachedNoticeProps {
  /** Server cache status for the currently-displayed data. */
  meta: CacheMeta | null | undefined;
  /** Force a live re-fetch (bypasses the server cache). */
  onRefresh: () => void;
  /** Disable the control while a refresh is in flight. */
  refreshing?: boolean;
  className?: string;
}

/** Renders nothing on a cache miss; a "cached Ns ago · refresh" button on a hit. */
export function CachedNotice({ meta, onRefresh, refreshing, className }: CachedNoticeProps) {
  if (!meta?.hit) return null;
  return (
    <button
      type="button"
      onClick={onRefresh}
      disabled={refreshing}
      title="Served from cache — click to refresh from server"
      className={`text-amber-500 dark:text-amber-400 text-xs hover:underline cursor-pointer disabled:opacity-60 disabled:cursor-default whitespace-nowrap ${className ?? ''}`}
    >
      cached {formatAge(meta.ageSecs)} ago · {refreshing ? 'refreshing…' : 'refresh'}
    </button>
  );
}
