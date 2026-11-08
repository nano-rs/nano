// SPDX-License-Identifier: AGPL-3.0-or-later

export interface SearchTimingBreakdown {
  /** The primary duration shown for compatibility with older responses. */
  displayTimeMs: number | null;
  /** Total server-side wall time for this request. */
  serverWallMs: number | null;
  /** Rows-query execution time. */
  queryExecutionMs: number | null;
  /** Fair admission queue wait. */
  queueWaitMs: number | null;
}

/** Total analyst-visible search time, falling back for older servers. */
export function searchDisplayTimeMs(response: {
  execution_time_ms?: number;
  server_wall_ms?: number;
}): number | undefined {
  return response.server_wall_ms ?? response.execution_time_ms;
}

/** Keep wall, execution, and fair-queue time distinct in the status bar. */
export function searchTimingBreakdown(response: {
  execution_time_ms?: number;
  server_wall_ms?: number;
  queue_wait_ms?: number;
}): SearchTimingBreakdown {
  return {
    displayTimeMs: searchDisplayTimeMs(response) ?? null,
    serverWallMs: response.server_wall_ms ?? null,
    queryExecutionMs: response.execution_time_ms ?? null,
    queueWaitMs: response.queue_wait_ms ?? null,
  };
}
