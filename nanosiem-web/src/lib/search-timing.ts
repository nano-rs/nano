// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3008: the time a search took, as the analyst experienced it.
 *
 * `server_wall_ms` is the server's total wall time for the request (admission,
 * lake readiness waits and retries, a cold query-process start, companions and
 * the rows query). `execution_time_ms` covers the rows query only and hid a
 * 23 s cold search behind "1.92 s". Older servers omit `server_wall_ms`.
 */
export function searchDisplayTimeMs(response: {
  execution_time_ms?: number;
  server_wall_ms?: number;
}): number | undefined {
  return response.server_wall_ms ?? response.execution_time_ms;
}
