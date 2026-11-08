// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { searchDisplayTimeMs, searchTimingBreakdown } from './search-timing';

describe('search timing', () => {
  it('uses total server wall time as the primary analyst-visible duration', () => {
    expect(searchDisplayTimeMs({ execution_time_ms: 1_920, server_wall_ms: 23_300 })).toBe(23_300);
  });

  it('keeps server, query, and fair-queue time separate', () => {
    expect(searchTimingBreakdown({
      execution_time_ms: 1_920,
      server_wall_ms: 23_300,
      queue_wait_ms: 18_000,
    })).toEqual({
      displayTimeMs: 23_300,
      serverWallMs: 23_300,
      queryExecutionMs: 1_920,
      queueWaitMs: 18_000,
    });
  });

  it('falls back to query execution time for older servers', () => {
    expect(searchTimingBreakdown({ execution_time_ms: 1_920 })).toEqual({
      displayTimeMs: 1_920,
      serverWallMs: null,
      queryExecutionMs: 1_920,
      queueWaitMs: null,
    });
  });
});
