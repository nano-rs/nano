// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { searchDisplayTimeMs } from './search-timing';

describe('searchDisplayTimeMs (NAN-3008)', () => {
  it('shows the server wall time, not the rows-query time', () => {
    expect(searchDisplayTimeMs({ execution_time_ms: 1920, server_wall_ms: 23300 })).toBe(23300);
  });
  it('falls back to execution_time_ms on older servers', () => {
    expect(searchDisplayTimeMs({ execution_time_ms: 1920 })).toBe(1920);
  });
  it('is undefined when neither is present', () => {
    expect(searchDisplayTimeMs({})).toBeUndefined();
  });
});
