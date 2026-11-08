// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { resolveRawView } from './event-raw-text';

describe('resolveRawView', () => {
  const apacheLine = '203.0.113.7 - - [07/Oct/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 0';

  it('prefers OCSF raw_data over a summary message', () => {
    expect(resolveRawView({ message: 'GET /index.html', raw_data: apacheLine }))
      .toEqual({ text: apacheLine, synthetic: false });
  });

  it('falls back to the UDM message, then _raw', () => {
    expect(resolveRawView({ raw_data: '', message: 'Failed password for root' }))
      .toEqual({ text: 'Failed password for root', synthetic: false });
    expect(resolveRawView({ raw_data: null, message: '  ', _raw: 'legacy line' }))
      .toEqual({ text: 'legacy line', synthetic: false });
  });

  it('builds a synthetic record for structured telemetry without raw text', () => {
    const view = resolveRawView({
      id: 'span-1',
      timestamp: '2026-10-07T12:00:00Z',
      _source_table: 'otel_spans',
      message: null,
      span_name: 'GET /api',
      duration_ms: 0,
      empty: '',
    });
    expect(view?.synthetic).toBe(true);
    expect(JSON.parse(view!.text)).toEqual({ span_name: 'GET /api', duration_ms: 0 });
  });

  it('returns null when no displayable field exists', () => {
    expect(resolveRawView(undefined)).toBeNull();
    expect(resolveRawView({ id: 'x', timestamp: 't', message: null })).toBeNull();
  });
});
