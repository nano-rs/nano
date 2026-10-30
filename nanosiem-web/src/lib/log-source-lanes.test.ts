// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { logSourceSlugLabel, platformLaneRows, receivingWithoutParser } from './log-source-lanes';
import { failureErrorCode, failureOrigin, parserRollErrorMessage } from './parser-rollout';

describe('log source lanes (NAN-3248)', () => {
  it('uses separately loaded detail health for raw arrivals, then clears the badge when a parser deploys', () => {
    const source = { deployed: false, ingest: null };
    expect(receivingWithoutParser(source, { events_last_24h: 12 })).toBe(true);
    expect(receivingWithoutParser(source, { events_last_hour: 1 })).toBe(true);
    expect(receivingWithoutParser(source, { events_last_24h: 0 })).toBe(false);
    expect(receivingWithoutParser(source)).toBe(false);
    expect(receivingWithoutParser({ ...source, deployed: true }, { events_last_24h: 12 })).toBe(false);
  });
  it('labels lean sources by their lake slugs and falls back to source_type', () => {
    expect(logSourceSlugLabel({ source_type: 'routed', ingest: { source_slugs: ['apache_access'] } as never })).toBe('apache_access');
    expect(logSourceSlugLabel({ source_type: 'routed', ingest: { source_slugs: ['a', 'b'] } as never })).toBe('a, b');
    expect(logSourceSlugLabel({ source_type: 'kafka', ingest: null })).toBe('kafka');
    expect(logSourceSlugLabel({ source_type: 'routed', ingest: { source_slugs: [] } as never })).toBe('routed');
  });

  it('builds platform lane rows only for unclaimed platform slugs with data', () => {
    const now = Date.parse('2026-10-07T23:30:00Z');
    const history = [
      { source_type: 'otlp_log', timestamp: '2026-10-07T22:00:00Z', count: 100 },
      { source_type: 'otlp_log', timestamp: '2026-10-07T23:00:00Z', count: 11 },
      { source_type: 'audit', timestamp: '2026-10-07T23:00:00Z', count: 0 },
      { source_type: 'findings', timestamp: '2026-10-07T23:00:00Z', count: 5 },
      { source_type: 'apache_access', timestamp: '2026-10-07T23:00:00Z', count: 5 },
    ];
    const rows = platformLaneRows(history, [], now);
    expect(rows.map((r) => r.slug)).toEqual(['otlp_log']);
    expect(rows[0].ingest).toMatchObject({ events_last_24h: 111, events_last_hour: 11, health_status: 'healthy', last_event_at: '2026-10-07T23:00:00.000Z' });
    expect(platformLaneRows(history, [{ ingest: { source_slugs: ['otlp_log'] } as never }], now)).toEqual([]);
    expect(platformLaneRows(undefined, [], now)).toEqual([]);
  });

  it('classifies failure stages and names parser-roll error codes', () => {
    expect(failureOrigin('vector_validate')).toBe('validation');
    expect(failureOrigin('roll')).toBe('platform');
    expect(failureOrigin(null)).toBe('unknown');
    expect(failureErrorCode({ failure_component: 'parser_roll_conflict', failure_reason: 'parser_roll_conflict' })).toBe('parser_roll_conflict');
    expect(failureErrorCode({ failure_component: 'transforms.tenant__x', failure_reason: 'error[E103]: x' })).toBeNull();
    expect(parserRollErrorMessage('parser_roll_conflict')).toMatch(/not the problem/);
    expect(parserRollErrorMessage('nope')).toBeNull();
  });
});
