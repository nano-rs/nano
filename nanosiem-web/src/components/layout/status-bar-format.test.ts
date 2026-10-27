import { describe, expect, it } from 'vitest';
import {
  EM_DASH,
  formatEventsPerMin,
  formatIngestScore,
  formatPlatformStatus,
} from './status-bar-format';

describe('status bar formatters', () => {
  describe('missing data', () => {
    it('omits the ingest segment and dashes the platform status', () => {
      expect(formatIngestScore(undefined)).toBeNull();
      expect(formatIngestScore(null)).toBeNull();
      expect(formatPlatformStatus(undefined)).toBe(EM_DASH);
      expect(formatPlatformStatus(null)).toBe(EM_DASH);
      expect(formatEventsPerMin(undefined)).toBeNull();
      expect(formatEventsPerMin([])).toBeNull();
    });
  });

  describe('partial data', () => {
    it('never renders NaN for a missing or non-finite ingestion score', () => {
      for (const ingestion_score of [undefined, null, NaN, Infinity, -Infinity, '87', {}]) {
        const out = formatIngestScore({ ingestion_score });
        expect(out).toBeNull();
      }
    });

    it('dashes a missing, blank or unknown overall status', () => {
      expect(formatPlatformStatus({})).toBe(EM_DASH);
      expect(formatPlatformStatus({ overall_status: '' })).toBe(EM_DASH);
      expect(formatPlatformStatus({ overall_status: '  ' })).toBe(EM_DASH);
      expect(formatPlatformStatus({ overall_status: 'unknown' })).toBe(EM_DASH);
      expect(formatPlatformStatus({ overall_status: 42 })).toBe(EM_DASH);
    });

    it('skips non-finite history counts and omits when none are usable', () => {
      expect(formatEventsPerMin([{ count: undefined }, { count: NaN }])).toBeNull();
      expect(formatEventsPerMin([{ count: 600 }, { count: NaN }, {}])).toBe('10 events/min');
    });
  });

  describe('valid data', () => {
    it('formats each segment', () => {
      expect(formatIngestScore({ ingestion_score: 86.6 })).toBe('87% ingest');
      expect(formatIngestScore({ ingestion_score: 0 })).toBe('0% ingest');
      expect(formatPlatformStatus({ overall_status: 'healthy' })).toBe('healthy');
      expect(formatEventsPerMin([{ count: 60_000 }, { count: 60_000 }])).toBe(
        `${(2000).toLocaleString()} events/min`,
      );
    });

    it('never emits NaN text in any combination', () => {
      const outputs = [
        formatIngestScore({ ingestion_score: NaN }),
        formatPlatformStatus({ overall_status: undefined }),
        formatEventsPerMin([{ count: NaN }]),
      ];
      for (const out of outputs) expect(String(out)).not.toMatch(/NaN/);
    });
  });
});
