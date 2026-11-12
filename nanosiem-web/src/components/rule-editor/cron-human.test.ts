// NAN-5316: the scheduler stores 6-field crons (`sec min hour dom mon dow`);
// `*/30 * * * * *` (every 30 s) was rendered as "every 30m".
import { describe, expect, it } from 'vitest';
import { cronHuman } from './helpers';

describe('cronHuman', () => {
  it('reads the leading seconds field of a 6-field cron', () => {
    expect(cronHuman('*/30 * * * * *')).toBe('every 30s');
    expect(cronHuman('* * * * * *')).toBe('every second');
  });

  it('treats a fixed-seconds 6-field cron like its 5-field form', () => {
    expect(cronHuman('15 */5 * * * *')).toBe('every 5m');
    expect(cronHuman('0 */5 * * * *')).toBe('every 5m');
    expect(cronHuman('0 * * * * *')).toBe('every minute');
    expect(cronHuman('0 */5 * * * * *')).toBe('every 5m');
  });

  it('keeps the 5-field forms', () => {
    expect(cronHuman('*/5 * * * *')).toBe('every 5m');
    expect(cronHuman('* * * * *')).toBe('every minute');
    expect(cronHuman('7 * * * *')).toBe('hourly at :07');
    expect(cronHuman('0 */2 * * *')).toBe('every 2h');
  });

  it('falls back to the raw expression for anything else', () => {
    expect(cronHuman('0 9 * * 1')).toBe('0 9 * * 1');
    expect(cronHuman('0 30 9 * * 1')).toBe('0 30 9 * * 1');
    expect(cronHuman(undefined)).toBe('—');
  });
});
