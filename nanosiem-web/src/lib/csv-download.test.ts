// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { csvExportFilename, csvFromRows } from './csv-download';

describe('csv-download (NAN-5699)', () => {
  it('builds a header row and spreadsheet-safe, RFC 4180-quoted cells', () => {
    expect(csvFromRows(['user', 'count'], [['=cmd|calc', 3], ['a,b', -5], [null, 0]])).toBe(
      "user,count\n'=cmd|calc,3\n\"a,b\",-5\n,0",
    );
  });

  it('names files like the events export, with an optional view', () => {
    const now = new Date('2026-11-19T12:30:05.123Z');
    expect(csvExportFilename(undefined, now)).toBe('nano-export-2026-11-19T12-30-05.csv');
    expect(csvExportFilename('timechart', now)).toBe('nano-export-timechart-2026-11-19T12-30-05.csv');
  });
});
