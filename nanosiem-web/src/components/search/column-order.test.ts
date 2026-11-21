// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { completeColumnOrder } from './column-order';

describe('completeColumnOrder (NAN-5702)', () => {
  it('keeps a join column the stats column_order does not name', () => {
    const rows = [
      { 'device.hostname': 'ws-1', launches: 4, logons: 9 },
      { 'device.hostname': 'ws-2', launches: 2, logons: 1 },
    ];
    expect(completeColumnOrder(['device.hostname', 'launches'], rows)).toEqual([
      'device.hostname',
      'launches',
      'logons',
    ]);
  });

  it('shows a renamed aggregate under its new name', () => {
    expect(completeColumnOrder(['user', 'count'], [{ user: 'bob', n: 3 }])).toEqual(['user', 'n']);
  });

  it('adds columns first seen on later rows', () => {
    expect(completeColumnOrder(['a'], [{ a: 1 }, { a: 2, b: 3 }])).toEqual(['a', 'b']);
  });

  it('falls back to the rows when no order is given', () => {
    expect(completeColumnOrder(undefined, [{ b: 1, a: 2 }])).toEqual(['b', 'a']);
  });

  it('never repeats a column', () => {
    expect(completeColumnOrder(['a', 'a', 'b'], [{ a: 1, b: 2 }])).toEqual(['a', 'b']);
  });
});
