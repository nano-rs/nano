// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it, vi } from 'vitest';
import {
  captureInitialSearchPage,
  mergeAsyncSearchPage,
  reserveAsyncSearchOffset,
  type AsyncSearchPage,
  type AsyncSearchPageState,
} from './async-search-paging';

const firstPage: AsyncSearchPage = { append: false, offset: 0, page: 1, pageSize: 50 };
const secondPage: AsyncSearchPage = { append: true, offset: 50, page: 2, pageSize: 50 };
const rows = (offset: number, count: number) => Array.from({ length: count }, (_, i) => ({
  id: `result-${offset + i}`,
  fields: {} as Record<string, unknown>,
}));
const empty: AsyncSearchPageState<ReturnType<typeof rows>[number]> = {
  results: [], totalCount: 0, currentPage: 1, complete: false,
};
const initial = () => mergeAsyncSearchPage(empty, rows(0, 50), 10_016_195, firstPage);

describe('durable async search paging', () => {
  it('appends page 2, advances the page, and preserves the exact page-1 count', () => {
    const previous = initial();
    const next = mergeAsyncSearchPage(previous, rows(50, 50), 101, secondPage);
    expect(next.results).toEqual(rows(0, 100));
    expect(next.totalCount).toBe(10_016_195);
    expect(next.currentPage).toBe(2);
    expect(next.complete).toBe(false);
    expect(previous.results).toHaveLength(50);
  });

  it.each([0, 17])('ends paging after a short appended page (%i rows), despite the exact count', count => {
    const next = mergeAsyncSearchPage(initial(), rows(50, count), 50 + count, secondPage);
    expect(next.results).toHaveLength(50 + count);
    expect(next.totalCount).toBe(10_016_195);
    expect(next.complete).toBe(true);
  });

  it('ends paging when an entire page repeats existing result IDs', () => {
    const next = mergeAsyncSearchPage(initial(), rows(0, 50), 101, secondPage);
    expect(next.results).toHaveLength(50);
    expect(next.complete).toBe(true);
  });

  it('deduplicates nested and dotted metadata.uid even when offset IDs differ', () => {
    const previous = mergeAsyncSearchPage(empty, [{ id: 'result-0', fields: { metadata: { uid: 'event-a' } } }], 100, firstPage);
    const next = mergeAsyncSearchPage(previous, [
      { id: 'result-50', fields: { 'metadata.uid': 'event-a' } },
      { id: 'result-51', fields: { metadata: { uid: 'event-b' } } },
      { id: 'result-52', fields: { 'metadata.uid': 'event-b' } },
    ], 54, { ...secondPage, pageSize: 3 });
    expect(next.results.map(row => row.id)).toEqual(['result-0', 'result-51']);
    expect(next.complete).toBe(false);
    const repeated = mergeAsyncSearchPage(next, [
      { id: 'result-100', fields: { metadata: { uid: 'event-a' } } },
    ], 102, { ...secondPage, pageSize: 1 });
    expect(repeated.complete).toBe(true);
  });

  it('reserves offsets synchronously and blocks consecutive duplicates and completed paging', () => {
    const lastOffset = { current: null as number | null };
    expect(reserveAsyncSearchOffset(lastOffset, firstPage, false)).toBe(true);
    expect(reserveAsyncSearchOffset(lastOffset, secondPage, false)).toBe(true);
    expect(reserveAsyncSearchOffset(lastOffset, secondPage, false)).toBe(false);
    expect(reserveAsyncSearchOffset(lastOffset, { ...secondPage, offset: 100, page: 3 }, false)).toBe(true);
    expect(reserveAsyncSearchOffset(lastOffset, { ...secondPage, offset: 150, page: 4 }, true)).toBe(false);
    expect(reserveAsyncSearchOffset(lastOffset, firstPage, true)).toBe(true);
    expect(mergeAsyncSearchPage({ ...initial(), complete: true }, rows(0, 50), 200, firstPage).complete).toBe(false);
  });

  it('records one notebook entry for the initial search and none for appended pages', () => {
    const captureSearch = vi.fn();
    captureInitialSearchPage(firstPage, captureSearch);
    captureInitialSearchPage(secondPage, captureSearch);
    captureInitialSearchPage({ ...secondPage, offset: 100, page: 3 }, captureSearch);
    expect(captureSearch).toHaveBeenCalledTimes(1);
  });

  it('retains notebook capture for legacy callers without a paging context', () => {
    const captureSearch = vi.fn();
    captureInitialSearchPage(undefined, captureSearch);
    expect(captureSearch).toHaveBeenCalledOnce();
  });
});
