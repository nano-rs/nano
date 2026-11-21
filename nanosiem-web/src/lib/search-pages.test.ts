// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { beginResultSet, createPageLoader, resetPaging } from './search-pages';

describe('createPageLoader (NAN-5703)', () => {
  it('admits one page at a time when the scroll handler fires repeatedly', () => {
    const loader = createPageLoader();
    const first = loader.claimNext();
    expect(first?.page).toBe(2);
    // The scroll handler fires again before React re-renders.
    expect(loader.claimNext()).toBeNull();
    expect(loader.claimNext()).toBeNull();
    expect(loader.accept(2)).toBe(true);
    loader.release(first!);
    expect(loader.claimNext()?.page).toBe(3);
  });

  it('appends a page at most once', () => {
    const loader = createPageLoader();
    const ticket = loader.claimNext()!;
    expect(loader.accept(ticket.page)).toBe(true);
    expect(loader.accept(ticket.page)).toBe(false);
    loader.release(ticket);
    expect(loader.accept(ticket.page)).toBe(false);
  });

  it('numbers pages from the last page appended, not a failed fetch', () => {
    const loader = createPageLoader();
    const failed = loader.claimNext()!;
    loader.release(failed); // the request errored: nothing appended
    expect(loader.lastLoaded()).toBe(1);
    expect(loader.claimNext()?.page).toBe(2);
  });

  it('drops a page of a superseded search', () => {
    const loader = createPageLoader();
    const stale = loader.claimNext()!;
    loader.reset(); // a new search started
    expect(loader.accept(stale.page)).toBe(false);
    loader.release(stale); // late release of the old ticket must not free a new one
    const fresh = loader.claimNext()!;
    loader.release(stale);
    expect(loader.claimNext()).toBeNull();
    expect(loader.accept(fresh.page)).toBe(true);
  });

  it('loads 1,085 events as 22 disjoint pages under rapid scrolling', () => {
    const total = 1085;
    const pageSize = 50;
    const loader = createPageLoader();
    const rows: number[] = Array.from({ length: pageSize }, (_, i) => i);
    let guard = 0;
    while (rows.length < total && guard++ < 1000) {
      // Three scroll events per frame, each trying to load more.
      const tickets = [loader.claimNext(), loader.claimNext(), loader.claimNext()].filter(Boolean);
      for (const ticket of tickets) {
        const offset = (ticket!.page - 1) * pageSize;
        if (loader.accept(ticket!.page)) {
          for (let i = offset; i < Math.min(offset + pageSize, total); i++) rows.push(i);
        }
        loader.release(ticket!);
      }
    }
    expect(rows.length).toBe(total);
    expect(new Set(rows).size).toBe(total);
  });
});

describe('beginResultSet / resetPaging (NAN-5703 review)', () => {
  const refs = () => {
    const loader = createPageLoader();
    return {
      pageLoader: { current: loader },
      jobContinuation: { current: { jobId: 'sjob_old', rowCount: 900 } as unknown },
      abortController: { current: new AbortController() as AbortController | null },
    };
  };

  it('a new result set pages from page 2 again and forgets the old job', () => {
    const r = refs();
    // The old search scrolled to page 5.
    for (let page = 2; page <= 5; page++) {
      const t = r.pageLoader.current.claimNext()!;
      r.pageLoader.current.accept(t.page);
      r.pageLoader.current.release(t);
    }
    expect(r.pageLoader.current.claimNext()?.page).toBe(6);
    const old = r.abortController.current!;
    const controller = beginResultSet(r);
    expect(old.signal.aborted).toBe(true);
    expect(r.abortController.current).toBe(controller);
    expect(controller.signal.aborted).toBe(false);
    expect(r.jobContinuation.current).toBeNull();
    expect(r.pageLoader.current.claimNext()?.page).toBe(2);
  });

  it('resetPaging leaves the in-flight request alone', () => {
    const r = refs();
    const live = r.abortController.current!;
    resetPaging(r);
    expect(live.signal.aborted).toBe(false);
    expect(r.jobContinuation.current).toBeNull();
    expect(r.pageLoader.current.lastLoaded()).toBe(1);
  });
});
