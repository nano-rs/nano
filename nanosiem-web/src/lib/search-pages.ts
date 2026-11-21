// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5703: infinite-scroll page bookkeeping for the Search results list.
 *
 * A scroll handler fires many times before React re-renders, so a guard read
 * from component state (`isSearching`, `currentPage`) is stale for the second
 * and later calls: each one requested the SAME next page and appended it
 * again (1,100 rows for 1,085 events, some events never shown). The loader
 * keeps the state synchronously: one page in flight at a time, the page
 * number derived from the last page actually appended, and a page is
 * appended at most once.
 */
export interface PageTicket {
  readonly page: number;
}

export interface PageLoader {
  /** Forget everything (a new search started); late pages of the old run are dropped. */
  reset(): void;
  /** Claim the next page to fetch, or null while another page is in flight. */
  claimNext(): PageTicket | null;
  /**
   * Whether the rows of `page` may be appended now: true once, for the page
   * currently in flight. A duplicate or stale page returns false and its rows
   * must be dropped.
   */
  accept(page: number): boolean;
  /** The fetch for `ticket` finished (appended, dropped or failed). */
  release(ticket: PageTicket): void;
  /** Last page whose rows were appended (1 = the first page). */
  lastLoaded(): number;
}

export function createPageLoader(): PageLoader {
  let loaded = 1;
  let inFlight: PageTicket | null = null;
  let accepted = false;
  return {
    reset() {
      loaded = 1;
      inFlight = null;
      accepted = false;
    },
    claimNext() {
      if (inFlight) return null;
      inFlight = { page: loaded + 1 };
      accepted = false;
      return inFlight;
    },
    accept(page) {
      if (!inFlight || inFlight.page !== page || accepted) return false;
      accepted = true;
      loaded = page;
      return true;
    },
    release(ticket) {
      if (inFlight === ticket) {
        inFlight = null;
        accepted = false;
      }
    },
    lastLoaded() {
      return loaded;
    },
  };
}

/** The Search page's per-result-set refs (React `useRef` objects). */
export interface ResultSetRefs {
  pageLoader: { current: PageLoader };
  jobContinuation: { current: unknown };
  abortController: { current: AbortController | null };
}

/**
 * NAN-5703 review: forget the paging state of the result set on screen. Every
 * path that replaces it with another search's first page (a run, a
 * drilldown, a background job's result, a back/forward restore) must call
 * this, or the next scroll numbers its page from the OLD set (skipping
 * pages) or pages the OLD background job (mixing two searches' rows).
 */
export function resetPaging(refs: ResultSetRefs): void {
  refs.pageLoader.current.reset();
  refs.jobContinuation.current = null;
}

/**
 * Start a new result set: reset paging, abort whatever request the old set
 * still has in flight, and install (and return) this set's own controller.
 * Check the RETURNED controller after each await, never the shared ref.
 */
export function beginResultSet(refs: ResultSetRefs): AbortController {
  resetPaging(refs);
  refs.abortController.current?.abort();
  const controller = new AbortController();
  refs.abortController.current = controller;
  return controller;
}
