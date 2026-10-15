// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Live tail as a *prepend*, not a re-run (NAN-2551).
 *
 * The old tail called `handleSearch(1, false, …)` on every tick, which ran the
 * whole new-search reset over a result set the analyst had already scrolled:
 * the infinite-scroll pages were discarded, the NAN-2514 artifact was
 * abandoned and re-materialised, and each tick pushed a browser-history entry,
 * a recent-search entry, and wiped the AI refinement conversation.
 *
 * A tail tick means "show me what arrived since I last looked". This module is
 * the pure half of that: it decides the window to ask for, which returned rows
 * are genuinely new, where they go, and how many to keep (a rolling window, NAN-3254). The Search page
 * keeps the tail rows in their own list in front of `searchResults`, so no
 * pagination arithmetic, artifact offset or count reconciliation sees them.
 *
 * ## Gaps and duplicates
 *
 * The shared cell follow stream deduplicates by logical event identity as
 * part-log heads advance. This client-side window applies to the polling
 * fallback. `/api/search` has no event cursor. `cursor_time` / `cursor_event_uid` exist
 * only inside the lake worker's `BroadNplRequest` (`nanosiem-lake-worker`) and
 * the lake view pager; `SearchRequest` (`nanosiem-core/src/search/types.rs`,
 * `nanosiem-web/src/lib/api/types.ts`) exposes nothing equivalent. So the tail
 * is a *time window plus a client-side dedupe*, which is what gives it both
 * properties at once:
 *
 * - **No gaps**: each tick re-asks for `[watermark - lookback, now]`, not
 *   `(watermark, now]`. The lookback (≥ `TAIL_LOOKBACK_MS`, and never less
 *   than two tick intervals) has to cover the lake's arrival→searchable lag,
 *   which is budgeted at ≤ 2 min. An event that was not yet visible when its
 *   own timestamp passed the watermark is still inside the re-asked window on
 *   a later tick. Out-of-order arrival within that lag is covered by the same
 *   overlap.
 * - **No duplicates**: the overlap is deliberate, so every tick re-returns
 *   rows already on screen. `selectTailRows` filters them against the keys of
 *   everything displayed, keyed on the event's own `metadata.uid` via the
 *   shared `rowKey` (positional `result-N` ids cannot be compared across
 *   requests).
 * - **No runaway watermark**: the watermark only ever advances to the newest
 *   event time actually seen, clamped to wall-clock now. A single event with a
 *   skewed future timestamp would otherwise move the window past everything
 *   real and open a permanent hole.
 */

import { rowKey, type ResultRow } from './async-search-paging';

/**
 * Minimum overlap re-asked on every tick. Sized against the lake's
 * arrival→searchable budget (≤ 2 min); below it, slow shards drop rows.
 */
export const TAIL_LOOKBACK_MS = 120_000;

/** Rows requested per tick. One page of arrivals is plenty at any sane rate. */
export const TAIL_FETCH_LIMIT = 500;

/**
 * Rolling window on tail-held rows, like `tail -f` (NAN-3254).
 *
 * The tail never stops on volume. Past the cap the oldest arrivals are
 * dropped and the newest are kept. The cap applies to the displayed `rows`
 * and, separately, to the `buffered` arrivals held back while the analyst is
 * scrolled away. Trimming displayed rows under a scrolled-away reader would
 * shift the list beneath them, so `rows` is trimmed only while the reader is
 * at the top or flushes the buffer, and the two lists are folded back under
 * one cap there. The worst case is `2 * TAIL_MAX_ROWS` while scrolled away.
 * Tailing never grows the paged `searchResults`.
 */
export const TAIL_MAX_ROWS = 2_000;

/**
 * Bound on the dedupe key set. The keys that matter are the ones the overlap
 * window can re-deliver (the last `TAIL_LOOKBACK_MS`, at most a few fetches),
 * so evicting the oldest-inserted keys past this size is safe.
 */
export const TAIL_SEEN_KEYS_MAX = 10_000;

/** Window to ask for on this tick. Both bounds are epoch milliseconds. */
export interface TailWindow {
  startMs: number;
  endMs: number;
}

export function tailWindow(watermarkMs: number, nowMs: number, intervalMs: number): TailWindow {
  const lookback = Math.max(TAIL_LOOKBACK_MS, intervalMs * 2);
  return { startMs: Math.min(Math.max(watermarkMs - lookback, 0), nowMs), endMs: nowMs };
}

/**
 * Advance the watermark to the newest event time seen, clamped to now and
 * monotonic. `rows` may be empty (a quiet tick must not move it).
 */
export function tailWatermark(
  rows: Array<{ timestamp?: Date | null }>,
  previousMs: number,
  nowMs: number,
): number {
  let newest = previousMs;
  for (const row of rows) {
    const ms = row.timestamp?.getTime();
    if (typeof ms === 'number' && Number.isFinite(ms) && ms > newest) newest = ms;
  }
  return Math.min(newest, nowMs);
}

/**
 * The rows in `incoming` that are not already on screen, in arrival order.
 * Mutates `seen` so the next tick's overlap is cheap — the caller seeds it from
 * the result set when the tail arms.
 */
export function selectTailRows<T extends ResultRow>(
  incoming: T[],
  seen: Set<string>,
  maxKeys = TAIL_SEEN_KEYS_MAX,
): T[] {
  const fresh: T[] = [];
  for (const row of incoming) {
    const key = rowKey(row);
    if (seen.has(key)) continue;
    seen.add(key);
    fresh.push(row);
  }
  trimSeenKeys(seen, maxKeys);
  return fresh;
}

/** Drop the oldest-inserted keys until `seen` fits `maxKeys` (Set keeps insertion order). */
export function trimSeenKeys(seen: Set<string>, maxKeys = TAIL_SEEN_KEYS_MAX): void {
  if (seen.size <= maxKeys) return;
  let excess = seen.size - maxKeys;
  for (const key of seen) {
    if (excess-- <= 0) break;
    seen.delete(key);
  }
}

/**
 * Add the keys of rows already on screen (newest first) to `seen`, keeping it
 * bounded. Keys go in oldest-first so that, when trimming, the newest keys
 * (the ones the overlap window can re-deliver) are the ones kept.
 */
export function rememberTailKeys<T extends ResultRow>(
  seen: Set<string>,
  rowsNewestFirst: T[],
  maxKeys = TAIL_SEEN_KEYS_MAX,
): void {
  for (let i = rowsNewestFirst.length - 1; i >= 0; i--) seen.add(rowKey(rowsNewestFirst[i]));
  trimSeenKeys(seen, maxKeys);
}

/**
 * Tail rows the page holds in front of `searchResults`.
 *
 * `rows` are displayed; `buffered` arrived while the analyst was reading
 * further down the list and are held back so the viewport does not jump under
 * them — the conventional log-viewer behaviour, surfaced as an "N new" chip.
 */
export interface TailState<T> {
  rows: T[];
  buffered: T[];
  /**
   * Every fresh arrival folded in since the tail was reset, including those
   * the rolling window has since dropped. It drives the displayed total, which
   * keeps advancing after `rows` stops growing at the cap.
   */
  arrived: number;
}

export function emptyTailState<T>(): TailState<T> {
  return { rows: [], buffered: [], arrived: 0 };
}

/**
 * Tail arrivals the page's total should include: every arrival except the
 * ones still held behind the "N new" chip (those are counted by the chip).
 */
export function tailCountedArrivals<T>(state: TailState<T>): number {
  return Math.max(0, state.arrived - state.buffered.length);
}

/** Rows the analyst has not seen yet — drives the "N new" chip. */
export function tailPendingCount<T>(state: TailState<T>): number {
  return state.buffered.length;
}

/**
 * Fold one tick's fresh rows into the tail state.
 *
 * `atTop` is the analyst's scroll position: at the top, arrivals go straight
 * into the list (rows push down, the viewport stays put); scrolled away, they
 * are buffered.
 */
export function applyTailBatch<T>(
  state: TailState<T>,
  fresh: T[],
  atTop: boolean,
  max = TAIL_MAX_ROWS,
): TailState<T> {
  if (fresh.length === 0) return state;
  // `fresh` and `buffered` are both newest-first, and `fresh` is the newer set.
  // Every list here is newest-first, so "drop the oldest" is a slice from 0.
  const pending = [...fresh, ...state.buffered];
  const arrived = state.arrived + fresh.length;
  if (atTop) return { rows: [...pending, ...state.rows].slice(0, max), buffered: [], arrived };
  // Scrolled away: leave the displayed rows alone (no shift under the reader)
  // and roll the buffer on its own cap.
  return { rows: state.rows, buffered: pending.slice(0, max), arrived };
}

/** Move buffered arrivals into the displayed list (the "N new" chip's click). */
export function flushTailBuffer<T>(state: TailState<T>, max = TAIL_MAX_ROWS): TailState<T> {
  if (state.buffered.length === 0) return state;
  return { rows: [...state.buffered, ...state.rows].slice(0, max), buffered: [], arrived: state.arrived };
}

/**
 * Whether a tail tick may prepend rather than re-run.
 *
 * Only the raw-event list has scroll state, an artifact and a stable per-event
 * identity. An aggregate (`stats`, `timechart`, `top`, …) is a whole-window
 * computation whose correct refresh *is* a re-run, and raw SQL has no
 * guaranteed time semantics to window on. Those keep the old behaviour, where
 * it was never destructive: they are single-page result sets.
 */
export function tailPrependEligible(
  mode: string,
  isAggregate: boolean,
  displayType: string | undefined,
): boolean {
  return mode !== 'sql' && !isAggregate && (displayType === undefined || displayType === 'events');
}

/**
 * The rows a re-arm must count as "already on screen" (NAN-2557).
 *
 * Re-arming (the tail toggled off and back on, or its interval changed) zeroes
 * the watermark so the next tick re-anchors on what is displayed *now*. What is
 * displayed now is not just the paged result set: the tail's own prepended and
 * buffered arrivals are on screen too, and re-arming does not take them away —
 * an analyst who switches 15s to 30s expects the arrivals they have been
 * watching to stay put. So the arming set carries the tail's rows across the
 * re-arm; seeding from the paged set alone would drop their keys and let the
 * overlap window deliver them a second time.
 *
 * Only a genuinely new search clears the tail, and that path resets `rows`,
 * `buffered` and the seen-key set together.
 */
export function tailArmRows<T>(state: TailState<T>, pagedRows: T[]): T[] {
  if (state.rows.length === 0 && state.buffered.length === 0) return pagedRows;
  return [...state.rows, ...state.buffered, ...pagedRows];
}

/**
 * Whether the tail keeps running after the analyst picks a new time range
 * (NAN-2836).
 *
 * The tail follows the clock: every tick re-anchors the selected window so it
 * ends at "now". That is what a relative range means ("Last 24 hours", or a
 * custom window whose end is already now), so for those the tail keeps going
 * on the NEW window, the way other SIEMs' real-time search keeps running when its
 * window changes.
 *
 * A fixed range that ends in the past ("yesterday 00:00–06:00") cannot be
 * tailed. Keeping the tail on would slide the analyst's window to now on the
 * next tick and silently throw their choice away. So the tail stops instead,
 * the way picking a historical range ends other SIEMs' real-time search. "Ends at
 * now" allows one tick interval (at least a minute) of slack, because a range
 * dragged or typed up to the present lands a few seconds before `nowMs`.
 */
export function tailFollowsRange(
  range: { type: 'preset' | 'custom'; end?: Date },
  nowMs: number,
  intervalMs: number,
): boolean {
  if (range.type === 'preset') return true;
  if (!range.end) return false;
  return range.end.getTime() >= nowMs - Math.max(60_000, intervalMs);
}

/**
 * Follow-stream supervisor (NAN-3244).
 *
 * On shared cell tenants the tail is a server follow stream
 * (`x-nano-follow: true`) with 15 s polling as the fallback. The old wiring
 * had three ways to go silently dead while the UI still read "tail -f 15s":
 * the follow's `onError` was dropped whenever the page's search request id had
 * moved on (any later `handleSearch`, including an infinite-scroll page), the
 * poll tick skipped forever while a stuck `isSearching` / in-flight flag was
 * set, and the follow reconnect timer refused to run once a poll interval
 * existed — so one fallback disabled reconnects for good.
 *
 * The supervisor is the pure half: one tick per interval decides whether to
 * poll and whether to reconnect the follow. Its invariants:
 *
 * - while the follow is not open, every tick polls (a visible request);
 * - a follow that ended (completed or failed) is always reconnected, after a
 *   capped exponential backoff, and polling keeps running meanwhile;
 * - a stale connection's events cannot change state (generation check);
 * - no guard can block polling for longer than `TAIL_STALE_GUARD_MS`.
 */

/** First follow reconnect delay after a failure; doubles per failure. */
export const TAIL_FOLLOW_RECONNECT_BASE_MS = 15_000;
/** Ceiling on the follow reconnect backoff. */
export const TAIL_FOLLOW_RECONNECT_MAX_MS = 120_000;
/** No in-flight flag may block a poll tick for longer than this. */
export const TAIL_STALE_GUARD_MS = 60_000;
/**
 * NAN-3264: a follow that has delivered no row and no `heartbeat` event for
 * this long is treated as dead even though its connection is open. The server
 * heartbeats every 10 s from the follow loop itself and abandons a page after
 * 20 s, so a healthy follow is never silent for this long. The transport's
 * `: keepalive` comments do not count: the HTTP handler writes them even while
 * the follow is wedged.
 */
export const TAIL_FOLLOW_STALL_MS = 45_000;
/** How often the page checks a follow for a stall, independent of the tick. */
export const TAIL_FOLLOW_STALL_CHECK_MS = 5_000;

/**
 * `off`: not opened yet. `unavailable`: the server refused follow for this
 * query/tenant (not retryable); the tail polls only until it is re-armed.
 */
export type TailFollowStatus = 'off' | 'connecting' | 'open' | 'down' | 'unavailable';

export interface TailSupervisor {
  status: TailFollowStatus;
  /** Identifies the current follow connection; stale callbacks carry an older one. */
  generation: number;
  /** Consecutive follow failures (drives the backoff). */
  failures: number;
  /** When the current connection attempt started (epoch ms). */
  connectingSinceMs: number;
  /** Earliest time a `down` follow may reconnect (epoch ms). */
  reconnectAtMs: number;
  /** Last proof of life from the current follow: a row batch or heartbeat (epoch ms). */
  lastActivityMs: number;
}

export function tailSupervisor(): TailSupervisor {
  return { status: 'off', generation: 0, failures: 0, connectingSinceMs: 0, reconnectAtMs: 0, lastActivityMs: 0 };
}

/** A new follow connection is being opened; returns the state and its generation. */
export function tailFollowConnecting(state: TailSupervisor, nowMs: number): TailSupervisor {
  return {
    ...state,
    status: 'connecting',
    generation: state.generation + 1,
    connectingSinceMs: nowMs,
    lastActivityMs: nowMs,
  };
}

/** The follow delivered its first event: it is live, polling stops. */
export function tailFollowOpened(state: TailSupervisor, generation: number, nowMs?: number): TailSupervisor {
  if (generation !== state.generation || state.status !== 'connecting') return state;
  return { ...state, status: 'open', failures: 0, lastActivityMs: nowMs ?? state.lastActivityMs };
}

/**
 * NAN-3264: the current follow proved it is alive (rows or a heartbeat).
 * Events from a superseded connection are ignored.
 */
export function tailFollowActivity(state: TailSupervisor, generation: number, nowMs: number): TailSupervisor {
  if (generation !== state.generation || (state.status !== 'connecting' && state.status !== 'open')) return state;
  return { ...state, lastActivityMs: Math.max(state.lastActivityMs, nowMs) };
}

/**
 * NAN-3264: the current follow is open (or still connecting) but has shown no
 * sign of life for `TAIL_FOLLOW_STALL_MS`. The caller aborts it and ends it as
 * an error, which polls at once and reconnects after backoff.
 */
export function tailFollowStalled(state: TailSupervisor, nowMs: number): boolean {
  if (state.status !== 'connecting' && state.status !== 'open') return false;
  return nowMs - state.lastActivityMs >= TAIL_FOLLOW_STALL_MS;
}

export function tailFollowReconnectDelay(failures: number): number {
  if (failures <= 0) return 0;
  return Math.min(TAIL_FOLLOW_RECONNECT_BASE_MS * 2 ** (failures - 1), TAIL_FOLLOW_RECONNECT_MAX_MS);
}

/**
 * Stream error codes that mean "this query/tenant cannot be followed", not
 * "this connection failed": reconnecting would fail the same way.
 */
const TAIL_FOLLOW_UNSUPPORTED_CODES = new Set(['VALIDATION_ERROR', 'PART_LOG_IDENTITY_MISSING']);

export function tailFollowOutcome(errorCode: string | undefined): 'error' | 'unsupported' {
  return errorCode && TAIL_FOLLOW_UNSUPPORTED_CODES.has(errorCode) ? 'unsupported' : 'error';
}

/**
 * The follow ended. `completed` is a clean server-side end (lifetime reached):
 * reconnect on the next tick. `error` is a failure and backs off.
 * `unsupported` stops reconnecting. In every case polling covers the tail.
 * Events from a superseded connection are ignored.
 */
export function tailFollowEnded(
  state: TailSupervisor,
  generation: number,
  outcome: 'completed' | 'error' | 'unsupported',
  nowMs: number,
): TailSupervisor {
  if (generation !== state.generation || (state.status !== 'connecting' && state.status !== 'open')) return state;
  if (outcome === 'unsupported') return { ...state, status: 'unavailable' };
  const failures = outcome === 'completed' ? 0 : state.failures + 1;
  return { ...state, status: 'down', failures, reconnectAtMs: nowMs + tailFollowReconnectDelay(failures) };
}

export interface TailTickInput {
  nowMs: number;
  /** The page may use a follow stream for this query (shared tenant, raw events). */
  followEligible: boolean;
  /** Tick interval; a connection still not open after one interval is polled around. */
  intervalMs: number;
  /** When the in-flight poll started, or 0. */
  pollStartedAtMs: number;
  /** When the page's own search started, or 0 when idle. */
  searchingSinceMs: number;
}

export interface TailTickAction {
  poll: boolean;
  reconnect: boolean;
}

function guardHeld(sinceMs: number, nowMs: number): boolean {
  return sinceMs > 0 && nowMs - sinceMs < TAIL_STALE_GUARD_MS;
}

/** What one tail tick must do. */
export function tailSupervisorTick(state: TailSupervisor, input: TailTickInput): TailTickAction {
  const reconnect = input.followEligible
    && (state.status === 'off' || (state.status === 'down' && input.nowMs >= state.reconnectAtMs));
  const followCovers = input.followEligible && (
    state.status === 'open'
    || (state.status === 'connecting' && input.nowMs - state.connectingSinceMs < input.intervalMs)
  );
  const blocked = guardHeld(input.pollStartedAtMs, input.nowMs) || guardHeld(input.searchingSinceMs, input.nowMs);
  return { poll: !followCovers && !blocked, reconnect };
}

/**
 * Paged poll (NAN-3264).
 *
 * A single newest-first page of `TAIL_FETCH_LIMIT` rows covers a tick at any
 * sane rate, but not the catch-up after a follow died or stalled: the events
 * since the last one seen can be several pages, and a newest-only page then
 * leaves a hole between the cursor and the oldest row it returned. So a poll
 * pages downwards from now, each page fenced at the previous page's oldest
 * instant (the instant itself kept; never an offset — deep offsets
 * are what exhaust the lean cell), until a page reaches the cursor (the last
 * event time seen, follow rows included) or comes back short.
 *
 * `complete` says whether the cursor was reached. Only then may the caller
 * advance its watermark past what it fetched; an incomplete catch-up (the page
 * cap, an escalated or failed page) keeps the old watermark so the next tick
 * re-pages the same span, and the seen-key dedupe drops what was already
 * shown. Hitting the page cap is the one exception: the caller advances
 * anyway so a sustained flood cannot pin the window open forever.
 */

/** Pages one poll may read while catching up. */
export const TAIL_POLL_MAX_PAGES = 8;

export interface TailPageFetch<T> {
  /** One newest-first page in `[startMs, endMs]`, or `null` when the read did not return rows (escalated job). */
  fetchPage: (window: TailWindow) => Promise<T[] | null>;
  /** Event time of a row (epoch ms), or NaN when it has none. */
  rowTimeMs: (row: T) => number;
  window: TailWindow;
  /** Newest event time already seen (the poll cursor); 0 when unarmed. */
  cursorMs: number;
  pageSize?: number;
  maxPages?: number;
}

export interface TailPagedPoll<T> {
  /** Every row fetched, newest first, duplicates across page fences included. */
  rows: T[];
  pages: number;
  /** The pages reached the cursor or the bottom of the window. */
  complete: boolean;
  /** Stopped at `maxPages` with the cursor not yet reached. */
  capped: boolean;
}

export async function collectTailPages<T>({
  fetchPage,
  rowTimeMs,
  window,
  cursorMs,
  pageSize = TAIL_FETCH_LIMIT,
  maxPages = TAIL_POLL_MAX_PAGES,
}: TailPageFetch<T>): Promise<TailPagedPoll<T>> {
  const rows: T[] = [];
  let endMs = window.endMs;
  for (let page = 0; page < maxPages; page++) {
    const batch = await fetchPage({ startMs: window.startMs, endMs });
    if (batch === null) return { rows, pages: page, complete: false, capped: false };
    rows.push(...batch);
    if (batch.length < pageSize) return { rows, pages: page + 1, complete: true, capped: false };
    let oldest = Number.POSITIVE_INFINITY;
    for (const row of batch) {
      const ms = rowTimeMs(row);
      if (Number.isFinite(ms) && ms < oldest) oldest = ms;
    }
    // Reached the cursor: everything older was seen before (the overlap below
    // it is re-read by the window's lookback on every tick anyway).
    if (oldest <= cursorMs) return { rows, pages: page + 1, complete: true, capped: false };
    // The fence must move down, or a page of one instant would repeat. It
    // keeps the oldest instant itself (+1 ms) whether `end` is read
    // inclusively or not; rows re-read there are dropped by the dedupe.
    if (!Number.isFinite(oldest) || oldest + 1 >= endMs || oldest <= window.startMs) {
      return { rows, pages: page + 1, complete: true, capped: false };
    }
    endMs = oldest + 1;
  }
  return { rows, pages: maxPages, complete: false, capped: true };
}
