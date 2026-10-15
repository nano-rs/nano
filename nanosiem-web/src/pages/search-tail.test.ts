// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  TAIL_FETCH_LIMIT,
  TAIL_LOOKBACK_MS,
  TAIL_MAX_ROWS,
  applyTailBatch,
  emptyTailState,
  flushTailBuffer,
  selectTailRows,
  tailArmRows,
  tailCountedArrivals,
  tailFollowsRange,
  tailPendingCount,
  tailPrependEligible,
  tailWatermark,
  tailWindow,
  TAIL_FOLLOW_RECONNECT_BASE_MS,
  TAIL_FOLLOW_RECONNECT_MAX_MS,
  TAIL_STALE_GUARD_MS,
  tailFollowConnecting,
  tailFollowEnded,
  tailFollowOpened,
  tailFollowReconnectDelay,
  tailSupervisor,
  tailSupervisorTick,
  TAIL_FOLLOW_STALL_MS,
  TAIL_POLL_MAX_PAGES,
  collectTailPages,
  tailFollowActivity,
  tailFollowStalled,
  type TailWindow,
} from './search-tail.ts';

interface Row {
  id: string;
  timestamp: Date;
  fields: Record<string, unknown>;
}

const row = (uid: string, isoTime: string): Row => ({
  id: `tail-${uid}`,
  timestamp: new Date(isoTime),
  fields: { 'metadata.uid': uid, time: isoTime },
});

const T0 = Date.parse('2026-09-21T12:00:00.000Z');

describe('tailWindow', () => {
  it('re-asks an overlapping window so the lake visibility lag cannot open a gap', () => {
    const window = tailWindow(T0, T0 + 15_000, 15_000);
    assert.equal(window.endMs, T0 + 15_000);
    // The window reaches back before the watermark, not forward from it.
    assert.equal(window.startMs, T0 - TAIL_LOOKBACK_MS);
    assert.ok(T0 - window.startMs >= 120_000, 'overlap must cover the ≤2 min arrival→searchable budget');
  });

  it('widens the overlap for slow tail intervals so two ticks always overlap', () => {
    const window = tailWindow(T0, T0 + 300_000, 300_000);
    assert.equal(window.startMs, T0 - 600_000);
  });

  it('never asks for a window that starts after now', () => {
    const window = tailWindow(T0 + 10_000_000, T0, 15_000);
    assert.equal(window.startMs, T0);
    assert.equal(window.endMs, T0);
  });
});

describe('tailWatermark', () => {
  it('advances to the newest event time seen', () => {
    const rows = [row('c', '2026-09-21T12:00:09Z'), row('a', '2026-09-21T12:00:03Z')];
    assert.equal(tailWatermark(rows, T0, T0 + 20_000), Date.parse('2026-09-21T12:00:09Z'));
  });

  it('does not move on a quiet tick', () => {
    assert.equal(tailWatermark([], T0, T0 + 20_000), T0);
  });

  it('never regresses on an out-of-order arrival', () => {
    const late = [row('late', '2026-09-21T11:59:10Z')];
    assert.equal(tailWatermark(late, T0, T0 + 20_000), T0);
  });

  it('clamps a skewed future timestamp to now so it cannot open a permanent hole', () => {
    const skewed = [row('skew', '2099-01-01T00:00:00Z')];
    assert.equal(tailWatermark(skewed, T0, T0 + 20_000), T0 + 20_000);
  });

  it('ignores rows with an unparseable timestamp', () => {
    const broken = [{ id: 'x', timestamp: new Date('nope'), fields: {} }];
    assert.equal(tailWatermark(broken, T0, T0 + 20_000), T0);
  });
});

describe('selectTailRows', () => {
  it('drops rows the overlap re-delivered and keeps genuinely new ones', () => {
    const seen = new Set(['uid:a', 'uid:b']);
    const fresh = selectTailRows([row('b', '2026-09-21T12:00:01Z'), row('c', '2026-09-21T12:00:02Z')], seen);
    assert.deepEqual(fresh.map(r => r.fields['metadata.uid']), ['c']);
    assert.ok(seen.has('uid:c'));
  });

  it('dedupes within one batch', () => {
    const seen = new Set<string>();
    const fresh = selectTailRows([row('c', '2026-09-21T12:00:02Z'), row('c', '2026-09-21T12:00:02Z')], seen);
    assert.equal(fresh.length, 1);
  });

  it('falls back to the row id when the event carries no uid', () => {
    const seen = new Set(['id:tail-1']);
    const anonymous = { id: 'tail-1', timestamp: new Date(T0), fields: { message: 'hi' } };
    assert.deepEqual(selectTailRows([anonymous], seen), []);
  });
});

describe('applyTailBatch', () => {
  const a = row('a', '2026-09-21T12:00:01Z');
  const b = row('b', '2026-09-21T12:00:02Z');
  const c = row('c', '2026-09-21T12:00:03Z');

  it('prepends newest-first while the analyst is at the top', () => {
    const first = applyTailBatch(emptyTailState<Row>(), [b, a], true);
    const second = applyTailBatch(first, [c], true);
    assert.deepEqual(second.rows.map(r => r.id), ['tail-c', 'tail-b', 'tail-a']);
    assert.equal(tailPendingCount(second), 0);
  });

  it('holds arrivals back while the analyst has scrolled away, newest first', () => {
    const first = applyTailBatch(emptyTailState<Row>(), [b, a], false);
    const second = applyTailBatch(first, [c], false);
    assert.deepEqual(second.rows, []);
    assert.deepEqual(second.buffered.map(r => r.id), ['tail-c', 'tail-b', 'tail-a']);
    assert.equal(tailPendingCount(second), 3);
  });

  it('flushes the buffer in front of the already-prepended rows', () => {
    const scrolled = applyTailBatch(applyTailBatch(emptyTailState<Row>(), [a], true), [c, b], false);
    const flushed = flushTailBuffer(scrolled);
    assert.deepEqual(flushed.rows.map(r => r.id), ['tail-c', 'tail-b', 'tail-a']);
    assert.deepEqual(flushed.buffered, []);
  });

  it('rolls past the cap: keeps the newest rows, drops the oldest, never stops (NAN-3254)', () => {
    const many = Array.from({ length: TAIL_MAX_ROWS }, (_, i) => row(`u${i}`, '2026-09-21T12:00:05Z'));
    const full = applyTailBatch(emptyTailState<Row>(), many, true);
    assert.equal(full.rows.length, TAIL_MAX_ROWS);
    assert.equal('saturated' in full, false);
    // The next arrival is still taken on; the oldest row falls off the end.
    const after = applyTailBatch(full, [c], true);
    assert.notEqual(after, full);
    assert.equal(after.rows.length, TAIL_MAX_ROWS);
    assert.equal(after.rows[0].id, 'tail-c');
    assert.equal(after.rows[TAIL_MAX_ROWS - 1].id, `tail-u${TAIL_MAX_ROWS - 2}`);
    assert.equal(after.rows.some(r => r.id === `tail-u${TAIL_MAX_ROWS - 1}`), false);
    // The total keeps counting every arrival, including the dropped one.
    assert.equal(after.arrived, TAIL_MAX_ROWS + 1);
    assert.equal(tailCountedArrivals(after), TAIL_MAX_ROWS + 1);
  });

  it('keeps rolling across many batches at a steady rate', () => {
    let state = emptyTailState<Row>();
    // ~18 eps for 30 minutes in 15 s ticks: far past the old 2 000-row stop.
    for (let tick = 0; tick < 120; tick++) {
      const batch = Array.from({ length: 270 }, (_, i) => row(`t${tick}-${269 - i}`, '2026-09-21T12:00:05Z'));
      state = applyTailBatch(state, batch, true);
      assert.ok(state.rows.length <= TAIL_MAX_ROWS);
    }
    assert.equal(state.rows.length, TAIL_MAX_ROWS);
    assert.equal(state.rows[0].fields['metadata.uid'], 't119-269');
    assert.equal(state.arrived, 120 * 270);
  });

  it('rolls the buffer on its own cap while scrolled away, without trimming the displayed rows', () => {
    const shown = applyTailBatch(
      emptyTailState<Row>(),
      Array.from({ length: TAIL_MAX_ROWS }, (_, i) => row(`s${i}`, '2026-09-21T12:00:05Z')),
      true,
    );
    let state = shown;
    for (let tick = 0; tick < 5; tick++) {
      state = applyTailBatch(
        state,
        Array.from({ length: TAIL_FETCH_LIMIT }, (_, i) => row(`b${tick}-${i}`, '2026-09-21T12:00:06Z')),
        false,
      );
    }
    // Displayed rows did not move under the reader.
    assert.equal(state.rows, shown.rows);
    assert.equal(state.buffered.length, TAIL_MAX_ROWS);
    assert.equal(state.buffered[0].id, 'tail-b4-0');
    // Buffered arrivals are counted by the chip, not the total.
    assert.equal(tailPendingCount(state), TAIL_MAX_ROWS);
    assert.equal(tailCountedArrivals(state), state.arrived - TAIL_MAX_ROWS);
    // Flushing folds both lists back under one cap, newest first.
    const flushed = flushTailBuffer(state);
    assert.equal(flushed.rows.length, TAIL_MAX_ROWS);
    assert.equal(flushed.buffered.length, 0);
    assert.equal(flushed.rows[0].id, 'tail-b4-0');
    assert.equal(tailCountedArrivals(flushed), flushed.arrived);
  });

  it('caps rows + buffered when arrivals land at the top', () => {
    const scrolled = applyTailBatch(
      emptyTailState<Row>(),
      Array.from({ length: TAIL_MAX_ROWS - 10 }, (_, i) => row(`u${i}`, '2026-09-21T12:00:05Z')),
      false,
    );
    const atTop = applyTailBatch(
      scrolled,
      Array.from({ length: TAIL_FETCH_LIMIT }, (_, i) => row(`v${i}`, '2026-09-21T12:00:06Z')),
      true,
    );
    assert.equal(atTop.rows.length + atTop.buffered.length, TAIL_MAX_ROWS);
    assert.equal(atTop.rows[0].id, 'tail-v0');
  });

  it('is a no-op on a quiet tick', () => {
    const state = emptyTailState<Row>();
    assert.equal(applyTailBatch(state, [], true), state);
  });
});

describe('tailPrependEligible', () => {
  it('prepends for the raw event list', () => {
    assert.equal(tailPrependEligible('piped', false, undefined), true);
    assert.equal(tailPrependEligible('piped', false, 'events'), true);
  });

  it('leaves aggregates, visualizations and raw SQL on the whole-window re-run', () => {
    assert.equal(tailPrependEligible('piped', true, 'table'), false);
    assert.equal(tailPrependEligible('piped', false, 'timechart'), false);
    assert.equal(tailPrependEligible('piped', false, 'ranked_bar'), false);
    assert.equal(tailPrependEligible('sql', false, 'events'), false);
  });
});

describe('tailArmRows', () => {
  it('carries the tail\'s own rows across a re-arm so the overlap cannot re-deliver them', () => {
    // NAN-2557: re-arming (tail toggled off/on, interval changed) zeroes the
    // watermark but leaves the arrivals on screen. Arming from the paged set
    // alone would forget their keys, and the next tick's deliberate overlap
    // would prepend them a second time.
    const paged = [row('paged-0', '2026-09-21T11:59:00.000Z')];
    const state = applyTailBatch(
      emptyTailState<Row>(),
      [row('new-0', '2026-09-21T12:00:00.000Z')],
      true,
    );
    const held = { ...state, buffered: [row('held-0', '2026-09-21T12:00:30.000Z')] };

    const armed = tailArmRows(held, paged);
    assert.deepEqual(
      armed.map(r => r.fields['metadata.uid']),
      ['new-0', 'held-0', 'paged-0'],
    );

    // Seeded from that set, the next tick re-asking the overlap returns nothing new.
    const seen = new Set(armed.map(r => `uid:${r.fields['metadata.uid'] as string}`));
    assert.deepEqual(
      selectTailRows([row('new-0', '2026-09-21T12:00:00.000Z'), row('held-0', '2026-09-21T12:00:30.000Z')], seen),
      [],
    );
  });

  it('is the paged set itself when the tail holds nothing', () => {
    const paged = [row('paged-0', '2026-09-21T11:59:00.000Z')];
    assert.equal(tailArmRows(emptyTailState<Row>(), paged), paged);
  });
});

describe('tailFollowsRange (NAN-2836)', () => {
  const now = Date.parse('2026-09-25T12:00:00Z');

  it('follows a relative preset', () => {
    assert.equal(tailFollowsRange({ type: 'preset' }, now, 15_000), true);
  });

  it('follows a custom window that already ends at now', () => {
    assert.equal(tailFollowsRange({ type: 'custom', end: new Date(now - 5_000) }, now, 15_000), true);
    assert.equal(tailFollowsRange({ type: 'custom', end: new Date(now) }, now, 15_000), true);
  });

  it('stops for a fixed window that ends in the past', () => {
    assert.equal(tailFollowsRange({ type: 'custom', end: new Date(now - 6 * 3600_000) }, now, 15_000), false);
    assert.equal(tailFollowsRange({ type: 'custom' }, now, 15_000), false);
  });

  it('allows one tick interval of slack for slow intervals', () => {
    const end = new Date(now - 4 * 60_000);
    assert.equal(tailFollowsRange({ type: 'custom', end }, now, 60_000), false);
    assert.equal(tailFollowsRange({ type: 'custom', end }, now, 5 * 60_000), true);
  });
});

describe('tail follow supervisor (NAN-3244)', () => {
  const tick = (
    state: ReturnType<typeof tailSupervisor>,
    nowMs: number,
    extra: Partial<Parameters<typeof tailSupervisorTick>[1]> = {},
  ) => tailSupervisorTick(state, {
    nowMs,
    followEligible: true,
    intervalMs: 15_000,
    pollStartedAtMs: 0,
    searchingSinceMs: 0,
    ...extra,
  });

  it('follow errors → the next poll tick fires and prepends the new rows', () => {
    // Arm: the follow connects and delivers its first batch.
    let sup = tailFollowConnecting(tailSupervisor(), T0);
    const generation = sup.generation;
    sup = tailFollowOpened(sup, generation);
    const seen = new Set<string>();
    let tail = applyTailBatch(emptyTailState<Row>(), selectTailRows([row('e1', '2026-09-21T11:59:59Z')], seen), true);
    assert.deepEqual(tick(sup, T0 + 15_000), { poll: false, reconnect: false }, 'an open follow covers the tail');

    // The server ends it with RESOURCE_EXHAUSTED 35 s in.
    sup = tailFollowEnded(sup, generation, 'error', T0 + 35_000);
    assert.equal(sup.status, 'down');

    // The very next tick (at most one interval later) polls...
    const action = tick(sup, T0 + 35_000);
    assert.equal(action.poll, true);
    // ...and what it fetches is prepended in front of the follow's rows.
    const polled = [row('e3', '2026-09-21T12:00:30Z'), row('e2', '2026-09-21T12:00:20Z'), row('e1', '2026-09-21T11:59:59Z')];
    tail = applyTailBatch(tail, selectTailRows(polled, seen), true);
    assert.deepEqual(tail.rows.map(r => r.fields['metadata.uid']), ['e3', 'e2', 'e1']);

    // Polling keeps going on every later tick until the follow is back.
    for (let t = T0 + 50_000; t < T0 + 300_000; t += 15_000) {
      assert.equal(tick(sup, t).poll, true, `poll at +${t - T0} ms`);
    }
  });

  it('a polled tail still reconnects the follow (polling must not disable reconnects)', () => {
    let sup = tailFollowConnecting(tailSupervisor(), T0);
    sup = tailFollowEnded(sup, sup.generation, 'error', T0);
    assert.equal(tick(sup, T0).reconnect, false, 'first retry waits for the backoff');
    assert.deepEqual(tick(sup, T0 + 15_000), { poll: true, reconnect: true });
    sup = tailFollowConnecting(sup, T0 + 15_000);
    sup = tailFollowEnded(sup, sup.generation, 'error', T0 + 16_000);
    assert.equal(tick(sup, T0 + 31_000).reconnect, false, 'backoff doubles');
    assert.equal(tick(sup, T0 + 46_000).reconnect, true);
  });

  it('caps the reconnect backoff', () => {
    assert.equal(tailFollowReconnectDelay(0), 0);
    assert.equal(tailFollowReconnectDelay(1), TAIL_FOLLOW_RECONNECT_BASE_MS);
    assert.equal(tailFollowReconnectDelay(20), TAIL_FOLLOW_RECONNECT_MAX_MS);
  });

  it('a clean server end reconnects at once and resets the backoff', () => {
    let sup = tailFollowConnecting(tailSupervisor(), T0);
    sup = tailFollowOpened(sup, sup.generation);
    sup = tailFollowEnded(sup, sup.generation, 'completed', T0 + 1_800_000);
    assert.equal(sup.failures, 0);
    assert.deepEqual(tick(sup, T0 + 1_800_000), { poll: true, reconnect: true });
  });

  it('ignores events from a superseded connection', () => {
    let sup = tailFollowConnecting(tailSupervisor(), T0);
    const stale = sup.generation;
    sup = tailFollowConnecting(sup, T0 + 1_000);
    sup = tailFollowOpened(sup, sup.generation);
    assert.equal(tailFollowEnded(sup, stale, 'error', T0 + 2_000).status, 'open');
  });

  it('polls around a connection that never opens', () => {
    const sup = tailFollowConnecting(tailSupervisor(), T0);
    assert.equal(tick(sup, T0 + 5_000).poll, false);
    assert.equal(tick(sup, T0 + 15_000).poll, true);
  });

  it('a stuck searching or in-flight flag cannot block polling forever', () => {
    const sup = tailSupervisor();
    const input = { followEligible: false };
    assert.equal(tick(sup, T0 + 10_000, { ...input, searchingSinceMs: T0 }).poll, false);
    assert.equal(tick(sup, T0 + TAIL_STALE_GUARD_MS, { ...input, searchingSinceMs: T0 }).poll, true);
    assert.equal(tick(sup, T0 + 10_000, { ...input, pollStartedAtMs: T0 }).poll, false);
    assert.equal(tick(sup, T0 + TAIL_STALE_GUARD_MS, { ...input, pollStartedAtMs: T0 }).poll, true);
  });

  it('dedicated tenants poll every tick and never open a follow', () => {
    assert.deepEqual(tick(tailSupervisor(), T0, { followEligible: false }), { poll: true, reconnect: false });
  });

  it('keeps polling and reconnecting however much the tail has accumulated (NAN-3254)', () => {
    // There is no volume stop any more: a tail far past TAIL_MAX_ROWS still
    // ticks exactly like an empty one.
    let tail = emptyTailState<Row>();
    for (let i = 0; i < 6; i++) {
      tail = applyTailBatch(tail, Array.from({ length: TAIL_FETCH_LIMIT }, (_, j) => row(`x${i}-${j}`, '2026-09-21T12:00:06Z')), true);
    }
    assert.ok(tail.arrived > TAIL_MAX_ROWS);
    const sup = tailFollowEnded(tailFollowConnecting(tailSupervisor(), T0), 1, 'error', T0);
    assert.deepEqual(tick(sup, T0 + 60_000), { poll: true, reconnect: true });
    assert.deepEqual(tick(tailSupervisor(), T0, { followEligible: false }), { poll: true, reconnect: false });
  });
});

describe('follow stall detection (NAN-3264)', () => {
  it('an open follow with no rows and no heartbeat for the stall window is dead', () => {
    let sup = tailFollowConnecting(tailSupervisor(), T0);
    const generation = sup.generation;
    sup = tailFollowOpened(sup, generation, T0 + 1_000);
    assert.equal(tailFollowStalled(sup, T0 + 1_000 + TAIL_FOLLOW_STALL_MS - 1), false);
    assert.equal(tailFollowStalled(sup, T0 + 1_000 + TAIL_FOLLOW_STALL_MS), true);
  });

  it('heartbeats and rows keep it alive; a stale connection cannot', () => {
    let sup = tailFollowConnecting(tailSupervisor(), T0);
    const generation = sup.generation;
    sup = tailFollowOpened(sup, generation, T0);
    // Heartbeats every 10 s for ten minutes: never stalled.
    for (let t = T0 + 10_000; t <= T0 + 600_000; t += 10_000) {
      sup = tailFollowActivity(sup, generation, t);
      assert.equal(tailFollowStalled(sup, t + 9_999), false);
    }
    // A superseded connection's heartbeat does not vouch for the new one.
    const replaced = tailFollowConnecting(sup, T0 + 600_000);
    const stillStale = tailFollowActivity(replaced, generation, T0 + 700_000);
    assert.equal(stillStale.lastActivityMs, T0 + 600_000);
    assert.equal(tailFollowStalled(stillStale, T0 + 600_000 + TAIL_FOLLOW_STALL_MS), true);
  });

  it('the live failure: rows stop, then the stall ends the follow and the next tick polls', () => {
    const tick = (state: ReturnType<typeof tailSupervisor>, nowMs: number) => tailSupervisorTick(state, {
      nowMs, followEligible: true, intervalMs: 15_000, pollStartedAtMs: 0, searchingSinceMs: 0,
    });
    let sup = tailFollowConnecting(tailSupervisor(), T0);
    const generation = sup.generation;
    sup = tailFollowOpened(sup, generation, T0);
    sup = tailFollowActivity(sup, generation, T0 + 20_000); // last rows
    // While silent but within the window the follow still covers the tail.
    assert.equal(tick(sup, T0 + 45_000).poll, false);
    const now = T0 + 20_000 + TAIL_FOLLOW_STALL_MS;
    assert.equal(tailFollowStalled(sup, now), true);
    // The watchdog ends it as an error: polling resumes at once and the
    // follow reconnects after the backoff.
    sup = tailFollowEnded(sup, generation, 'error', now);
    assert.equal(sup.status, 'down');
    assert.equal(tick(sup, now).poll, true);
    assert.equal(tick(sup, now + TAIL_FOLLOW_RECONNECT_BASE_MS).reconnect, true);
    assert.equal(tailFollowStalled(sup, now + 600_000), false, 'a down follow is not re-detected');
  });

  it('a connection that never delivers anything is a stall too', () => {
    const sup = tailFollowConnecting(tailSupervisor(), T0);
    assert.equal(tailFollowStalled(sup, T0 + TAIL_FOLLOW_STALL_MS), true);
  });
});

describe('paged poll cursor handoff (NAN-3264)', () => {
  // A source at 15 eps with whole-second event times, newest first.
  const EPS = 15;
  const events = (fromSec: number, toSec: number) => {
    const out: Array<{ uid: string; ms: number }> = [];
    for (let sec = toSec - 1; sec >= fromSec; sec--) {
      for (let k = EPS - 1; k >= 0; k--) out.push({ uid: `e${sec}-${k}`, ms: T0 + sec * 1_000 });
    }
    return out;
  };
  const serve = (all: Array<{ uid: string; ms: number }>, pageSize = TAIL_FETCH_LIMIT) => {
    const asked: TailWindow[] = [];
    const fetchPage = async (w: TailWindow) => {
      asked.push(w);
      return all.filter(e => e.ms >= w.startMs && e.ms <= w.endMs).slice(0, pageSize);
    };
    return { asked, fetchPage };
  };
  const rowTimeMs = (e: { ms: number }) => e.ms;

  it('after the follow dies, the poll resumes from the last follow row with no gap', () => {
    // The follow delivered everything up to second 600, then stalled for
    // three minutes: 2700 events arrived since. One newest page (500) would
    // leave a 2200-event hole; the paged poll reaches the cursor.
    const seen = new Set<string>();
    const followed = events(540, 600);
    for (const e of followed) seen.add(e.uid);
    const cursorMs = T0 + 599_000; // follow rows advanced the cursor
    const nowMs = T0 + 780_000;
    const all = events(0, 780);
    const { asked, fetchPage } = serve(all);
    return collectTailPages({ fetchPage, rowTimeMs, cursorMs, window: tailWindow(cursorMs, nowMs, 15_000) }).then(polled => {
      assert.equal(polled.complete, true);
      assert.equal(polled.capped, false);
      const fresh = polled.rows.filter(e => { if (seen.has(e.uid)) return false; seen.add(e.uid); return true; });
      assert.deepEqual(new Set(fresh.map(e => e.uid)), new Set(events(600, 780).map(e => e.uid)), 'every event since the cursor, once');
      assert.ok(asked.length > 1 && asked.length <= TAIL_POLL_MAX_PAGES);
      // Pages are fenced by time, never by offset, and the fence only moves down.
      for (let i = 1; i < asked.length; i++) assert.ok(asked[i].endMs < asked[i - 1].endMs);
    });
  });

  it('a quiet tick is one page', async () => {
    const cursorMs = T0 + 599_000;
    const { asked, fetchPage } = serve(events(0, 610));
    const polled = await collectTailPages({ fetchPage, rowTimeMs, cursorMs, window: tailWindow(cursorMs, T0 + 610_000, 15_000) });
    assert.equal(asked.length, 1);
    assert.equal(polled.complete, true);
  });

  it('an escalated page stops the catch-up as incomplete (the cursor must not move)', async () => {
    let calls = 0;
    const polled = await collectTailPages({
      fetchPage: async (w: TailWindow) => (++calls === 2 ? null : events(0, 780).filter(e => e.ms <= w.endMs).slice(0, TAIL_FETCH_LIMIT)),
      rowTimeMs, cursorMs: T0 + 599_000, window: tailWindow(T0 + 599_000, T0 + 780_000, 15_000),
    });
    assert.equal(polled.complete, false);
    assert.equal(polled.capped, false);
    assert.equal(polled.rows.length, TAIL_FETCH_LIMIT);
  });

  it('a flood past the page cap reports capped (the caller moves on rather than pinning the window)', async () => {
    const { fetchPage } = serve(events(0, 1_200));
    const polled = await collectTailPages({ fetchPage, rowTimeMs, cursorMs: T0 + 10_000, window: { startMs: T0, endMs: T0 + 1_200_000 } });
    assert.equal(polled.capped, true);
    assert.equal(polled.pages, TAIL_POLL_MAX_PAGES);
  });

  it('follow rows advance the cursor (watermark) the poll resumes from', () => {
    const followRows = [row('f2', '2026-09-21T12:10:00Z'), row('f1', '2026-09-21T12:09:59Z')];
    const watermark = tailWatermark(followRows, T0, T0 + 3_600_000);
    assert.equal(watermark, Date.parse('2026-09-21T12:10:00Z'));
    const w = tailWindow(watermark, T0 + 3_600_000, 15_000);
    assert.equal(w.startMs, watermark - TAIL_LOOKBACK_MS);
  });
});
