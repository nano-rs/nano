// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-2599: first-event checklist steps and troubleshooting hints. */
import { describe, expect, it } from 'vitest';
import type { IngestCredentialActivity } from '@/lib/api/types';
import { firstEventSteps, formatElapsed, rejectionHint, troubleshootingHints, SEARCHABLE_TARGET_MS } from './first-event';

function activity(over: Partial<IngestCredentialActivity> = {}, edge: Partial<NonNullable<IngestCredentialActivity['edge']>> | null = null): IngestCredentialActivity {
  return {
    credential_id: 'c1', window_hours: 1,
    edge: edge === null ? null : {
      first_accepted_at: null, last_accepted_at: null, last_rejected_at: null, last_rejection_class: null, last_rejection_status: null,
      requests_24h: 0, events_24h: 0, bytes_24h: 0, unknown_event_requests_24h: 0, sampled_at: null, recorded_at: null, ...edge,
    },
    lake: { events: 0, bytes: 0, parse_failures: 0, first_event_at: null, last_event_at: null, first_searchable_at: null,
      last_searchable_at: null, sources: [], hours: [] },
    first_event: { received_at_edge: null, searchable_at: null, state: 'waiting' },
    ...over,
  };
}
const T0 = '2026-09-23T10:00:00Z';
const at = (s: number) => new Date(Date.parse(T0) + s * 1000).toISOString();

describe('firstEventSteps', () => {
  it('waits, then receives, then turns searchable with elapsed times', () => {
    let steps = firstEventSteps(T0, undefined, Date.parse(at(5)));
    expect(steps.map((s) => s.state)).toEqual(['done', 'active', 'pending']);
    steps = firstEventSteps(T0, activity({ first_event: { received_at_edge: at(8), searchable_at: null, state: 'received' } }), Date.parse(at(20)));
    expect(steps.map((s) => s.state)).toEqual(['done', 'done', 'active']);
    expect(steps[1].elapsedMs).toBe(8000);
    steps = firstEventSteps(T0, activity({ first_event: { received_at_edge: at(8), searchable_at: at(68), state: 'searchable' } }), Date.parse(at(90)));
    expect(steps.map((s) => s.state)).toEqual(['done', 'done', 'done']);
    expect(steps[2].elapsedMs).toBe(60_000);
    expect(steps[2].overTarget).toBe(false);
  });

  it('flags searchable over the 2 min target, and clamps browser clock skew', () => {
    const late = activity({ first_event: { received_at_edge: at(-3), searchable_at: at(200), state: 'searchable' } });
    const steps = firstEventSteps(T0, late, Date.parse(at(300)));
    expect(steps[1].elapsedMs).toBe(0);
    expect(steps[2].overTarget).toBe(true);
    const waiting = firstEventSteps(T0, activity({ first_event: { received_at_edge: at(1), searchable_at: null, state: 'received' } }),
      Date.parse(at(2)) + SEARCHABLE_TARGET_MS);
    expect(waiting[2].overTarget).toBe(true);
  });

  it('treats a searchable lake as received when the edge row has not landed yet', () => {
    const steps = firstEventSteps(T0, activity({ first_event: { received_at_edge: null, searchable_at: at(40), state: 'searchable' } }), Date.parse(at(50)));
    expect(steps[1].state).toBe('done');
    expect(steps[2].state).toBe('done');
  });
});

describe('formatElapsed', () => {
  it('formats compactly', () => {
    expect(formatElapsed(1234)).toBe('1.2 s');
    expect(formatElapsed(42_000)).toBe('42 s');
    expect(formatElapsed(185_000)).toBe('3 m 05 s');
    expect(formatElapsed(7_440_000)).toBe('2 h 04 m');
    expect(formatElapsed(null)).toBe('—');
  });
});

describe('rejectionHint', () => {
  it.each([
    [{ last_rejection_class: 'http_401', last_rejection_status: 401 }, 'unauthorized', 3],
    [{ last_rejection_class: null, last_rejection_status: 401 }, 'unauthorized', 3],
    [{ last_rejection_class: 'source_not_allowed', last_rejection_status: 403 }, 'source_not_allowed', 6],
    [{ last_rejection_class: 'http_403', last_rejection_status: 403 }, 'wrong_source', 4],
    [{ last_rejection_class: 'source_not_enrolled', last_rejection_status: 503 }, 'source_not_enrolled', undefined],
    [{ last_rejection_class: 'raw_handoff_queue_full', last_rejection_status: 503 }, 'busy', 9],
    [{ last_rejection_class: 'http_400', last_rejection_status: 400 }, 'invalid_data', 6],
  ])('%j → %s', (edge, id, code) => {
    const hint = rejectionHint(edge)!;
    expect(hint.id).toBe(id);
    expect(hint.hecCode).toBe(code);
  });
  it('is null without a rejection', () => {
    expect(rejectionHint(null)).toBeNull();
    expect(rejectionHint({ last_rejection_class: null, last_rejection_status: null })).toBeNull();
  });
});

describe('troubleshootingHints', () => {
  it('links parse failures to the parser', () => {
    const hints = troubleshootingHints(activity({ lake: { ...activity().lake, events: 10, parse_failures: 3 } }), 0);
    expect(hints.map((h) => h.id)).toEqual(['parse_failures']);
    expect(hints[0].parserLink).toBe(true);
  });
  it('drops a rejection that an accepted request superseded', () => {
    const stale = activity({}, { last_rejected_at: at(1), last_accepted_at: at(5), last_rejection_class: 'http_401', last_rejection_status: 401 });
    expect(troubleshootingHints(stale, 0)).toEqual([]);
    const current = activity({}, { last_rejected_at: at(6), last_accepted_at: at(5), last_rejection_class: 'http_401', last_rejection_status: 401 });
    expect(troubleshootingHints(current, 0).map((h) => h.id)).toEqual(['unauthorized']);
  });
  it('nudges after 30 s of silence, and says when activity is redacted', () => {
    expect(troubleshootingHints(activity(), 10_000)).toEqual([]);
    expect(troubleshootingHints(activity(), 31_000).map((h) => h.id)).toEqual(['nothing_yet']);
    expect(troubleshootingHints(activity({ redacted: true }), 0).map((h) => h.id)).toEqual(['redacted']);
  });
});
