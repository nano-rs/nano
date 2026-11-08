// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-4922: the first-event checklist from the source's connect status (main's NAN-2599 tests, re-backed). */
import { describe, expect, it } from 'vitest';
import type { LogSourceConnectDetail } from '@/lib/api/log-source-connect';
import { firstEventFacts, firstEventSteps, formatElapsed, troubleshootingHints } from './first-event';

const ISSUED = '2026-11-03T10:00:00Z';
function detail(partial: Partial<LogSourceConnectDetail> = {}): LogSourceConnectDetail {
  return { source_id: 'lsrc_1', route_key: 'acme', state: 'awaiting_data', deployed: false, lifecycle_status: 'draft',
    push_capable: true, events_24h: 0, active_tokens: 1, tokens: [], ...partial };
}
const token = (last_used_at: string | null) => ({ credential_id: 'c1', name: 'acme-hec', token_prefix: 'nit_abcd1234', state: 'active' as const,
  created_at: ISSUED, last_used_at, revocable: true });

describe('firstEventFacts', () => {
  it('waits until the token is used or an event lands after issuance', () => {
    expect(firstEventFacts(detail(), 'c1', ISSUED).state).toBe('waiting');
    expect(firstEventFacts(detail({ tokens: [token('2026-11-03T10:00:05Z')] }), 'c1', ISSUED).state).toBe('received');
    const f = firstEventFacts(detail({ tokens: [token('2026-11-03T10:00:05Z')], last_seen: '2026-11-03T10:00:06Z', events_24h: 3, state: 'receiving_unparsed' }), 'c1', ISSUED);
    expect(f).toMatchObject({ state: 'searchable', events24h: 3, unparsed: true });
  });

  it('ignores activity from before the token existed (an existing source)', () => {
    const f = firstEventFacts(detail({ last_seen: '2026-11-02T09:00:00Z', events_24h: 900, tokens: [token('2026-11-02T09:00:00Z')] }), 'c1', ISSUED);
    expect(f.state).toBe('waiting');
  });

  it('only reads the issued token', () => {
    const other = { ...token('2026-11-03T10:00:05Z'), credential_id: 'c2' };
    expect(firstEventFacts(detail({ tokens: [other] }), 'c1', ISSUED).receivedAt).toBeNull();
  });
});

describe('firstEventSteps', () => {
  it('implies acceptance when the event is searchable first', () => {
    const steps = firstEventSteps(ISSUED, { receivedAt: null, searchableAt: '2026-11-03T10:00:30Z', state: 'searchable', events24h: 1, unparsed: false }, Date.parse(ISSUED) + 60_000);
    expect(steps.map((s) => s.state)).toEqual(['done', 'done', 'done']);
  });
  it('flags a searchable step waiting past its target', () => {
    const steps = firstEventSteps(ISSUED, { receivedAt: '2026-11-03T10:00:01Z', searchableAt: null, state: 'received', events24h: 0, unparsed: false }, Date.parse(ISSUED) + 5 * 60_000);
    expect(steps[2]).toMatchObject({ state: 'active', overTarget: true });
  });
});

describe('troubleshootingHints', () => {
  it('maps what has not arrived to a hint', () => {
    const waiting = { receivedAt: null, searchableAt: null, state: 'waiting' as const, events24h: 0, unparsed: false };
    expect(troubleshootingHints(waiting, 30_000)).toEqual([]);
    expect(troubleshootingHints(waiting, 90_000).map((h) => h.id)).toEqual(['nothing-yet']);
    expect(troubleshootingHints({ ...waiting, state: 'received', receivedAt: ISSUED }, 3 * 60_000).map((h) => h.id)).toEqual(['accepted-not-searchable']);
    const unparsed = troubleshootingHints({ ...waiting, state: 'searchable', searchableAt: ISSUED, unparsed: true }, 1000);
    expect(unparsed).toMatchObject([{ id: 'unparsed', parserLink: true }]);
  });
  it('formats elapsed time', () => {
    expect(formatElapsed(null)).toBe('');
    expect(formatElapsed(4_000)).toBe('4 s');
    expect(formatElapsed(72_000)).toBe('1 m 12 s');
  });
});
