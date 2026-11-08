// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * First-event confirmation (main's NAN-2599 module, re-backed for the
 * ClickHouse product by NAN-4922): the pure half of the Add source
 * "token issued → first request accepted → searchable" checklist, read from
 * the source's connect status (`GET /api/log-sources/{id}/connect-status`).
 *
 * - accepted: the token's `last_used_at` (Vector's per-token request counter,
 *   sampled by nano-api), so it can lag a few seconds;
 * - searchable: the per-source ClickHouse rollup saw an event at or after the
 *   token was issued (events land unparsed before any parser is published).
 *
 * Targets: accepted ≤ 10 s after the first send, searchable ≤ 2 min after that.
 */

import type { LogSourceConnectDetail } from '@/lib/api/log-source-connect';

/** Poll cadence while waiting. */
export const FIRST_EVENT_POLL_MS = 3000;
export const RECEIVED_TARGET_MS = 10_000;
export const SEARCHABLE_TARGET_MS = 120_000;

export type StepState = 'done' | 'active' | 'pending';

export interface FirstEventStep {
  key: 'issued' | 'received' | 'searchable';
  label: string;
  state: StepState;
  at: string | null;
  /** Milliseconds from the previous step's time to this one's, when both are known. */
  elapsedMs: number | null;
  overTarget: boolean;
}

function ms(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  return Number.isNaN(t) ? null : t;
}

/** Clock skew between the browser and the servers; a first event this far before issuance still counts. */
const SKEW_MS = 60_000;

export interface FirstEventFacts {
  receivedAt: string | null;
  searchableAt: string | null;
  state: 'waiting' | 'received' | 'searchable';
  /** Events the source has received in 24 h (any token). */
  events24h: number;
  /** Arriving but no parser published yet. */
  unparsed: boolean;
}

/** What the connect status says about one token issued at `issuedAt`. */
export function firstEventFacts(
  detail: LogSourceConnectDetail | undefined,
  credentialId: string,
  issuedAt: string,
): FirstEventFacts {
  const issued = ms(issuedAt) ?? 0;
  const token = detail?.tokens.find((t) => t.credential_id === credentialId);
  const used = ms(token?.last_used_at);
  const receivedAt = used !== null && used >= issued - SKEW_MS ? token!.last_used_at! : null;
  const last = ms(detail?.last_seen);
  const searchableAt = last !== null && last >= issued - SKEW_MS ? detail!.last_seen! : null;
  return {
    receivedAt,
    searchableAt,
    state: searchableAt ? 'searchable' : receivedAt ? 'received' : 'waiting',
    events24h: detail?.events_24h ?? 0,
    unparsed: detail?.state === 'receiving_unparsed',
  };
}

export function firstEventSteps(issuedAt: string, facts: FirstEventFacts | undefined, now: number): FirstEventStep[] {
  const issued = ms(issuedAt);
  const received = ms(facts?.receivedAt);
  const searchable = ms(facts?.searchableAt);
  const gap = (from: number | null, to: number | null) => (from !== null && to !== null ? Math.max(0, to - from) : null);
  // The rollup can see the event before the token counter is sampled: "accepted" is then implied.
  const receivedDone = received !== null || searchable !== null;
  const searchableDone = searchable !== null;
  const searchableElapsed = gap(received, searchable);
  const waitingSinceReceived = received !== null ? now - received : null;
  return [
    { key: 'issued', label: 'Token issued', state: 'done', at: issuedAt, elapsedMs: null, overTarget: false },
    {
      key: 'received',
      label: 'First request accepted by Vector',
      state: receivedDone ? 'done' : 'active',
      at: facts?.receivedAt ?? null,
      elapsedMs: gap(issued, received),
      overTarget: false,
    },
    {
      key: 'searchable',
      label: 'Searchable',
      state: searchableDone ? 'done' : receivedDone ? 'active' : 'pending',
      at: facts?.searchableAt ?? null,
      elapsedMs: searchableElapsed,
      overTarget: searchableDone
        ? (searchableElapsed ?? 0) > SEARCHABLE_TARGET_MS
        : waitingSinceReceived !== null && waitingSinceReceived > SEARCHABLE_TARGET_MS,
    },
  ];
}

export interface TroubleshootingHint {
  id: string;
  tone: 'info' | 'warning' | 'error';
  title: string;
  detail: string;
  /** A HEC response code, when one explains the hint. */
  hecCode?: number;
  /** Show "Build the parser". */
  parserLink?: boolean;
}

/** Hints from what has (not) arrived `waitedMs` after issuance. */
export function troubleshootingHints(facts: FirstEventFacts | undefined, waitedMs: number): TroubleshootingHint[] {
  const hints: TroubleshootingHint[] = [];
  if (!facts) return hints;
  if (facts.state === 'waiting' && waitedMs > 60_000) {
    hints.push({
      id: 'nothing-yet',
      tone: 'info',
      title: 'Nothing has arrived with this token yet',
      detail: 'Check the sender points at the endpoint above and sends the header exactly as shown (HEC uses "Authorization: Splunk <token>", HTTP and OTLP use "Bearer"). A 401 means the token is wrong or revoked.',
    });
  }
  if (facts.state === 'received' && waitedMs > SEARCHABLE_TARGET_MS) {
    hints.push({
      id: 'accepted-not-searchable',
      tone: 'warning',
      title: 'Vector accepted requests but no event is searchable yet',
      detail: 'The requests carried no events, or the events failed to write. HEC needs an "event" field; HTTP JSON needs a JSON object, array or NDJSON body.',
    });
  }
  if (facts.unparsed && facts.state === 'searchable') {
    hints.push({
      id: 'unparsed',
      tone: 'info',
      title: 'Events are arriving unparsed',
      detail: 'They are searchable now. Build and publish the parser to normalize them; events received before that stay as they arrived.',
      parserLink: true,
    });
  }
  return hints;
}

/** `+4 s`, `+1 m 12 s`. */
export function formatElapsed(msValue: number | null): string {
  if (msValue === null) return '';
  const s = Math.round(msValue / 1000);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} m ${s % 60} s`;
  return `${Math.floor(m / 60)} h ${m % 60} m`;
}
