// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * First-event confirmation (NAN-2599, design §3.3 / §9 P3): the pure half of
 * the Add data "credential issued → received at edge → searchable" checklist
 * and the troubleshooting hints mapped from what the edge last refused.
 *
 * P3 exit criteria: received at the edge ≤ 10 s after the first send, and
 * searchable ≤ 2 min after that. The step targets below are those numbers.
 */

import type { EdgeCredentialActivity, IngestCredentialActivity } from '@/lib/api/types';

/** Poll cadence while waiting (the edge is seconds-fresh; the lake ≤ 2 min). */
export const FIRST_EVENT_POLL_MS = 3000;
/** Received-at-edge target (P3). */
export const RECEIVED_TARGET_MS = 10_000;
/** Searchable target after receipt (P3). */
export const SEARCHABLE_TARGET_MS = 120_000;

export type StepState = 'done' | 'active' | 'pending';

export interface FirstEventStep {
  key: 'issued' | 'received' | 'searchable';
  label: string;
  state: StepState;
  at: string | null;
  /** Milliseconds from the previous step's time to this one's, when both are known. */
  elapsedMs: number | null;
  /** Over its P3 target (done late, or still waiting past it). */
  overTarget: boolean;
}

function ms(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  return Number.isNaN(t) ? null : t;
}

/**
 * The three steps. `issuedAt` is the browser's reveal time (the server does
 * not stamp it on the reveal), so issued→received is clamped at zero against
 * clock skew; received→searchable is server time on both ends.
 */
export function firstEventSteps(
  issuedAt: string,
  activity: IngestCredentialActivity | undefined,
  now: number,
): FirstEventStep[] {
  const issued = ms(issuedAt);
  const receivedAt = activity?.first_event.received_at_edge ?? null;
  const searchableAt = activity?.first_event.searchable_at ?? null;
  const received = ms(receivedAt);
  const searchable = ms(searchableAt);
  const gap = (from: number | null, to: number | null) => (from !== null && to !== null ? Math.max(0, to - from) : null);

  // The lake can report searchable before the edge snapshot lands (the edge
  // is recorded by the Bronze publisher poll): then "received" is implied.
  const receivedDone = received !== null || searchable !== null;
  const searchableDone = searchable !== null;
  const receivedElapsed = gap(issued, received);
  const searchableElapsed = gap(received, searchable);
  const waitingSinceReceived = received !== null ? now - received : null;
  return [
    { key: 'issued', label: 'Credential issued', state: 'done', at: issuedAt, elapsedMs: null, overTarget: false },
    {
      key: 'received',
      label: 'First event received at the edge',
      state: receivedDone ? 'done' : 'active',
      at: receivedAt,
      elapsedMs: receivedElapsed,
      // Before anything arrives the clock is the sender's, not ours: no target.
      overTarget: false,
    },
    {
      key: 'searchable',
      label: 'Searchable',
      state: searchableDone ? 'done' : receivedDone ? 'active' : 'pending',
      at: searchableAt,
      elapsedMs: searchableElapsed,
      overTarget: searchableDone
        ? (searchableElapsed ?? 0) > SEARCHABLE_TARGET_MS
        : waitingSinceReceived !== null && waitingSinceReceived > SEARCHABLE_TARGET_MS,
    },
  ];
}

/** `1.2 s`, `42 s`, `3 m 05 s`, `2 h 04 m`. */
export function formatElapsed(msValue: number | null): string {
  if (msValue === null || !Number.isFinite(msValue)) return '—';
  const v = Math.max(0, msValue);
  if (v < 10_000) return `${(v / 1000).toFixed(1)} s`;
  const s = Math.round(v / 1000);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} m ${String(s % 60).padStart(2, '0')} s`;
  return `${Math.floor(m / 60)} h ${String(m % 60).padStart(2, '0')} m`;
}

export type HintTone = 'error' | 'warning' | 'info';

export interface TroubleshootingHint {
  id: string;
  tone: HintTone;
  title: string;
  detail: string;
  /** HEC `code` the sender saw, when the rejection maps to one. */
  hecCode?: number;
  /** Show a link to the source's parser. */
  parserLink?: boolean;
}

/** Hint for the edge's last refusal of this credential (`last_rejection_class` / `_status`). */
export function rejectionHint(edge: Pick<EdgeCredentialActivity, 'last_rejection_class' | 'last_rejection_status'> | null | undefined): TroubleshootingHint | null {
  const cls = edge?.last_rejection_class ?? null;
  const status = edge?.last_rejection_status ?? null;
  if (!cls && status === null) return null;
  if (cls === 'source_not_allowed') {
    return {
      id: 'source_not_allowed', tone: 'error', hecCode: 6,
      title: '403 source_not_allowed: an event declared a source outside the allowlist',
      detail:
        'The whole request was refused and nothing was stored. Make each event declare one of this credential\'s sources (by slug or alias: HEC sourcetype, X-Source-Type, source_type or nano.source), add the name as an alias, or send it with a credential for that source.',
    };
  }
  if (cls === 'source_not_enrolled' || (status === 503 && cls?.includes('enrol'))) {
    return {
      id: 'source_not_enrolled', tone: 'warning',
      title: '503 source_not_enrolled: the source is still rolling out',
      detail:
        'The parser for this source is not live on your parser cell yet, and this edge predates the source hold: senders retry on 503 and events arrive once the rollout finishes. A current edge accepts and holds these events instead. Check the rollout status on the source.',
    };
  }
  if (status === 401 || cls === 'http_401') {
    return {
      id: 'unauthorized', tone: 'error', hecCode: 3,
      title: '401: the token was refused (HEC code 2 token required, 3 invalid authorization)',
      detail:
        'Send the full token: HEC as "Authorization: Splunk <token>", HTTPS and OTLP as "Authorization: Bearer <token>". A revoked credential is refused within about 5 s.',
    };
  }
  if (status === 403) {
    return {
      id: 'wrong_source', tone: 'error', hecCode: 4,
      title: '403: this credential was used for another source (HEC code 4)',
      detail:
        'A per-source credential writes exactly one source. Point this sender at its own source, or issue a credential (or a collector) for the source it sends.',
    };
  }
  if (status === 413) {
    return { id: 'too_large', tone: 'error', title: '413: request too large', detail: 'Lower the sender\'s batch size (max bytes per request).' };
  }
  if (status === 429 || (status === 503 && cls !== null)) {
    return {
      id: 'busy', tone: 'warning', hecCode: 9,
      title: `${status}: the edge was busy`,
      detail: 'The sender should retry with backoff; nothing is lost if it does. Persistent 503s are on our side.',
    };
  }
  if (status === 400) {
    return {
      id: 'invalid_data', tone: 'error', hecCode: 6,
      title: '400: invalid data (HEC code 6)',
      detail: 'The body did not parse for this endpoint: HEC /event expects JSON envelopes with an "event" field; /raw takes lines.',
    };
  }
  return {
    id: 'rejected', tone: 'warning',
    title: `Last request refused${status !== null ? ` (${status})` : ''}${cls ? `: ${cls}` : ''}`,
    detail: 'Check the sender\'s response body; HEC errors carry {"text", "code"}.',
  };
}

/** Every hint for the current activity, most actionable first. */
export function troubleshootingHints(activity: IngestCredentialActivity | undefined, waitingMs: number): TroubleshootingHint[] {
  const hints: TroubleshootingHint[] = [];
  const edge = activity?.edge ?? null;
  const rejection = rejectionHint(edge);
  // A rejection older than the last accepted request no longer blocks.
  const accepted = ms(edge?.last_accepted_at);
  const rejected = ms(edge?.last_rejected_at);
  if (rejection && !(accepted !== null && rejected !== null && accepted > rejected)) hints.push(rejection);
  if ((activity?.lake.parse_failures ?? 0) > 0) {
    hints.push({
      id: 'parse_failures', tone: 'warning', parserLink: true,
      title: `${activity!.lake.parse_failures.toLocaleString()} event${activity!.lake.parse_failures === 1 ? '' : 's'} failed to parse`,
      detail:
        'They are stored and searchable with metadata.parse_error set. Fix the parser with a sample of these events, then publish it.',
    });
  }
  const state = activity?.first_event.state ?? 'waiting';
  if (state === 'waiting' && !rejection && waitingMs > 30_000) {
    hints.push({
      id: 'nothing_yet', tone: 'info',
      title: 'Nothing has reached the edge with this token yet',
      detail:
        'Check the sender is running, its URL is your ingest endpoint above, and it uses this token. A token the edge cannot match (mistyped, truncated) is refused with 401 and cannot be attributed to this credential, so check the sender\'s own log for 401s.',
    });
  }
  if (activity?.redacted) {
    hints.push({
      id: 'redacted', tone: 'info',
      title: 'Some activity is hidden',
      detail: 'This credential writes a source you are restricted from; its counts are withheld.',
    });
  }
  return hints;
}
