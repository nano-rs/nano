// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-2607: rollout state vocabulary, polling and timing formatting. */
import { describe, expect, it } from 'vitest';
import type { TenantParserRollout } from '@/lib/api/types';
import {
  ROLLOUT_STEPS,
  failureStageLabel,
  formatDurationMs,
  formatStageTimings,
  isTerminal,
  latestRolloutFor,
  parserServingState,
  rolloutFailureText,
  rolloutPollInterval,
  rolloutStateLabel,
  rolloutStepIndex,
  shortSha,
} from './parser-rollout';

const base = { failure_stage: null, roll_id: null } as const;

describe('parser rollout vocabulary', () => {
  it('orders the happy path and labels every state', () => {
    expect(ROLLOUT_STEPS).toEqual(['pending', 'building', 'validated', 'rolling', 'live']);
    expect(ROLLOUT_STEPS.map(rolloutStateLabel)).toEqual(['Queued', 'Building', 'Validated', 'Rolling out', 'Live']);
    expect(rolloutStateLabel('failed')).toBe('Failed');
    expect(rolloutStateLabel('rolled_back')).toBe('Rolled back');
    expect(rolloutStateLabel('something_new')).toBe('something new');
  });

  it('knows terminal states and polls only while moving', () => {
    expect(isTerminal({ state: 'live' })).toBe(true);
    expect(isTerminal({ state: 'failed' })).toBe(true);
    expect(isTerminal({ state: 'rolled_back' })).toBe(true);
    expect(isTerminal({ state: 'rolling' })).toBe(false);
    expect(isTerminal(undefined)).toBe(false);
    expect(rolloutPollInterval({ state: 'building' })).toBe(3000);
    expect(rolloutPollInterval({ state: 'live' })).toBe(false);
    expect(rolloutPollInterval([{ state: 'live' }, { state: 'pending' }])).toBe(3000);
    expect(rolloutPollInterval([{ state: 'live' }, { state: 'failed' }])).toBe(false);
    expect(rolloutPollInterval(undefined)).toBe(3000);
  });

  it('places failures on the step they stopped at', () => {
    expect(rolloutStepIndex({ ...base, state: 'rolling' })).toBe(3);
    expect(rolloutStepIndex({ ...base, state: 'failed', failure_stage: 'vector_validate' })).toBe(1);
    expect(rolloutStepIndex({ ...base, state: 'failed', failure_stage: 'sign' })).toBe(2);
    expect(rolloutStepIndex({ ...base, state: 'failed', failure_stage: 'verify' })).toBe(3);
    expect(rolloutStepIndex({ ...base, state: 'rolled_back' })).toBe(3);
  });

  it('labels NAN-2604 failure stages', () => {
    expect(failureStageLabel('vector_validate')).toBe('vector validate');
    expect(failureStageLabel('structural_guard')).toBe('structural guard');
    expect(failureStageLabel('render')).toBe('worker render');
    expect(failureStageLabel('odd_stage')).toBe('odd stage');
    expect(failureStageLabel(null)).toBeNull();
  });

  it('formats durations and stage timings in pipeline order', () => {
    expect(formatDurationMs(850)).toBe('850ms');
    expect(formatDurationMs(1200)).toBe('1.2s');
    expect(formatDurationMs(12_400)).toBe('12.4s');
    expect(formatDurationMs(125_000)).toBe('2m 05s');
    expect(formatDurationMs(-1)).toBe('—');
    expect(formatStageTimings({ build_ms: 1200, queue_ms: 400, verify_ms: 61_000, note: 'x' })).toEqual([
      ['queue', '400ms'], ['build', '1.2s'], ['verify', '1m 01s'],
    ]);
    expect(formatStageTimings(null)).toEqual([]);
  });

  it('shortens digests and finds the newest rollout of a source', () => {
    expect(shortSha('sha256:' + 'ab'.repeat(32), 8)).toBe('abababab');
    expect(shortSha(null)).toBe('—');
    const rows = [
      { log_source_id: 'lsrc_a', requested_at: '2026-09-22T10:00:00Z', id: '1' },
      { log_source_id: 'lsrc_a', requested_at: '2026-09-22T11:00:00Z', id: '2' },
      { log_source_id: 'lsrc_b', requested_at: '2026-09-22T12:00:00Z', id: '3' },
    ] as TenantParserRollout[];
    expect(latestRolloutFor(rows, 'lsrc_a')?.id).toBe('2');
    expect(latestRolloutFor(rows, 'lsrc_c')).toBeUndefined();
  });
});

describe('parserServingState (NAN-3298)', () => {
  const r = (
    id: string,
    version: number,
    state: TenantParserRollout['state'],
    requestedAt: string,
    extra: Partial<TenantParserRollout> = {},
  ): TenantParserRollout =>
    ({
      id,
      kind: 'publish',
      state,
      log_source_id: 'lsrc_a',
      log_source_version_ids: [`pub-${version}`],
      version_numbers: [version],
      base_offer_id: null,
      requested_by: 'u',
      requested_at: requestedAt,
      request_reason: null,
      state_revision: 1,
      roll_id: null,
      bundle_revision: null,
      content_sha256: null,
      report_sha256: null,
      failure_reason: null,
      failure_component: null,
      failure_stage: null,
      stage_timings: null,
      updated_at: requestedAt,
      completed_at: isTerminal({ state }) ? requestedAt.replace(':00Z', ':40Z') : null,
      terminal: isTerminal({ state }),
      ...extra,
    }) as TenantParserRollout;

  const v1Live = r('r1', 1, 'live', '2026-10-07T10:00:00Z');
  const v2RolledBack = r('r2', 2, 'rolled_back', '2026-10-08T13:16:00Z', {
    failure_reason: 'Parser bundle roll failed roll-safety: verify:probe 503; previous Cloudflare version restored',
    failure_stage: 'verify',
  });

  it('a rolled-back newer version is not serving; the last promoted one is', () => {
    const s = parserServingState([v2RolledBack, v1Live], v1Live, 2);
    expect(s).toMatchObject({ tracked: true, servingVersion: 1, servingSince: v1Live.completed_at, inFlight: null });
    expect(s.failed?.id).toBe('r2');
    expect(rolloutFailureText(s.failed!)).toBe(
      'verify: Parser bundle roll failed roll-safety: verify:probe 503; previous Cloudflare version restored',
    );
  });

  it('a rollout in progress shows as in flight while the previous version keeps serving', () => {
    const s = parserServingState([r('r2', 2, 'rolling', '2026-10-08T13:16:00Z'), v1Live], v1Live, 2);
    expect(s).toMatchObject({ servingVersion: 1, failed: null });
    expect(s.inFlight?.id).toBe('r2');
  });

  it('the newest rollout live means that version serves', () => {
    const v2Live = r('r2', 2, 'live', '2026-10-08T13:16:00Z');
    expect(parserServingState([v2Live, v1Live], v2Live, 2)).toMatchObject({
      servingVersion: 2,
      servingSince: v2Live.completed_at,
      inFlight: null,
      failed: null,
    });
  });

  it('a later live roll of another source carries the active version (bundles build from active versions)', () => {
    const other = { ...r('rX', 7, 'live', '2026-10-08T14:00:00Z'), log_source_id: 'lsrc_b' };
    expect(parserServingState([v2RolledBack, v1Live], other, 2)).toMatchObject({
      servingVersion: 2,
      servingSince: other.completed_at,
      failed: null,
    });
  });

  it('nothing live yet: no serving version', () => {
    const s = parserServingState([r('r1', 1, 'failed', '2026-10-08T13:16:00Z', { failure_reason: 'vector test failed' })], null, 1);
    expect(s).toMatchObject({ tracked: true, servingVersion: null, servingSince: null });
    expect(s.failed?.id).toBe('r1');
  });

  it('untracked when there are no rollouts or the active version filed none', () => {
    expect(parserServingState([], null, 1).tracked).toBe(false);
    expect(parserServingState(undefined, null, undefined).tracked).toBe(false);
    expect(parserServingState([v1Live], v1Live, 3).tracked).toBe(false);
    expect(parserServingState([{ ...v1Live, version_numbers: undefined }], v1Live, 1).tracked).toBe(false);
  });
});
