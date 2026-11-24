// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { watchdogReplicaState } from './siemHealthWatchdog';

const base = { reachable: true, hot: false, error: '', sample_age_secs: 20 };

describe('watchdogReplicaState (NAN-5819)', () => {
  it('shows a stale last-known-good sample as stale, never calm', () => {
    expect(watchdogReplicaState({ ...base, sample_age_secs: 3600, stale: true })).toBe(
      'stale (no sample for 3600s)',
    );
  });
  it('keeps the live states', () => {
    expect(watchdogReplicaState(base)).toBe('calm');
    expect(watchdogReplicaState({ ...base, hot: true })).toBe('HOT');
    expect(watchdogReplicaState({ ...base, reachable: false, error: 'refused' })).toBe(
      'unreachable (refused)',
    );
  });
  it('treats reports without the field as fresh', () => {
    expect(watchdogReplicaState({ ...base, stale: undefined })).toBe('calm');
  });
});
