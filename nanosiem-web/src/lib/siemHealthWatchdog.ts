// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5819: one watchdog replica's coverage state. A stale latest sample is old
 * evidence, shown as stale whatever it last said (never "calm").
 */
export function watchdogReplicaState(replica: {
  reachable: boolean;
  hot: boolean;
  error: string;
  sample_age_secs: number;
  stale?: boolean;
}): string {
  if (replica.stale) return `stale (no sample for ${replica.sample_age_secs}s)`;
  if (!replica.reachable) return `unreachable (${replica.error})`;
  return replica.hot ? 'HOT' : 'calm';
}
