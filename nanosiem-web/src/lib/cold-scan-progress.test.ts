// SPDX-License-Identifier: AGPL-3.0-or-later

/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  backgroundJobPhaseLabel, coldScanLabel, formatJobElapsed, hasMeasuredProgress, isColdScanProgress,
} from './cold-scan-progress.ts';

const base = { rows_scanned: 0, rows_total: 0, percent: 0, elapsed_ms: 0 };

test('only cold_scan progress is a cold read', () => {
  assert.equal(isColdScanProgress({ ...base, phase: 'cold_scan' }), true);
  assert.equal(isColdScanProgress({ ...base, rows_scanned: 10 }), false);
  assert.equal(isColdScanProgress(null), false);
});

test('a queued read says it is queued, not failed', () => {
  assert.equal(coldScanLabel({ ...base, phase: 'cold_scan', queued: true, cold_bytes_read: 0, cold_bytes_total: 0 }),
    'Queued behind another cold-data scan…');
});

test('a fetching read shows bytes read of the expected total', () => {
  assert.equal(coldScanLabel({ ...base, phase: 'cold_scan', cold_bytes_read: 1_000_000_000, cold_bytes_total: 2_200_000_000 }),
    'Scanning cold data… 1.0 of 2.2 GB');
  assert.equal(coldScanLabel({ ...base, phase: 'cold_scan', cold_bytes_read: 30_000_000_000, cold_bytes_total: 25_000_000_000 }),
    'Scanning cold data… 25 of 25 GB');
  assert.equal(coldScanLabel({ ...base, phase: 'cold_scan' }), 'Scanning cold data…');
});

test('NAN-3883: a phase-only durable job has no measure; rows, percent or cold bytes do', () => {
  assert.equal(hasMeasuredProgress({ ...base, phase: 'scanning', attempt: 1 }), false);
  assert.equal(hasMeasuredProgress(null), false);
  assert.equal(hasMeasuredProgress({ ...base, rows_total: 10 }), true);
  assert.equal(hasMeasuredProgress({ ...base, percent: 40 }), true);
  assert.equal(hasMeasuredProgress({ ...base, phase: 'cold_scan', cold_bytes_total: 5 }), true);
  assert.equal(hasMeasuredProgress({ ...base, phase: 'cold_scan' }), false);
});

test('NAN-3883: a background job names its phase and a retry', () => {
  assert.equal(backgroundJobPhaseLabel({ ...base, phase: 'scanning', attempt: 1 }), 'Scanning in the background…');
  assert.equal(backgroundJobPhaseLabel({ ...base, phase: 'scanning', attempt: 2 }), 'Scanning in the background (attempt 2)…');
  assert.equal(backgroundJobPhaseLabel({ ...base, phase: 'publishing_result' }), 'Writing results…');
  assert.equal(backgroundJobPhaseLabel(null), 'Running in the background…');
  assert.equal(backgroundJobPhaseLabel({ ...base, phase: 'retrying_2', attempt: 1 }), 'Cold data was slow to load; retrying (2)…');
  assert.equal(formatJobElapsed(47_400), '47s');
  assert.equal(formatJobElapsed(125_000), '2m 05s');
  assert.equal(formatJobElapsed(3_900_000), '1h 05m');
});
