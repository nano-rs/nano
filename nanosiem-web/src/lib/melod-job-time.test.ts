// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DEFAULT_JOB_MAX_WAIT_MS,
  PARSER_JOB_MAX_WAIT_MS,
  PARSER_JOB_SERVER_TIMEOUT_MS,
  formatElapsed,
  jobTimeoutMessage,
} from './melod-job-time.ts';

test('parser polling outlasts the 25-minute server job ceiling (NAN-4778)', () => {
  assert.equal(PARSER_JOB_SERVER_TIMEOUT_MS, 25 * 60_000);
  assert.ok(PARSER_JOB_MAX_WAIT_MS > PARSER_JOB_SERVER_TIMEOUT_MS);
  // Other wizards wait past their five-minute server ceiling.
  assert.ok(DEFAULT_JOB_MAX_WAIT_MS > 5 * 60_000);
  assert.ok(DEFAULT_JOB_MAX_WAIT_MS < PARSER_JOB_SERVER_TIMEOUT_MS);
});

test('elapsed and timeout lines read naturally', () => {
  assert.equal(formatElapsed(0), '0s');
  assert.equal(formatElapsed(45_400), '45s');
  assert.equal(formatElapsed(192_000), '3m 12s');
  assert.equal(jobTimeoutMessage(PARSER_JOB_MAX_WAIT_MS), 'Job timed out after 30 minutes');
  assert.equal(jobTimeoutMessage(60_000), 'Job timed out after 1 minute');
});
