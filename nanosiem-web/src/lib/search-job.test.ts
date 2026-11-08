// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  isDurableJobId,
  isPageInStoredRange,
  jobFailureCode,
  jobPollPolicy,
  nextContinuationPage,
  pageableRowCount,
} from './search-job.ts';

test('durable job ids are recognized by their typeid prefix only', () => {
  assert.equal(isDurableJobId('sjob_01m6fxjhhqew08797yz9r82jrg'), true);
  assert.equal(isDurableJobId('0198f7a2-3c1d-7e4b-9a0f-123456789abc'), false);
  assert.equal(isDurableJobId('sjobx_abc'), false);
});

test('durable jobs are polled without the legacy 5-minute cutoff', () => {
  assert.equal(jobPollPolicy('sjob_01m6fxjhhqew08797yz9r82jrg').maxPolls, Number.POSITIVE_INFINITY);
  assert.deepEqual(jobPollPolicy('0198f7a2-3c1d-7e4b-9a0f-123456789abc'), { intervalMs: 1000, maxPolls: 300 });
});

test('job failures map to typed codes, parse errors first', () => {
  assert.equal(jobFailureCode('Query parse error: Unexpected token', 'invalid_query'), 'PARSE_ERROR');
  assert.equal(jobFailureCode('Search exceeded the background job time limit', 'timeout'), 'JOB_TIMEOUT');
  assert.equal(jobFailureCode('lost', 'worker_lost'), 'JOB_WORKER_LOST');
  assert.equal(jobFailureCode('boom', undefined), 'JOB_FAILED');
});

test('continuation pages stop at the stored row count, not the total match count', () => {
  assert.deepEqual(nextContinuationPage(0, 97, 50), { offset: 0, limit: 50 });
  assert.deepEqual(nextContinuationPage(50, 97, 50), { offset: 50, limit: 47 });
  assert.equal(nextContinuationPage(97, 97, 50), null);
  // A truncated job (100k stored of 2M matched) never asks past row 100k.
  assert.equal(nextContinuationPage(100_000, 100_000, 50), null);
  assert.equal(nextContinuationPage(0, 10, 0), null);
});

test('a truncated job only offers pages over its stored rows', () => {
  // 500k matched, 100k stored: the paginator is bounded to 100k.
  assert.equal(pageableRowCount(500_000, 100_000, true), 100_000);
  assert.equal(pageableRowCount(97, 97, false), 97);
  assert.equal(isPageInStoredRange(0, 0), true, 'the empty first page of a zero-row job is valid');
  assert.equal(isPageInStoredRange(99_950, 100_000), true);
  assert.equal(isPageInStoredRange(100_000, 100_000), false);
  assert.equal(isPageInStoredRange(50_000_000, 100_000), false);
});
