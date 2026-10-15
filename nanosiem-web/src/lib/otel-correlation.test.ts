// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import { ocsfTraceLogPredicate, resolveLogTraceId } from './otel-correlation.ts';

test('resolves canonical OCSF trace profile before unmapped and legacy fields', () => {
  assert.equal(
    resolveLogTraceId({
      trace: { uid: 'AABB' },
      unmapped: { trace_id: 'ccdd' },
      trace_id: 'eeff',
    }),
    'aabb',
  );
});

test('resolves generic OCSF Base Event unmapped correlation ids', () => {
  assert.equal(resolveLogTraceId({ unmapped: { trace_id: 'A1B2' } }), 'a1b2');
  assert.equal(resolveLogTraceId({ 'unmapped.trace_id': 'C3D4' }), 'c3d4');
});

test('builds a query over both valid OCSF storage locations', () => {
  assert.equal(
    ocsfTraceLogPredicate('aabb'),
    '(trace.uid="aabb" OR unmapped.trace_id="aabb")',
  );
});
