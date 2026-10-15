// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  canonicalSpillFieldName,
  hasObservedSpillValue,
  isSpillFieldName,
  sortFieldStatsByName,
} from './field-rail-policy.ts';

test('keeps canonical OCSF unmapped names single-prefixed', () => {
  assert.equal(canonicalSpillFieldName('unmapped.action', true), 'unmapped.action');
  assert.equal(canonicalSpillFieldName('action', true), 'unmapped.action');
  assert.equal(
    canonicalSpillFieldName('unmapped.unmapped.details.reason', true),
    'unmapped.details.reason',
  );
});

test('recognizes observed spill fields by namespace rather than synthetic origin', () => {
  assert.equal(isSpillFieldName('unmapped.details.reason', true), true);
  assert.equal(isSpillFieldName('actor.process.name', true), false);
  assert.equal(isSpillFieldName('ext.vendor_key', false), true);
});

test('only populated OCSF spill leaves count as observed fields', () => {
  assert.equal(hasObservedSpillValue([]), false);
  assert.equal(hasObservedSpillValue([{ value: '', count: 1000 }]), false);
  assert.equal(hasObservedSpillValue([{ value: '   ', count: 1 }]), false);
  assert.equal(hasObservedSpillValue([{ value: 'false', count: 356 }]), true);
  assert.equal(hasObservedSpillValue([{ value: '0', count: 1 }]), true);
});

test('sorts each field rail section alphabetically without mutating its input', () => {
  const stats = [
    { field: 'enrichments.data.detector' },
    { field: 'action_id' },
    { field: 'action' },
  ];
  assert.deepEqual(
    sortFieldStatsByName(stats).map(({ field }) => field),
    ['action', 'action_id', 'enrichments.data.detector'],
  );
  assert.equal(stats[0].field, 'enrichments.data.detector');
});
