// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import test from 'node:test';

import { eventFieldValue, flattenEventFieldEntries } from './event-field-access.ts';

test('reads canonical fields from flat aggregate and nested raw OCSF rows', () => {
  assert.equal(eventFieldValue({ 'actor.user.name': 'flat' }, 'actor.user.name'), 'flat');
  assert.equal(
    eventFieldValue({ actor: { user: { name: 'nested' } } }, 'actor.user.name'),
    'nested',
  );
});

test('literal dotted projection wins over nested payload', () => {
  const event = {
    'device.hostname': 'projected-host',
    device: { hostname: 'raw-host' },
  };
  assert.equal(eventFieldValue(event, 'device.hostname'), 'projected-host');
});

test('reads and flattens canonical leaves through repeated OCSF objects', () => {
  const event = {
    actor: { process: { name: 'pwsh.exe' } },
    file: {
      hashes: [
        { algorithm_id: 3, value: 'abc' },
        { algorithm_id: 4, value: 'def' },
      ],
    },
  };
  assert.deepEqual(eventFieldValue(event, 'file.hashes.value'), ['abc', 'def']);
  assert.deepEqual(
    flattenEventFieldEntries(event),
    [
      { key: 'actor.process.name', value: 'pwsh.exe' },
      { key: 'file.hashes.algorithm_id', value: [3, 4] },
      { key: 'file.hashes.value', value: ['abc', 'def'] },
    ],
  );
});
