// SPDX-License-Identifier: AGPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { atPath, firstStringAt, firstBoolAt } from './row-path.ts';

/** The exact shape a lake ImageLoad (Sysmon event ID 7) row returns. */
const IMAGE_LOAD_ROW = {
  class_uid: 1005,
  device: { hostname: 'ws-hr-032.corp.local' },
  module: {
    file: {
      name: 'kernel32.dll',
      signatures: [
        {
          algorithm: 'Authenticode',
          algorithm_id: 4,
          developer_uid: 'Microsoft Windows',
          state: 'Valid',
          state_id: 1,
        },
      ],
    },
  },
};

/** The same query projected through `| table`, i.e. flat dotted keys. */
const FLAT_ROW = {
  'device.hostname': 'ws-hr-032.corp.local',
  'process.file.name': 'msedge.exe',
};

test('nested OCSF paths resolve', () => {
  assert.equal(atPath(IMAGE_LOAD_ROW, 'device.hostname'), 'ws-hr-032.corp.local');
  assert.equal(atPath(IMAGE_LOAD_ROW, 'module.file.name'), 'kernel32.dll');
});

test('flat dotted keys resolve through the same accessor', () => {
  assert.equal(atPath(FLAT_ROW, 'device.hostname'), 'ws-hr-032.corp.local');
  assert.equal(atPath(FLAT_ROW, 'process.file.name'), 'msedge.exe');
});

test('plural signature arrays are traversed element-wise', () => {
  // The bug this file exists for: OCSF stores code signing in `signatures[]`,
  // and the old flat `row['file.signature.state']` lookup could never reach it.
  assert.equal(atPath(IMAGE_LOAD_ROW, 'module.file.signatures.state'), 'Valid');
  assert.equal(
    atPath(IMAGE_LOAD_ROW, 'module.file.signatures.developer_uid'),
    'Microsoft Windows',
  );
});

test('the signer is developer_uid, not certificate.subject', () => {
  const signer = firstStringAt(IMAGE_LOAD_ROW, [
    'module.file.signatures.developer_uid',
    'module.file.signatures.certificate.subject',
  ]);
  assert.equal(signer, 'Microsoft Windows');
});

test('a Valid state reads as signed', () => {
  assert.equal(firstBoolAt(IMAGE_LOAD_ROW, ['module.file.signatures.state']), true);
});

test('unrecognised verdicts stay undefined rather than reading as unsigned', () => {
  for (const state of ['Expired', 'Untrusted', 'Revoked']) {
    const row = { file: { signatures: [{ state }] } };
    assert.equal(
      firstBoolAt(row, ['file.signatures.state']),
      undefined,
      `${state} must not be coerced to unsigned`,
    );
  }
  assert.equal(firstBoolAt({ file: { signatures: [{ state: 'Unsigned' }] } }, ['file.signatures.state']), false);
});

test('a ProcessCreate row carries no signature at all', () => {
  // Sysmon emits signature fields only on ImageLoad by default, so the rows
  // that become tree NODES have nothing to show — "not collected", not
  // "unsigned".
  const processCreate = {
    class_uid: 1007,
    process: { file: { name: 'msedge.exe', path: 'C:\\msedge.exe' }, uid: '{a}' },
  };
  assert.equal(atPath(processCreate, 'process.file.signatures.state'), undefined);
  assert.equal(firstBoolAt(processCreate, ['process.file.signatures.state']), undefined);
});

test('missing and malformed input never throws', () => {
  assert.equal(atPath(undefined, 'a.b'), undefined);
  assert.equal(atPath(null, 'a.b'), undefined);
  assert.equal(atPath('scalar', 'a.b'), undefined);
  assert.equal(atPath({ a: 1 }, ''), undefined);
  assert.equal(firstStringAt({}, ['a.b']), undefined);
});
