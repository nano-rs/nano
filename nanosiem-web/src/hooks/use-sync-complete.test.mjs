// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { act, create } from 'react-test-renderer';
import { useSyncCompleteEffect } from './use-sync-complete.ts';

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

test('hook handles accepted 202, stale poll, syncing poll, and result exactly once', async () => {
  const completed = [];
  let accept;
  function Harness({ rows }) {
    accept = useSyncCompleteEffect(rows, 'repo', (repo) => completed.push(repo.last_sync_status));
    return null;
  }
  const old = { id: 'repo', last_sync_status: 'success', last_synced_at: '2026-09-18T00:00:00Z' };
  let root;
  await act(async () => { root = create(React.createElement(Harness, { rows: [old] })); });
  // The mutation receives a 202 with the committed lease's timestamp.
  accept('repo', '2026-09-19T21:20:44Z');
  await act(async () => root.update(React.createElement(Harness, { rows: [{ ...old }] })));
  assert.deepEqual(completed, []);
  await act(async () => root.update(React.createElement(Harness, { rows: [{ ...old, last_sync_status: 'syncing' }] })));
  const done = { ...old, last_synced_at: '2026-09-19T21:21:03Z' };
  await act(async () => root.update(React.createElement(Harness, { rows: [done] })));
  await act(async () => root.update(React.createElement(Harness, { rows: [{ ...done }] })));
  assert.deepEqual(completed, ['success']);
  await act(async () => root.unmount());
});

test('hook reports a fast failed sync even when no syncing poll was observed', async () => {
  const completed = [];
  let accept;
  function Harness({ rows }) {
    accept = useSyncCompleteEffect(rows, 'repo', (repo) => completed.push(repo.last_sync_status));
    return null;
  }
  let root;
  await act(async () => { root = create(React.createElement(Harness, { rows: [] })); });
  accept('repo', '2026-09-19T21:20:44Z');
  await act(async () => root.update(React.createElement(Harness, { rows: [{ id: 'repo', last_sync_status: 'failed', updated_at: '2026-09-19T21:21:03Z' }] })));
  assert.deepEqual(completed, ['failed']);
  await act(async () => root.unmount());
});
