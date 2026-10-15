// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  RepositorySyncTracker,
  platformCatalogSettingUp,
  platformCatalogSetupBlocksPage,
  repositorySyncPollInterval,
} from './repository-sync-state.ts';
const start = '2026-09-19T21:20:44Z';
const end = '2026-09-19T21:21:03Z';
test('202 acceptance followed by syncing and terminal poll completes once', () => {
  const tracker = new RepositorySyncTracker();
  tracker.start('repo', start);
  const syncing = { id: 'repo', last_sync_status: 'syncing', sync_started_at: start };
  assert.equal(repositorySyncPollInterval([syncing], Date.parse(end)), 1500);
  assert.equal(tracker.observe(syncing), false);
  const done = { ...syncing, last_sync_status: 'success', last_synced_at: end };
  assert.equal(tracker.observe(done), true);
  assert.equal(tracker.observe(done), false);
  assert.equal(repositorySyncPollInterval([done]), false);
});
test('fast sync completes without observing syncing; stale poll is ignored', () => {
  const tracker = new RepositorySyncTracker();
  tracker.start('repo', start);
  assert.equal(tracker.observe({ id: 'repo', last_sync_status: 'success', last_synced_at: '2026-09-18T00:00:00Z' }), false);
  assert.equal(tracker.observe({ id: 'repo', last_sync_status: 'success', last_synced_at: end }), true);
});
test('failed completion and independent repositories', () => {
  const tracker = new RepositorySyncTracker();
  tracker.start('one', start);
  assert.equal(tracker.observe({ id: 'two', last_sync_status: 'success', last_synced_at: end }), false);
  assert.equal(tracker.observe({ id: 'one', last_sync_status: 'failed', updated_at: end }), true);
});
test('polling has a 65 minute upper bound', () => {
  assert.equal(repositorySyncPollInterval([{ id: 'repo', last_sync_status: 'syncing', sync_started_at: start }], Date.parse(start) + 65 * 60_000), false);
});

test('NAN-3436: a new shared tenant sees its platform catalog as setting up, never as empty', () => {
  const rules = 'nano-rs/rules' as const;
  // Before the background follow creates the row.
  assert.equal(platformCatalogSettingUp(true, [], rules), true);
  assert.equal(platformCatalogSetupBlocksPage(true, [], rules), true);
  // Row created, first sync in flight.
  const creating = { id: 'r', url: 'https://github.com/nano-rs/rules', last_sync_status: 'syncing', last_synced_at: null };
  assert.equal(platformCatalogSettingUp(true, [creating], rules), true);
  // URL spelling variants still match.
  const variant = { ...creating, url: 'https://GitHub.com/Nano-RS/Rules.git/' };
  assert.equal(platformCatalogSettingUp(true, [variant], rules), true);
  // Synced, or a recorded failure (shown by the normal page), is not setting up.
  assert.equal(platformCatalogSettingUp(true, [{ ...creating, last_sync_status: 'success', last_synced_at: end }], rules), false);
  assert.equal(platformCatalogSettingUp(true, [{ ...creating, last_sync_status: 'failed' }], rules), false);
  // Another catalog's row is not this one.
  const parsers = { ...creating, url: 'https://github.com/nano-rs/parsers', last_synced_at: end };
  assert.equal(platformCatalogSettingUp(true, [parsers], rules), true);
  // A tenant with other synced content keeps the normal page.
  assert.equal(platformCatalogSetupBlocksPage(true, [parsers], rules), false);
  // Dedicated deployments never show it.
  assert.equal(platformCatalogSettingUp(false, [], rules), false);
});
