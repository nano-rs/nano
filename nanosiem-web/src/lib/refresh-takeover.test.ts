// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import {
  broadcastSessionReplacement,
  coordinateBrowserRefresh,
  refreshCoordinationNames,
  tenantCookieSlot,
} from './refresh-coordinator.ts';
import { SessionCredentials } from './session-credentials.ts';
import { requestCredentials } from './request-credentials.ts';

function mockLocks(t: TestContext, locks: Locks | undefined): void {
  const values = new Map<string, string>();
  const originalStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
  } });
  t.after(() => {
    if (originalStorage) Object.defineProperty(globalThis, 'localStorage', originalStorage);
    else Reflect.deleteProperty(globalThis, 'localStorage');
  });
  const original = Object.getOwnPropertyDescriptor(navigator, 'locks');
  Object.defineProperty(navigator, 'locks', { configurable: true, value: locks });
  t.after(() => {
    if (original) Object.defineProperty(navigator, 'locks', original);
    else Reflect.deleteProperty(navigator, 'locks');
  });
}

/** Models Web Locks including rejection of the previous request on steal.
 * BroadcastChannel is Node's actual asynchronous channel implementation. */
class Locks {
  holders = new Map<string, { reject: (error: Error) => void }>();
  steals = 0;
  request(name: string, options: LockOptions, callback: (lock: Lock | null) => unknown): Promise<unknown> {
    if (options.steal) {
      this.steals++;
      this.holders.get(name)?.reject(new DOMException('Lock stolen', 'AbortError'));
      this.holders.delete(name);
    }
    if (this.holders.has(name)) return Promise.resolve(callback(null));
    return new Promise((resolve, reject) => {
      const owner = { reject };
      this.holders.set(name, owner);
      Promise.resolve().then(() => callback({ name, mode: 'exclusive' })).then(resolve, reject).finally(() => {
        if (this.holders.get(name) === owner) this.holders.delete(name);
      });
    });
  }
}

test('dead leader is replaced by one follower; queued API calls use its credential', async t => {
  const locks = new Locks();
  mockLocks(t, locks);
  const scopeKey = 'enterprise_shared:takeover:user';
  const lockName = refreshCoordinationNames(scopeKey).lockName;
  // The elected tab is suspended mid-fetch and never publishes or releases.
  const leader = locks.request(lockName, {}, () => new Promise(() => {})).catch(() => undefined);
  void leader;
  let calls = 0;
  let token: string | null = null;
  const gate = new SessionCredentials(() => token);
  const refresh = () => coordinateBrowserRefresh(async () => {
    calls++;
    await new Promise(resolve => setTimeout(resolve, 10));
    return 'fresh';
  }, { scopeKey, timeoutMs: 80 });
  gate.configure(() => gate.runRefresh(async () => { token = await refresh(); return true; }), null);
  const sent: string[] = [];
  const started = Date.now();
  const queued = Array.from({ length: 12 }, async () => {
    const credential = await gate.credential();
    requestCredentials('/api/dashboards', { Authorization: `Bearer ${credential}` });
    sent.push(credential);
  });
  // Another waiting tab must not steal the replacement leader's lock.
  const sibling = refresh();
  await Promise.all([...queued, sibling]);
  assert.deepEqual(sent, Array(12).fill('fresh'));
  assert.equal(calls, 1);
  assert.equal(locks.steals, 1);
  assert.ok(Date.now() - started < 1000);
});

test('BroadcastChannel fallback elects one simultaneous refresh winner without Locks', async t => {
  mockLocks(t, undefined);
  let calls = 0;
  const refresh = () => coordinateBrowserRefresh(async () => {
    calls++;
    await new Promise(resolve => setTimeout(resolve, 20));
    return 'fallback-token';
  }, { scopeKey: 'fallback', requireCoordination: true, timeoutMs: 200 });
  assert.deepEqual(await Promise.all([refresh(), refresh()]), ['fallback-token', 'fallback-token']);
  assert.equal(calls, 1);
});

test('a slow leader timeout is observed and does not emit an unhandled rejection', async t => {
  const locks = new Locks();
  mockLocks(t, locks);
  await assert.rejects(coordinateBrowserRefresh(async () => {
    await new Promise(resolve => setTimeout(resolve, 40));
    return 'stale';
  }, { scopeKey: 'slow', timeoutMs: 20 }), /Timed out/);
});

test('a replacement leader can also disappear without holding the election lock', async t => {
  const locks = new Locks();
  mockLocks(t, locks);
  const scopeKey = 'replacement-disappears';
  const lockName = refreshCoordinationNames(scopeKey).lockName;
  void locks.request(lockName, {}, () => new Promise(() => {})).catch(() => undefined);
  let started!: () => void;
  const replacing = new Promise<void>(resolve => { started = resolve; });
  const first = coordinateBrowserRefresh(async () => {
    started();
    return new Promise<string>(() => {});
  }, { scopeKey, timeoutMs: 40 }).catch(error => error);
  await replacing;
  const result = await coordinateBrowserRefresh(async () => 'second-takeover', { scopeKey, timeoutMs: 80 });
  assert.equal(result, 'second-takeover');
  assert.equal(locks.steals, 2);
  assert.equal((await first).name, 'AbortError');
});

test('BroadcastChannel follower takes over an expired, disappeared leader lease', async t => {
  mockLocks(t, undefined);
  const scopeKey = 'fallback-dead';
  const channel = new BroadcastChannel(`${refreshCoordinationNames(scopeKey).lockName}:lease`);
  t.after(() => channel.close());
  const expiresAt = Date.now() + 100;
  channel.onmessage = event => {
    if (event.data.kind === 'claim') {
      channel.postMessage({ kind: 'held', id: 'dead-leader', expiresAt });
      channel.close();
    }
  };
  let calls = 0;
  assert.equal(await coordinateBrowserRefresh(async () => {
    calls++;
    return 'recovered';
  }, { scopeKey, timeoutMs: 150 }), 'recovered');
  assert.equal(calls, 1);
});

test('NAN-3548: a stuck acme refresh never delays or blocks a globex refresh', async t => {
  const locks = new Locks();
  mockLocks(t, locks);
  const acme = { scopeKey: 'enterprise_shared:tenant-acme:user-ann', cookieSlot: tenantCookieSlot('acme') };
  const globex = { scopeKey: 'enterprise_shared:tenant-globex:user-ann', cookieSlot: tenantCookieSlot('globex') };
  // acme's leader is suspended mid-rotation and holds acme's cookie lock.
  void locks.request(
    refreshCoordinationNames(acme.scopeKey, acme.cookieSlot).lockName,
    {},
    () => new Promise(() => {}),
  ).catch(() => undefined);
  const started = Date.now();
  const token = await coordinateBrowserRefresh(async () => 'globex-access', {
    ...globex, requireCoordination: true, timeoutMs: 5_000,
  });
  assert.equal(token, 'globex-access');
  assert.equal(locks.steals, 0, 'globex must not steal acme\'s lock');
  assert.ok(Date.now() - started < 1_000, 'no wait on another tenant\'s leader');
});

test("NAN-3548: an acme sign-in/refresh signal does not abort a waiting globex follower", async t => {
  const locks = new Locks();
  mockLocks(t, locks);
  const acme = { scopeKey: 'enterprise_shared:tenant-acme:user-ann', cookieSlot: tenantCookieSlot('acme') };
  const globex = { scopeKey: 'enterprise_shared:tenant-globex:user-ann', cookieSlot: tenantCookieSlot('globex') };
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  let calls = 0;
  const leader = coordinateBrowserRefresh(async () => {
    calls++;
    await gate;
    return 'globex-access';
  }, { ...globex, requireCoordination: true, timeoutMs: 2_000 });
  await new Promise(resolve => setTimeout(resolve, 10));
  const follower = coordinateBrowserRefresh(async () => {
    calls++;
    return 'unexpected-second-rotation';
  }, { ...globex, requireCoordination: true, timeoutMs: 2_000 });
  await new Promise(resolve => setTimeout(resolve, 10));
  // The acme tab signs in / refreshes while globex's refresh is in flight.
  broadcastSessionReplacement(acme.scopeKey, acme.cookieSlot);
  await new Promise(resolve => setTimeout(resolve, 20));
  release();
  assert.deepEqual(await Promise.all([leader, follower]), ['globex-access', 'globex-access']);
  assert.equal(calls, 1);
});

test('NAN-3548: a same-tenant replacement still aborts a waiting follower (fail closed)', async t => {
  const locks = new Locks();
  mockLocks(t, locks);
  const slot = tenantCookieSlot('acme');
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const leader = coordinateBrowserRefresh(async () => {
    await gate;
    return 'ann-access';
  }, { scopeKey: 'enterprise_shared:tenant-acme:user-ann', cookieSlot: slot, timeoutMs: 2_000 });
  await new Promise(resolve => setTimeout(resolve, 10));
  const follower = coordinateBrowserRefresh(async () => 'never', {
    scopeKey: 'enterprise_shared:tenant-acme:user-ann', cookieSlot: slot, timeoutMs: 2_000,
  });
  await new Promise(resolve => setTimeout(resolve, 10));
  broadcastSessionReplacement('enterprise_shared:tenant-acme:user-eve', slot);
  await assert.rejects(follower, /different tenant session replaced/);
  release();
  assert.equal(await leader, 'ann-access');
});
