// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />
import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { coordinateBrowserRefresh, REFRESH_LOCK_NAME } from './refresh-coordinator.ts';
import { SessionCredentials } from './session-credentials.ts';

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
 * BroadcastChannel is Node's real asynchronous channel implementation, so
 * every "tab" below talks over an actual channel. */
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
      Promise.resolve().then(() => callback({ name, mode: 'exclusive' } as Lock)).then(resolve, reject).finally(() => {
        if (this.holders.get(name) === owner) this.holders.delete(name);
      });
    });
  }
}

/** The server's single-use refresh cookie: compare-and-swap rotation, so a
 * second presentation of the same cookie is refused (base auth service). */
class RotatingCookieServer {
  private cookie = 'refresh-0';
  private generation = 0;
  calls = 0;
  rejected = 0;
  async refresh(presented: string): Promise<string> {
    this.calls++;
    await new Promise(resolve => setTimeout(resolve, 15));
    if (presented !== this.cookie) {
      this.rejected++;
      throw new Error('401 invalid refresh token');
    }
    this.generation++;
    this.cookie = `refresh-${this.generation}`;
    return `access-${this.generation}`;
  }
  current(): string { return this.cookie; }
}

test('multi-tab refresh race: one rotation, every tab keeps its session, no logout', async t => {
  mockLocks(t, new Locks());
  const server = new RotatingCookieServer();
  let prompts = 0;
  // Four tabs, each with its own in-memory bearer and request gate, sharing
  // the origin's cookie jar. All of their access tokens expire together.
  const tabs = Array.from({ length: 4 }, () => {
    let token: string | null = null;
    const gate = new SessionCredentials(() => token);
    const refresh = () => gate.runRefresh(async () => {
      token = await coordinateBrowserRefresh(
        () => server.refresh(server.current()),
        { timeoutMs: 500 },
      );
      return true;
    });
    gate.configure(refresh, () => { prompts++; });
    return gate;
  });
  const credentials = await Promise.all(tabs.flatMap(gate => [gate.credential(), gate.credential()]));
  assert.equal(server.calls, 1, 'exactly one tab presents the single-use cookie');
  assert.equal(server.rejected, 0);
  assert.deepEqual(credentials, Array(8).fill('access-1'));
  assert.equal(prompts, 0, 'no tab is logged out');
});

test('dead leader is replaced by one follower; queued API calls use its credential', async t => {
  const locks = new Locks();
  mockLocks(t, locks);
  // The elected tab is suspended mid-fetch and never publishes or releases.
  void locks.request(REFRESH_LOCK_NAME, {}, () => new Promise(() => {})).catch(() => undefined);
  let calls = 0;
  let token: string | null = null;
  const gate = new SessionCredentials(() => token);
  const refresh = () => coordinateBrowserRefresh(async () => {
    calls++;
    await new Promise(resolve => setTimeout(resolve, 10));
    return 'fresh';
  }, { timeoutMs: 80 });
  gate.configure(() => gate.runRefresh(async () => { token = await refresh(); return true; }), null);
  const started = Date.now();
  const queued = Array.from({ length: 12 }, () => gate.credential());
  // Another waiting tab must not steal the replacement leader's lock.
  const sibling = refresh();
  const [sent] = await Promise.all([Promise.all(queued), sibling]);
  assert.deepEqual(sent, Array(12).fill('fresh'));
  assert.equal(calls, 1);
  assert.equal(locks.steals, 1);
  assert.ok(Date.now() - started < 1000);
});

test('BroadcastChannel fallback (no Web Locks, e.g. http origin) elects one winner', async t => {
  mockLocks(t, undefined);
  let calls = 0;
  const refresh = () => coordinateBrowserRefresh(async () => {
    calls++;
    await new Promise(resolve => setTimeout(resolve, 20));
    return 'fallback-token';
  }, { timeoutMs: 200 });
  assert.deepEqual(await Promise.all([refresh(), refresh()]), ['fallback-token', 'fallback-token']);
  assert.equal(calls, 1);
});

test('a slow leader times out instead of publishing a stale result', async t => {
  mockLocks(t, new Locks());
  await assert.rejects(coordinateBrowserRefresh(async () => {
    await new Promise(resolve => setTimeout(resolve, 40));
    return 'stale';
  }, { timeoutMs: 20 }), /Timed out/);
});

test('a replacement leader can also disappear', async t => {
  const locks = new Locks();
  mockLocks(t, locks);
  void locks.request(REFRESH_LOCK_NAME, {}, () => new Promise(() => {})).catch(() => undefined);
  let started!: () => void;
  const replacing = new Promise<void>(resolve => { started = resolve; });
  const first = coordinateBrowserRefresh(async () => {
    started();
    return new Promise<string>(() => {});
  }, { timeoutMs: 40 }).catch(error => error);
  await replacing;
  const result = await coordinateBrowserRefresh(async () => 'second-takeover', { timeoutMs: 80 });
  assert.equal(result, 'second-takeover');
  assert.equal(locks.steals, 2);
  assert.equal((await first).name, 'AbortError');
});

test('BroadcastChannel follower takes over an expired, disappeared leader lease', async t => {
  mockLocks(t, undefined);
  const channel = new BroadcastChannel(`${REFRESH_LOCK_NAME}:lease`);
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
  }, { timeoutMs: 150 }), 'recovered');
  assert.equal(calls, 1);
});

test('only the access token crosses tabs', async () => {
  const { accessOnlyRefreshResult } = await import('./refresh-coordinator.ts');
  assert.deepEqual(
    accessOnlyRefreshResult({ access_token: 'a', expires_in: 900, refresh_token: 'secret' }),
    { access_token: 'a', expires_in: 900 },
  );
});

/** BroadcastChannel whose delivery is delayed past the 50 ms election window
 * (a busy or throttled renderer): the http-origin election can no longer see
 * its rival, so both tabs reach the refresh endpoint. */
function delayBroadcastChannel(t: TestContext, delayMs: number): void {
  const Original = globalThis.BroadcastChannel;
  class Delayed extends Original {
    postMessage(message: unknown): void {
      setTimeout(() => { try { super.postMessage(message); } catch { /* closed */ } }, delayMs);
    }
  }
  Object.defineProperty(globalThis, 'BroadcastChannel', { configurable: true, writable: true, value: Delayed });
  t.after(() => Object.defineProperty(globalThis, 'BroadcastChannel', { configurable: true, writable: true, value: Original }));
}

/** The origin cookie jar plus the server's rotation. `graceMs` models the
 * server-side tolerance for the immediately previous refresh token
 * (REFRESH_GRACE_SECS): such a refresh returns an access token and leaves the
 * cookie alone. A refused refresh clears the cookie (the real 401 response). */
class CookieJarServer {
  cookie: string | null = 'refresh-0';
  private previous: string | null = null;
  private rotatedAt = 0;
  private generation = 0;
  calls = 0;
  private readonly graceMs: number;
  constructor(graceMs: number) { this.graceMs = graceMs; }
  async refresh(): Promise<string> {
    const presented = this.cookie;
    this.calls++;
    await new Promise(resolve => setTimeout(resolve, 10));
    if (presented !== null && presented === this.cookie) {
      this.previous = presented;
      this.rotatedAt = Date.now();
      this.generation++;
      this.cookie = `refresh-${this.generation}`;
      return `access-${this.generation}`;
    }
    if (presented !== null && presented === this.previous && Date.now() - this.rotatedAt < this.graceMs) {
      return `access-${this.generation}-grace`;
    }
    this.cookie = null; // 401 + clear-cookie headers
    throw new Error('401 invalid refresh token');
  }
}

async function raceTwoTabs(server: CookieJarServer) {
  let prompts = 0;
  const tabs = Array.from({ length: 2 }, () => {
    let token: string | null = null;
    const gate = new SessionCredentials(() => token);
    gate.configure(() => gate.runRefresh(async () => {
      token = await coordinateBrowserRefresh(() => server.refresh(), { timeoutMs: 1000 });
      return true;
    }), () => { prompts++; });
    return gate;
  });
  const results = await Promise.allSettled(tabs.map(gate => gate.credential()));
  return { results, prompts };
}

test('http origin, delayed BroadcastChannel: the race reaches the server twice', async t => {
  // Control: proves the election alone is not mutual exclusion. Against a
  // strict single-use server one tab is logged out and the cookie is wiped.
  mockLocks(t, undefined);
  delayBroadcastChannel(t, 200);
  const strict = new CookieJarServer(0);
  const { results, prompts } = await raceTwoTabs(strict);
  assert.equal(strict.calls, 2);
  assert.ok(results.some(r => r.status === 'rejected'));
  assert.ok(prompts >= 1);
  assert.equal(strict.cookie, null);
});

test('http origin, delayed BroadcastChannel: server grace window keeps both tabs signed in', async t => {
  mockLocks(t, undefined);
  delayBroadcastChannel(t, 200);
  const server = new CookieJarServer(20_000);
  const { results, prompts } = await raceTwoTabs(server);
  assert.equal(server.calls, 2, 'both tabs reached the endpoint');
  assert.deepEqual(results.map(r => r.status), ['fulfilled', 'fulfilled']);
  assert.equal(prompts, 0, 'no logout');
  assert.equal(server.cookie, 'refresh-1', "the winner's rotated cookie survives");
});
