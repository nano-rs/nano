// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Cross-tab coordination of the rotating refresh cookie (NAN-2453).
 *
 * `POST /api/auth/refresh` rotates a single-use refresh token held in an
 * origin-wide HttpOnly cookie. When two tabs refresh at the same moment they
 * both present the same cookie: the server's compare-and-swap lets exactly one
 * win and answers the other with 401 plus cookie-clearing headers. The loser
 * then logs out, and its clear can even wipe the winner's new cookie — the
 * "spurious multi-tab logout".
 *
 * Here exactly one tab (the lock winner) calls the endpoint; every other tab
 * registers for the winner's result BEFORE contending, and consumes the
 * access token it broadcasts. Only the access token and its TTL cross tabs
 * (never the refresh token), transiently over a same-origin BroadcastChannel;
 * nothing is persisted. If the winner disappears (suspended or closed mid
 * refresh) a follower takes over after `timeoutMs` instead of waiting forever.
 *
 * Primitives: Web Locks when available. Web Locks (like crypto.randomUUID)
 * exist only in secure contexts, and open-core installs are often served over
 * plain http on a LAN address, so a BroadcastChannel lease election is the
 * fallback. Without either primitive the refresh runs uncoordinated, which is
 * the pre-NAN-2453 behaviour.
 */

export type RefreshOutcome<T> =
  | { ok: true; value: T }
  | { ok: false; message: string };

export interface PendingRefreshOutcome<T> {
  promise: Promise<RefreshOutcome<T>>;
  cancel(): void;
}

export interface RefreshOutcomeBus<T> {
  wait(timeoutMs: number): PendingRefreshOutcome<T>;
  publish(outcome: RefreshOutcome<T>): void;
}

export interface RefreshTryLock {
  takeOver?<T>(operation: () => Promise<T>): Promise<{ acquired: true; value: T } | { acquired: false }>;
  tryRun<T>(operation: () => Promise<T>): Promise<{ acquired: true; value: T } | { acquired: false }>;
}

export class RefreshWaitTimeout extends Error {
  constructor() {
    super('Timed out waiting for the active refresh tab');
    this.name = 'RefreshWaitTimeout';
  }
}

/** Strip the refresh token from a refresh response before it can be shared. */
export function accessOnlyRefreshResult(response: {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
}): { access_token: string; expires_in: number } {
  return { access_token: response.access_token, expires_in: response.expires_in };
}

/**
 * Exactly the lock winner invokes `operation`; contenders consume its
 * broadcast result. Contenders listen before they contend, which closes the
 * publish-before-listen race. On a winner timeout the next attempt takes the
 * lock over (when the lock supports it).
 */
export async function coordinateSingleWinnerRefresh<T>(
  lock: RefreshTryLock,
  bus: RefreshOutcomeBus<T>,
  operation: () => Promise<T>,
  timeoutMs = 15_000,
): Promise<T> {
  const run = async () => {
    const deadline = Date.now() + timeoutMs;
    try {
      const value = await operation();
      // A suspended former leader must never publish a stale result after
      // another tab has taken over its expired lease.
      if (Date.now() >= deadline) throw new RefreshWaitTimeout();
      bus.publish({ ok: true, value });
      return value;
    } catch (error) {
      if (Date.now() < deadline) {
        bus.publish({ ok: false, message: error instanceof Error ? error.message : 'Refresh failed' });
      }
      throw error;
    }
  };
  for (let attempt = 0; attempt < 3; attempt++) {
    const pending = bus.wait(timeoutMs);
    // Observe immediately, even while the leader's operation is still pending.
    const outcomePromise = pending.promise.then(
      outcome => ({ outcome }),
      error => ({ error }),
    );
    try {
      const result = attempt > 0 && lock.takeOver
        ? await lock.takeOver(run)
        : await lock.tryRun(run);
      if (result.acquired) return result.value;
      const resultMessage = await outcomePromise;
      if ('error' in resultMessage) {
        if (resultMessage.error instanceof RefreshWaitTimeout && attempt < 2) continue;
        throw resultMessage.error;
      }
      if (!resultMessage.outcome.ok) throw new Error(resultMessage.outcome.message);
      return resultMessage.outcome.value;
    } finally {
      pending.cancel();
    }
  }
  throw new RefreshWaitTimeout();
}

export const REFRESH_CHANNEL_NAME = 'nanosiem-auth-refresh';
export const REFRESH_LOCK_NAME = 'nanosiem-auth-refresh-cookie';

/** Non-secret, non-crypto identifier: crypto.randomUUID is undefined on http
 * origins (NAN-3768), and these ids only order lease claims. */
function contenderId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}-${Math.random().toString(36).slice(2)}`;
}

type RefreshChannelMessage<T> =
  | { kind: 'refresh-result'; outcome: RefreshOutcome<T> }
  | { kind: 'refresh-result-request' };

class BroadcastRefreshBus<T> implements RefreshOutcomeBus<T> {
  private readonly channel: BroadcastChannel;
  private lastOutcome: RefreshOutcome<T> | null = null;
  private readonly replayListener: (event: MessageEvent<RefreshChannelMessage<T>>) => void;

  constructor(channel: BroadcastChannel) {
    this.channel = channel;
    this.replayListener = (event) => {
      if (event.data?.kind === 'refresh-result-request' && this.lastOutcome) {
        this.channel.postMessage({ kind: 'refresh-result', outcome: this.lastOutcome });
      }
    };
    this.channel.addEventListener('message', this.replayListener);
  }

  wait(timeoutMs: number): PendingRefreshOutcome<T> {
    let active = true;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    let listener: ((event: MessageEvent<RefreshChannelMessage<T>>) => void) | undefined;
    const promise = new Promise<RefreshOutcome<T>>((resolve, reject) => {
      listener = (event) => {
        if (!active || event.data?.kind !== 'refresh-result') return;
        active = false;
        if (timeout) clearTimeout(timeout);
        this.channel.removeEventListener('message', listener!);
        resolve(event.data.outcome);
      };
      this.channel.addEventListener('message', listener);
      // A winner may have published after we opened the channel but just
      // before we observed its held lock. Ask it to replay while it still
      // owns the lock/channel rather than timing out on a missed edge.
      this.channel.postMessage({ kind: 'refresh-result-request' });
      timeout = setTimeout(() => {
        if (!active) return;
        active = false;
        this.channel.removeEventListener('message', listener!);
        reject(new RefreshWaitTimeout());
      }, timeoutMs);
    });
    return {
      promise,
      cancel: () => {
        if (!active) return;
        active = false;
        if (timeout) clearTimeout(timeout);
        if (listener) this.channel.removeEventListener('message', listener);
      },
    };
  }

  publish(outcome: RefreshOutcome<T>): void {
    this.lastOutcome = outcome;
    this.channel.postMessage({ kind: 'refresh-result', outcome });
  }

  close(): void {
    this.channel.removeEventListener('message', this.replayListener);
  }
}

class BrowserRefreshLock implements RefreshTryLock {
  private readonly lockName: string;
  private readonly leaseMs: number;

  constructor(lockName: string, leaseMs: number) {
    this.lockName = lockName;
    this.leaseMs = leaseMs;
  }

  async takeOver<T>(operation: () => Promise<T>): Promise<
    { acquired: true; value: T } | { acquired: false }
  > {
    // The election lock guards only a synchronous metadata update, never a
    // network request. A replacement leader can disappear too: its lease
    // expires and the next contender can steal the cookie lock again.
    const leaseKey = `${this.lockName}:takeover-lease`;
    const owner = contenderId();
    let attempt: Promise<{ acquired: true; value: T }> | undefined;
    await navigator.locks.request(`${this.lockName}:takeover`, { ifAvailable: true }, lock => {
      if (!lock) return;
      const lease = readLease(leaseKey);
      if (lease && lease.expiresAt > Date.now()) return;
      // Metadata only: bearer / refresh tokens are never persisted.
      writeLease(leaseKey, { owner, expiresAt: Date.now() + this.leaseMs });
      attempt = navigator.locks.request(this.lockName, { steal: true }, async () => ({
        acquired: true as const, value: await operation(),
      }));
      // Stealing can reject the request before the election lock is released.
      void attempt.catch(() => {});
    });
    if (!attempt) return { acquired: false };
    try {
      return await attempt;
    } finally {
      if (readLease(leaseKey)?.owner === owner) removeLease(leaseKey);
    }
  }

  async tryRun<T>(operation: () => Promise<T>): Promise<
    { acquired: true; value: T } | { acquired: false }
  > {
    return navigator.locks.request(
      this.lockName,
      { mode: 'exclusive', ifAvailable: true },
      async (lock) => lock
        ? { acquired: true as const, value: await operation() }
        : { acquired: false as const },
    );
  }
}

function readLease(key: string): { owner: string; expiresAt: number } | null {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) as { owner: string; expiresAt: number } : null;
  } catch {
    return null;
  }
}
function writeLease(key: string, value: { owner: string; expiresAt: number }): void {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage unavailable */ }
}
function removeLease(key: string): void {
  try { localStorage.removeItem(key); } catch { /* storage unavailable */ }
}

/** Credential-free election for browsers without Web Locks (http origins).
 * The lexicographically first simultaneous contender wins; an existing
 * holder always wins over a new contender. A suspended or closed leader's
 * claim expires without needing an unload handler. */
class BroadcastRefreshLock implements RefreshTryLock {
  private readonly channel = new BroadcastChannel(`${REFRESH_LOCK_NAME}:lease`);
  private readonly id = contenderId();
  private readonly claims = new Map<string, number>();
  private expiresAt = 0;
  private held = false;
  private holderExpiry = 0;
  private readonly leaseMs: number;

  constructor(leaseMs: number) {
    this.leaseMs = leaseMs;
    this.channel.onmessage = event => {
      const message = event.data;
      if (!message || typeof message.id !== 'string') return;
      if (message.kind === 'release') this.claims.delete(message.id);
      if (message.kind === 'claim' && typeof message.expiresAt === 'number') {
        this.claims.set(message.id, message.expiresAt);
        if (this.expiresAt > Date.now()) this.publish(this.held ? 'held' : 'contender');
      }
      if (message.kind === 'contender' && typeof message.expiresAt === 'number') {
        this.claims.set(message.id, message.expiresAt);
      }
      if (message.kind === 'held' && typeof message.expiresAt === 'number') {
        this.holderExpiry = message.expiresAt;
        this.claims.set(message.id, message.expiresAt);
      }
    };
  }

  private publish(kind: string): void {
    this.channel.postMessage({ kind, id: this.id, expiresAt: this.expiresAt });
  }

  async tryRun<T>(operation: () => Promise<T>): Promise<
    { acquired: true; value: T } | { acquired: false }
  > {
    this.expiresAt = Date.now() + this.leaseMs;
    this.publish('claim');
    await new Promise(resolve => setTimeout(resolve, 50));
    if (this.holderExpiry > Date.now()
      || [...this.claims].some(([id, expiry]) => expiry > Date.now() && id < this.id)) {
      this.expiresAt = 0;
      this.publish('release');
      return { acquired: false };
    }
    if (this.expiresAt <= Date.now()) return { acquired: false };
    this.expiresAt = Date.now() + this.leaseMs;
    this.held = true;
    this.publish('held');
    try {
      return { acquired: true, value: await operation() };
    } finally {
      this.held = false;
      this.expiresAt = 0;
      this.publish('release');
    }
  }

  close(): void { this.channel.close(); }
}

/**
 * Coordinate the HttpOnly-cookie refresh across this origin's tabs. Demo
 * sessions (refresh token in the request body, per tab) do not use this.
 */
export async function coordinateBrowserRefresh<T>(
  operation: () => Promise<T>,
  options: { timeoutMs?: number } = {},
): Promise<T> {
  if (typeof navigator === 'undefined' || typeof BroadcastChannel === 'undefined') {
    return operation();
  }
  const timeoutMs = options.timeoutMs ?? 15_000;
  const channel = new BroadcastChannel(REFRESH_CHANNEL_NAME);
  const bus = new BroadcastRefreshBus<T>(channel);
  const lock = navigator.locks
    ? new BrowserRefreshLock(REFRESH_LOCK_NAME, timeoutMs)
    : new BroadcastRefreshLock(timeoutMs);
  try {
    return await coordinateSingleWinnerRefresh(lock, bus, operation, timeoutMs);
  } finally {
    if (lock instanceof BroadcastRefreshLock) lock.close();
    bus.close();
    channel.close();
  }
}
