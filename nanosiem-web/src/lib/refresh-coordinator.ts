// SPDX-License-Identifier: AGPL-3.0-or-later

import type { TenantRuntimeScope } from './tenant-runtime.ts';
import { safeRandomUUID } from './uuid.ts';

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
  tryRun<T>(operation: () => Promise<T>): Promise<
    { acquired: true; value: T } | { acquired: false }
  >;
}

export function accessOnlyRefreshResult(response: {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
}): { access_token: string; expires_in: number } {
  return { access_token: response.access_token, expires_in: response.expires_in };
}

export async function uncoordinatedRefreshFallback<T>(
  operation: () => Promise<T>,
  requireCoordination: boolean,
): Promise<T> {
  if (requireCoordination) {
    throw new Error('Cross-tab refresh coordination is required but unavailable');
  }
  return operation();
}

/**
 * Serialize every endpoint that can replace the origin-wide authentication
 * cookies, not only refresh. The caller must publish its credential-free
 * session-replacement signal before returning so a refresh contender cannot
 * acquire the lock in the gap between Set-Cookie and notification.
 */
export async function withBrowserCookieMutationLock<T>(
  operation: () => Promise<T>,
  options: {
    requireCoordination?: boolean;
    /** Which HttpOnly session-cookie pair the operation may replace. */
    cookieSlot?: string;
    /** Test seam; production callers always use the browser lock manager. */
    lockManager?: Pick<LockManager, 'request'> | null;
  } = {},
): Promise<T> {
  const lockManager = options.lockManager === undefined
    ? (typeof navigator === 'undefined' ? null : navigator.locks)
    : options.lockManager;
  if (!lockManager) {
    return uncoordinatedRefreshFallback(
      operation,
      options.requireCoordination === true,
    );
  }
  return lockManager.request(
    cookieMutationLockName(options.cookieSlot),
    { mode: 'exclusive' },
    operation,
  );
}

/**
 * Registers for the winner's result before attempting the lock, eliminating
 * the publish-before-listen race. Exactly the lock winner invokes the rotating
 * refresh endpoint; contenders consume its in-memory broadcast result.
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

export class RefreshWaitTimeout extends Error {
  constructor() {
    super('Timed out waiting for the active refresh tab');
    this.name = 'RefreshWaitTimeout';
  }
}

const REFRESH_CHANNEL_NAME = 'nanosiem-auth-refresh';
const REFRESH_LOCK_NAME = 'nanosiem-auth-refresh-cookie';
export const REFRESH_SESSION_CHANNEL_NAME = 'nanosiem-auth-session';

// ---------------------------------------------------------------------------
// Cookie slots (NAN-3548)
//
// A cookie slot names one HttpOnly session-cookie pair in the browser jar.
// Dedicated / open-core / self-hosted deployments have exactly one pair per
// origin (`access_token` + `refresh_token`): every tab shares ORIGIN_COOKIE_SLOT.
// On the hosted-shared pooled host the server issues one pair per tenant
// (`refresh_token__<sha256(tenant)>`, #6068), so each tenant is its own slot.
// A session replacement or invalidation can only end tabs whose credential
// lives in the same slot; a sign-in or refusal for tenant B never ends tenant
// A. ALL_COOKIE_SLOTS is the fail-closed wildcard for a mutation whose tenant
// is unknown (and the meaning of a message from a pre-slot tab).
// ---------------------------------------------------------------------------

export const ORIGIN_COOKIE_SLOT = 'origin';
export const ALL_COOKIE_SLOTS = '*';

export function tenantCookieSlot(tenantSlug: string): string {
  const slug = tenantSlug.trim();
  if (!slug) throw new Error('Tenant cookie slot requires a tenant slug');
  return `tenant:${slug}`;
}

/**
 * The cookie pair a tab's credential lives in. On the pooled host the server
 * selects the pair by the slug the SPA sends on refresh (the route slug first,
 * then the active tenant), so the slot follows the same precedence.
 */
export function cookieSlotForScope(
  scope: TenantRuntimeScope,
  routeTenantSlug?: string,
): string {
  if (routeTenantSlug) return tenantCookieSlot(routeTenantSlug);
  if (scope.kind === 'enterprise_shared') return tenantCookieSlot(scope.tenant.slug);
  return ORIGIN_COOKIE_SLOT;
}

/** AUTH channel `{ type: 'logout' }` signal. Only tabs sharing the logged-out
 * cookie pair react; a message without a slot (pre-slot tab) is origin-wide. */
export function logoutMessageAffectsSlot(data: unknown, currentSlot: string): boolean {
  if (!data || typeof data !== 'object' || (data as { type?: unknown }).type !== 'logout') {
    return false;
  }
  const slot = (data as { cookieSlot?: unknown }).cookieSlot;
  return typeof slot !== 'string' || sharesCookieSlot(slot, currentSlot);
}

function sharesCookieSlot(messageSlot: string, currentSlot: string): boolean {
  return messageSlot === ALL_COOKIE_SLOTS
    || currentSlot === ALL_COOKIE_SLOTS
    || messageSlot === currentSlot;
}

/** Web Lock serializing physical mutation of one cookie slot. The origin slot
 * keeps the historical lock name so single-cookie deployments are unchanged. */
function cookieMutationLockName(cookieSlot: string | undefined): string {
  return cookieSlot === undefined
    || cookieSlot === ORIGIN_COOKIE_SLOT
    || cookieSlot === ALL_COOKIE_SLOTS
    ? REFRESH_LOCK_NAME
    : `${REFRESH_LOCK_NAME}:${cookieSlot}`;
}

export type RefreshSessionMessage =
  | { kind: 'session-replaced'; scopeKey: string; cookieSlot?: string }
  | { kind: 'session-invalidated'; scopeKey: string; cookieSlot?: string }
  | { kind: 'tenant-session-revoked'; scopeKey: string; cookieSlot?: string };

export function isRefreshSessionMessage(value: unknown): value is RefreshSessionMessage {
  if (!value || typeof value !== 'object') return false;
  const message = value as Record<string, unknown>;
  return (
    (message.kind === 'session-replaced' || message.kind === 'session-invalidated'
      || message.kind === 'tenant-session-revoked')
    && typeof message.scopeKey === 'string'
    && message.scopeKey.length > 0
    && (message.cookieSlot === undefined
      || (typeof message.cookieSlot === 'string' && message.cookieSlot.length > 0))
  );
}

/**
 * Does `message` end the session of a tab whose identity is `currentScopeKey`
 * and whose credential lives in `currentCookieSlot`?
 *
 * - tenant-session-revoked: only the exact tenant/user scope.
 * - session-invalidated: every tab in the same cookie slot.
 * - session-replaced: a different identity in the same cookie slot (the one
 *   pair the two tabs share was overwritten). A sign-in to another tenant on
 *   the pooled host wrote a different pair and leaves this tab alone.
 *
 * A message without `cookieSlot` came from a pre-slot sender and is treated
 * as ALL_COOKIE_SLOTS (fail closed, the historical behaviour).
 */
export function refreshSessionMessageReplacesScope(
  message: RefreshSessionMessage,
  currentScopeKey: string,
  currentCookieSlot: string = ORIGIN_COOKIE_SLOT,
): boolean {
  if (message.kind === 'tenant-session-revoked') return message.scopeKey === currentScopeKey;
  if (!sharesCookieSlot(message.cookieSlot ?? ALL_COOKIE_SLOTS, currentCookieSlot)) return false;
  return message.kind === 'session-invalidated' || message.scopeKey !== currentScopeKey;
}

function withCookieSlot<M extends RefreshSessionMessage>(message: M, cookieSlot?: string): M {
  return cookieSlot === undefined ? message : { ...message, cookieSlot };
}

/** A bearer-only tenant logout did not rotate or clear the origin cookie.
 * Invalidate only the revoked tenant/user, not an independent sibling session.
 */
export function broadcastTenantSessionRevocation(scopeKey: string): void {
  if (!scopeKey.startsWith('enterprise_shared:') || typeof BroadcastChannel === 'undefined') return;
  const channel = new BroadcastChannel(REFRESH_SESSION_CHANNEL_NAME);
  channel.postMessage({ kind: 'tenant-session-revoked', scopeKey } satisfies RefreshSessionMessage);
  channel.close();
}

/** A refresh result is not yet a verified identity. In particular the initial
 * reload scope may be only a route slug. AuthContext announces successful
 * replacement after /auth/me verifies the canonical tenant/user binding.
 */
export function refreshOutcomeSessionMessage(
  outcome: { ok: boolean },
  scopeKey: string,
  cookieSlot?: string,
): RefreshSessionMessage | undefined {
  return outcome.ok
    ? undefined
    : withCookieSlot({ kind: 'session-invalidated', scopeKey }, cookieSlot);
}

/**
 * Recheck a queued cookie mutation after it acquires the origin-global lock.
 * A different tenant login may have replaced both the runtime identity and
 * in-memory bearer while this operation was waiting.
 */
export function cookieMutationStillOwnsSession(
  expectedScopeKey: string,
  expectedAccessToken: string | null,
  currentScopeKey: string,
  currentAccessToken: string | null,
): boolean {
  return (
    expectedScopeKey === currentScopeKey
    && expectedAccessToken === currentAccessToken
  );
}

export function sessionReplacementMessage(
  scopeKey: string,
  cookieSlot?: string,
): RefreshSessionMessage {
  if (!scopeKey.trim()) throw new Error('Session replacement scope may not be empty');
  return withCookieSlot({ kind: 'session-replaced', scopeKey }, cookieSlot);
}

export function sessionInvalidationMessage(
  scopeKey: string,
  cookieSlot?: string,
): RefreshSessionMessage {
  if (!scopeKey.trim()) throw new Error('Session invalidation scope may not be empty');
  return withCookieSlot({ kind: 'session-invalidated', scopeKey }, cookieSlot);
}

export function broadcastSessionReplacement(scopeKey: string, cookieSlot?: string): void {
  if (!scopeKey.trim() || typeof BroadcastChannel === 'undefined') return;
  const channel = new BroadcastChannel(REFRESH_SESSION_CHANNEL_NAME);
  channel.postMessage(sessionReplacementMessage(scopeKey, cookieSlot));
  channel.close();
}

export function broadcastSessionInvalidation(scopeKey: string, cookieSlot?: string): void {
  if (!scopeKey.trim() || typeof BroadcastChannel === 'undefined') return;
  const channel = new BroadcastChannel(REFRESH_SESSION_CHANNEL_NAME);
  channel.postMessage(sessionInvalidationMessage(scopeKey, cookieSlot));
  channel.close();
}

export function refreshCoordinationNames(
  scopeKey: string,
  cookieSlot: string = ORIGIN_COOKIE_SLOT,
): {
  channelName: string;
  lockName: string;
} {
  // The lock guards physical rotation of one HttpOnly cookie pair, so it is
  // scoped to the cookie slot: origin-global in single-cookie deployments,
  // per tenant on the pooled host (NAN-3548). Bearer results are scoped to the
  // exact tenant/user identity so no credential reaches a different tenant tab.
  const normalizedScope = scopeKey.trim();
  if (!normalizedScope) throw new Error('Refresh coordination scope may not be empty');
  return {
    channelName: `${REFRESH_CHANNEL_NAME}:${normalizedScope}`,
    lockName: cookieMutationLockName(cookieSlot),
  };
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
    // network request. Even a replacement leader can disappear: its lease
    // expires and the next contender can steal the cookie lock again.
    const leaseKey = `${this.lockName}:takeover-lease`;
    const owner = safeRandomUUID();
    let attempt: Promise<{ acquired: true; value: T }> | undefined;
    await navigator.locks.request(`${this.lockName}:takeover`, { ifAvailable: true }, lock => {
      if (!lock) return;
      const raw = localStorage.getItem(leaseKey);
      const lease = raw ? JSON.parse(raw) as { expiresAt: number } : null;
      if (lease && lease.expiresAt > Date.now()) return;
      // Metadata only: bearer/refresh tokens are never persisted.
      localStorage.setItem(leaseKey, JSON.stringify({ owner, expiresAt: Date.now() + this.leaseMs }));
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
      const raw = localStorage.getItem(leaseKey);
      if (raw && (JSON.parse(raw) as { owner: string }).owner === owner) {
        localStorage.removeItem(leaseKey);
      }
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

/** Credential-free election for browsers without Web Locks. Claims are
 * origin-wide; the lexicographically first simultaneous contender wins. A
 * suspended/closed leader's claim expires without needing an unload handler.
 *
 * This is the path every insecure context takes (open core over plain
 * http://<lan-ip>: no navigator.locks), where crypto.randomUUID is also
 * undefined. The election id is a tie-breaker, not a credential, so it uses
 * safeRandomUUID (NAN-3768; same trap as NAN-1235). */
class BroadcastRefreshLock implements RefreshTryLock {
  private readonly channel: BroadcastChannel;
  private readonly id = safeRandomUUID();
  private readonly claims = new Map<string, number>();
  private expiresAt = 0;
  private held = false;
  private holderExpiry = 0;

  private readonly leaseMs: number;

  constructor(lockName: string, leaseMs: number) {
    this.leaseMs = leaseMs;
    this.channel = new BroadcastChannel(`${lockName}:lease`);
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
    if (this.holderExpiry > Date.now() || [...this.claims].some(([id, expiry]) => expiry > Date.now() && id < this.id)) {
      this.expiresAt = 0;
      this.publish('release');
      return { acquired: false };
    }
    if (this.expiresAt <= Date.now()) return { acquired: false };
    // An existing holder always wins over a new contender, regardless of ID.
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
 * Same-scope tabs exchange only the access-token result. The origin-global
 * channel contains identity/change signals only, allowing a different-tenant
 * contender to stop immediately without ever receiving the winning bearer.
 */
class ScopedBrowserRefreshBus<T> implements RefreshOutcomeBus<T> {
  private readonly resultBus: BroadcastRefreshBus<T>;
  private readonly sessionChannel: BroadcastChannel;
  private readonly scopeKey: string;
  private readonly cookieSlot: string | undefined;

  constructor(
    scopeKey: string,
    resultChannel: BroadcastChannel,
    sessionChannel: BroadcastChannel,
    cookieSlot?: string,
  ) {
    this.scopeKey = scopeKey;
    this.cookieSlot = cookieSlot;
    this.resultBus = new BroadcastRefreshBus<T>(resultChannel);
    this.sessionChannel = sessionChannel;
  }

  wait(timeoutMs: number): PendingRefreshOutcome<T> {
    const local = this.resultBus.wait(timeoutMs);
    let active = true;
    let listener: ((event: MessageEvent<unknown>) => void) | undefined;
    const promise = new Promise<RefreshOutcome<T>>((resolve, reject) => {
      const finish = (
        callback: (value: RefreshOutcome<T> | Error) => void,
        value: RefreshOutcome<T> | Error,
      ) => {
        if (!active) return;
        active = false;
        local.cancel();
        if (listener) this.sessionChannel.removeEventListener('message', listener);
        callback(value);
      };
      local.promise.then(
        (outcome) => finish((value) => resolve(value as RefreshOutcome<T>), outcome),
        (error) => finish((value) => reject(value), error instanceof Error ? error : new Error('Refresh failed')),
      );
      listener = (event) => {
        if (!active || !isRefreshSessionMessage(event.data)) return;
        if (!refreshSessionMessageReplacesScope(
          event.data,
          this.scopeKey,
          this.cookieSlot ?? ORIGIN_COOKIE_SLOT,
        )) {
          return;
        }
        finish(
          (value) => resolve(value as RefreshOutcome<T>),
          {
            ok: false,
            message: event.data.kind === 'session-invalidated'
              ? 'The browser session was invalidated by another tab'
              : 'A different tenant session replaced this browser session',
          },
        );
      };
      this.sessionChannel.addEventListener('message', listener);
    });
    return {
      promise,
      cancel: () => {
        if (!active) return;
        active = false;
        local.cancel();
        if (listener) this.sessionChannel.removeEventListener('message', listener);
      },
    };
  }

  publish(outcome: RefreshOutcome<T>): void {
    // Bearer-bearing results stay scoped. Success is announced by AuthContext
    // only after the returned identity has been independently verified.
    this.resultBus.publish(outcome);
    const message = refreshOutcomeSessionMessage(outcome, this.scopeKey, this.cookieSlot);
    if (message) this.sessionChannel.postMessage(message);
  }

  close(): void {
    this.resultBus.close();
  }
}

/**
 * Coordinates the HttpOnly-cookie refresh endpoint across tabs. The access
 * token is broadcast only transiently to same-tenant/user tabs; it is never
 * sent on the origin-global session channel and is never stored.
 * Demo refresh remains on its existing per-tab path.
 */
export async function coordinateBrowserRefresh<T>(
  operation: () => Promise<T>,
  options: {
    requireCoordination?: boolean;
    scopeKey?: string;
    /** Cookie pair this refresh rotates; see ORIGIN_COOKIE_SLOT / tenantCookieSlot. */
    cookieSlot?: string;
    timeoutMs?: number;
  } = {},
): Promise<T> {
  const primitivesAvailable = !(
    typeof navigator === 'undefined'
    || typeof BroadcastChannel === 'undefined'
  );
  if (!primitivesAvailable) {
    // Shared mode fails closed if no cross-tab channel is available.
    return uncoordinatedRefreshFallback(operation, options.requireCoordination === true);
  }

  if (options.requireCoordination && !options.scopeKey?.trim()) {
    throw new Error('Tenant-scoped refresh coordination requires a scope key');
  }
  const names = refreshCoordinationNames(
    options.scopeKey ?? 'dedicated',
    options.cookieSlot ?? ORIGIN_COOKIE_SLOT,
  );
  // Construct the lock before opening the result/session channels so a
  // throwing constructor cannot leak open BroadcastChannels.
  const lock = navigator.locks
    ? new BrowserRefreshLock(names.lockName, options.timeoutMs ?? 15_000)
    : new BroadcastRefreshLock(names.lockName, options.timeoutMs ?? 15_000);
  const resultChannel = new BroadcastChannel(names.channelName);
  const sessionChannel = new BroadcastChannel(REFRESH_SESSION_CHANNEL_NAME);
  const bus = new ScopedBrowserRefreshBus<T>(
    options.scopeKey ?? 'dedicated',
    resultChannel,
    sessionChannel,
    options.cookieSlot,
  );
  try {
    return await coordinateSingleWinnerRefresh(
      lock,
      bus,
      operation,
      options.timeoutMs,
    );
  } finally {
    if (lock instanceof BroadcastRefreshLock) lock.close();
    bus.close();
    resultChannel.close();
    sessionChannel.close();
  }
}
