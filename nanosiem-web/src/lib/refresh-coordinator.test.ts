// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  coordinateSingleWinnerRefresh,
  accessOnlyRefreshResult,
  coordinateBrowserRefresh,
  cookieMutationStillOwnsSession,
  type PendingRefreshOutcome,
  type RefreshOutcome,
  type RefreshOutcomeBus,
  type RefreshTryLock,
  ALL_COOKIE_SLOTS,
  cookieSlotForScope,
  isRefreshSessionMessage,
  logoutMessageAffectsSlot,
  ORIGIN_COOKIE_SLOT,
  sessionInvalidationMessage,
  tenantCookieSlot,
  refreshCoordinationNames,
  refreshSessionMessageReplacesScope,
  refreshOutcomeSessionMessage,
  sessionReplacementMessage,
  uncoordinatedRefreshFallback,
  withBrowserCookieMutationLock,
} from './refresh-coordinator.ts';

class FakeLock implements RefreshTryLock {
  private busy = false;

  async tryRun<T>(operation: () => Promise<T>) {
    if (this.busy) return { acquired: false as const };
    this.busy = true;
    try {
      return { acquired: true as const, value: await operation() };
    } finally {
      this.busy = false;
    }
  }
}

class FakeBus<T> implements RefreshOutcomeBus<T> {
  private listeners = new Set<(outcome: RefreshOutcome<T>) => void>();

  wait(): PendingRefreshOutcome<T> {
    let listener!: (outcome: RefreshOutcome<T>) => void;
    const promise = new Promise<RefreshOutcome<T>>((resolve) => {
      listener = resolve;
      this.listeners.add(listener);
    });
    return { promise, cancel: () => this.listeners.delete(listener) };
  }

  publish(outcome: RefreshOutcome<T>): void {
    for (const listener of [...this.listeners]) listener(outcome);
    this.listeners.clear();
  }
}

test('simultaneous tabs have one refresh winner and share its result', async () => {
  const lock = new FakeLock();
  const bus = new FakeBus<{ access_token: string }>();
  let calls = 0;
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => { release = resolve; });
  const refresh = async () => {
    calls += 1;
    await blocked;
    return { access_token: 'winner-token' };
  };

  const tabA = coordinateSingleWinnerRefresh(lock, bus, refresh);
  const tabB = coordinateSingleWinnerRefresh(lock, bus, refresh);
  await Promise.resolve();
  assert.equal(calls, 1);
  release();

  assert.deepEqual(await tabA, { access_token: 'winner-token' });
  assert.deepEqual(await tabB, { access_token: 'winner-token' });
  assert.equal(calls, 1);
});

test('required shared-mode coordination fails closed when browser primitives are absent', async () => {
  let calls = 0;
  await assert.rejects(
    uncoordinatedRefreshFallback(async () => { calls += 1; return 'token'; }, true),
    /coordination is required/,
  );
  assert.equal(calls, 0);
});

test('required shared cookie mutation also fails closed without a browser lock', async () => {
  let calls = 0;
  await assert.rejects(
    withBrowserCookieMutationLock(async () => { calls += 1; return 'session'; }, {
      requireCoordination: true,
      lockManager: null,
    }),
    /coordination is required/,
  );
  assert.equal(calls, 0);
});

test('broadcast refresh value never carries the rotating refresh credential', () => {
  const value = accessOnlyRefreshResult({
    access_token: 'access', expires_in: 900, refresh_token: 'must-not-broadcast',
  });
  assert.deepEqual(value, { access_token: 'access', expires_in: 900 });
  assert.equal('refresh_token' in value, false);
});

test('a late contender can consume a replayed winner result without refreshing again', async () => {
  const outcome: RefreshOutcome<{ access_token: string }> = {
    ok: true,
    value: { access_token: 'already-rotated' },
  };
  const replayBus: RefreshOutcomeBus<{ access_token: string }> = {
    wait: () => ({ promise: Promise.resolve(outcome), cancel: () => undefined }),
    publish: () => undefined,
  };
  const heldLock: RefreshTryLock = {
    tryRun: async () => ({ acquired: false }),
  };
  let calls = 0;
  const value = await coordinateSingleWinnerRefresh(heldLock, replayBus, async () => {
    calls += 1;
    return { access_token: 'wrong' };
  });
  assert.deepEqual(value, { access_token: 'already-rotated' });
  assert.equal(calls, 0);
});

test('single-cookie deployments serialize the one origin-global rotating cookie', () => {
  const userA = refreshCoordinationNames('dedicated:user-1');
  const userB = refreshCoordinationNames('dedicated:user-2', ORIGIN_COOKIE_SLOT);
  assert.notEqual(userA.channelName, userB.channelName);
  assert.equal(userA.lockName, userB.lockName);
  // The historical lock name is unchanged for single-cookie deployments.
  assert.equal(userA.lockName, 'nanosiem-auth-refresh-cookie');
});

test('NAN-3548: pooled-host tenants rotate independent cookie pairs under independent locks', () => {
  const tenantA = refreshCoordinationNames('enterprise_shared:tenant-a:user-1', tenantCookieSlot('acme'));
  const tenantB = refreshCoordinationNames('enterprise_shared:tenant-b:user-1', tenantCookieSlot('globex'));
  const tenantA2 = refreshCoordinationNames('enterprise_shared_slug:acme', tenantCookieSlot('acme'));
  assert.notEqual(tenantA.channelName, tenantB.channelName);
  assert.notEqual(tenantA.lockName, tenantB.lockName);
  // Every tab of one tenant still has a single rotation winner.
  assert.equal(tenantA.lockName, tenantA2.lockName);
});

test('concurrent same-scope tabs have one origin-wide cookie rotation winner', async () => {
  const lock = new FakeLock();
  const bus = new FakeBus<{ access_token: string }>();
  let calls = 0;
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => { release = resolve; });
  const refresh = async () => {
    calls += 1;
    await blocked;
    return { access_token: 'winner-token' };
  };

  const results = [
    coordinateSingleWinnerRefresh(lock, bus, refresh),
    coordinateSingleWinnerRefresh(lock, bus, refresh),
  ];
  await Promise.resolve();
  release();
  const [first, second] = await Promise.all(results);
  assert.deepEqual([first, second], [
    { access_token: 'winner-token' },
    { access_token: 'winner-token' },
  ]);
  assert.equal(calls, 1);
});

test('origin-global session signals carry identity only and invalidate other scopes', () => {
  const message = sessionReplacementMessage('enterprise_shared:tenant-a:user-1');
  assert.equal(isRefreshSessionMessage(message), true);
  assert.equal(refreshSessionMessageReplacesScope(
    message,
    'enterprise_shared:tenant-a:user-1',
  ), false);
  assert.equal(refreshSessionMessageReplacesScope(
    message,
    'enterprise_shared:tenant-b:user-1',
  ), true);
  const serialized = JSON.stringify(message);
  assert.equal(serialized.includes('access_token'), false);
  assert.equal(serialized.includes('refresh_token'), false);
});

test('session invalidation stops even the matching tenant scope', () => {
  const message = {
    kind: 'session-invalidated' as const,
    scopeKey: 'enterprise_shared:tenant-a:user-1',
  };
  assert.equal(refreshSessionMessageReplacesScope(message, message.scopeKey), true);
});

test('successful refresh cannot announce an unverified route-slug identity', () => {
  assert.equal(refreshOutcomeSessionMessage({ ok: true }, 'enterprise_shared_slug:tenant-a'), undefined);
  assert.equal(refreshOutcomeSessionMessage({ ok: true }, 'enterprise_shared:tenant-a:user-1'), undefined);
  assert.deepEqual(refreshOutcomeSessionMessage({ ok: false }, 'enterprise_shared_slug:tenant-a'), {
    kind: 'session-invalidated', scopeKey: 'enterprise_shared_slug:tenant-a',
  });
});

test('bearer-only shared logout invalidates only the exact tenant/user scope', () => {
  const message = { kind: 'tenant-session-revoked' as const, scopeKey: 'enterprise_shared:tenant-a:user-1' };
  assert.equal(isRefreshSessionMessage(message), true);
  assert.equal(refreshSessionMessageReplacesScope(message, message.scopeKey), true);
  assert.equal(refreshSessionMessageReplacesScope(message, 'enterprise_shared:tenant-b:user-1'), false);
  assert.equal(refreshSessionMessageReplacesScope(message, 'enterprise_shared:tenant-a:user-2'), false);
  assert.equal(refreshSessionMessageReplacesScope(message, 'anonymous'), false);
});

test('queued tenant A logout cannot mutate tenant B after session replacement', () => {
  assert.equal(cookieMutationStillOwnsSession(
    'enterprise_shared:tenant-a:user-1',
    'tenant-a-access',
    'enterprise_shared:tenant-b:user-1',
    'tenant-b-access',
  ), false);
  assert.equal(cookieMutationStillOwnsSession(
    'enterprise_shared:tenant-a:user-1',
    'stale-tenant-a-access',
    'enterprise_shared:tenant-a:user-1',
    'new-tenant-a-access',
  ), false);
  assert.equal(cookieMutationStillOwnsSession(
    'enterprise_shared:tenant-a:user-1',
    'tenant-a-access',
    'enterprise_shared:tenant-a:user-1',
    'tenant-a-access',
  ), true);
});

// ---------------------------------------------------------------------------
// NAN-3548 regression: two tenants in two tabs on the pooled host.
//
// A live repro on the pooled host, after the cookies became per tenant:
// acme tab works -> sign in to globex in tab 2 -> acme tab shows logged
// out -> refresh acme (restores, its cookie survived) -> globex tab is
// logged out -> refresh globex -> acme logged out again. The cookies were
// independent; the SPA's cross-tab "session-replaced" signal was not.
// ---------------------------------------------------------------------------

const ACME = { scopeKey: 'enterprise_shared:tenant-acme:user-ann', slot: tenantCookieSlot('acme') };
const GLOBEX = { scopeKey: 'enterprise_shared:tenant-globex:user-ann', slot: tenantCookieSlot('globex') };

/** A tab's view of the origin-wide session channel. */
function tabSurvives(tab: typeof ACME, message: unknown): boolean {
  assert.equal(isRefreshSessionMessage(message), true);
  return !refreshSessionMessageReplacesScope(
    message as Parameters<typeof refreshSessionMessageReplacesScope>[0],
    tab.scopeKey,
    tab.slot,
  );
}

test("NAN-3548: the interleaved login/refresh sequence never logs the other tenant out", () => {
  // 1. Sign in to globex in tab 2: AuthContext.login broadcasts.
  const globexLogin = sessionReplacementMessage(GLOBEX.scopeKey, GLOBEX.slot);
  assert.equal(tabSurvives(ACME, globexLogin), true, 'acme tab must survive a globex sign-in');
  assert.equal(tabSurvives(GLOBEX, globexLogin), true);

  // 2. Reload acme: its refresh succeeds and announces the verified identity.
  const acmeRefresh = sessionReplacementMessage(ACME.scopeKey, ACME.slot);
  assert.equal(tabSurvives(GLOBEX, acmeRefresh), true, 'globex tab must survive an acme refresh');

  // 3. Reload globex: the route-slug refresh announces again.
  const globexRefresh = sessionReplacementMessage(GLOBEX.scopeKey, GLOBEX.slot);
  assert.equal(tabSurvives(ACME, globexRefresh), true, 'acme tab must survive a globex refresh');

  // 4. A refused refresh on a globex route (cookie gone / revoked) ends
  //    globex tabs only; the server clears only that tenant's pair.
  const globexRefused = refreshOutcomeSessionMessage(
    { ok: false },
    'enterprise_shared_slug:globex',
    GLOBEX.slot,
  );
  assert.equal(tabSurvives(ACME, globexRefused), true, 'a globex refusal must not end acme');
  assert.equal(tabSurvives(GLOBEX, globexRefused), false);

  // 5. Logging out of acme (single-cookie style invalidation) ends acme only.
  const acmeInvalidated = sessionInvalidationMessage(ACME.scopeKey, ACME.slot);
  assert.equal(tabSurvives(GLOBEX, acmeInvalidated), true);
  assert.equal(tabSurvives(ACME, acmeInvalidated), false);
});

test('NAN-3548: a different user replacing the SAME tenant pair still ends the old tab', () => {
  const otherUser = sessionReplacementMessage('enterprise_shared:tenant-acme:user-eve', ACME.slot);
  assert.equal(tabSurvives(ACME, otherUser), false);
  // ... and leaves the other tenant alone.
  assert.equal(tabSurvives(GLOBEX, otherUser), true);
});

test('NAN-3548: an anonymous tab on another tenant route ignores a sign-in elsewhere', () => {
  const globexLogin = sessionReplacementMessage(GLOBEX.scopeKey, GLOBEX.slot);
  const acmeLoginTab = cookieSlotForScope({ kind: 'anonymous' }, 'acme');
  assert.equal(refreshSessionMessageReplacesScope(globexLogin, 'anonymous', acmeLoginTab), false);
});

test('NAN-3548: single-cookie deployments keep origin-wide replacement semantics', () => {
  const replaced = sessionReplacementMessage('dedicated:user-2', ORIGIN_COOKIE_SLOT);
  assert.equal(refreshSessionMessageReplacesScope(replaced, 'dedicated:user-1', ORIGIN_COOKIE_SLOT), true);
  assert.equal(refreshSessionMessageReplacesScope(replaced, 'dedicated:user-2', ORIGIN_COOKIE_SLOT), false);
  assert.equal(cookieSlotForScope({ kind: 'anonymous' }), ORIGIN_COOKIE_SLOT);
});

test('NAN-3548: slot-less (pre-slot) and wildcard signals fail closed across every slot', () => {
  const legacy = { kind: 'session-invalidated' as const, scopeKey: 'enterprise-shared-oidc-callback-failed' };
  assert.equal(tabSurvives(ACME, legacy), false);
  assert.equal(tabSurvives(GLOBEX, legacy), false);
  const wildcard = sessionInvalidationMessage('enterprise-shared-oidc-callback-failed', ALL_COOKIE_SLOTS);
  assert.equal(tabSurvives(ACME, wildcard), false);
  assert.equal(tabSurvives(GLOBEX, wildcard), false);
  // Tenant revocation stays exact-scope regardless of slot.
  const revoked = { kind: 'tenant-session-revoked' as const, scopeKey: ACME.scopeKey, cookieSlot: ACME.slot };
  assert.equal(tabSurvives(ACME, revoked), false);
  assert.equal(tabSurvives(GLOBEX, revoked), true);
  // Malformed slots are not session messages.
  assert.equal(isRefreshSessionMessage({ kind: 'session-replaced', scopeKey: 'x', cookieSlot: '' }), false);
  assert.equal(isRefreshSessionMessage({ kind: 'session-replaced', scopeKey: 'x', cookieSlot: 7 }), false);
});

test('NAN-3548: the AUTH logout broadcast is tenant-scoped', () => {
  assert.equal(logoutMessageAffectsSlot({ type: 'logout', cookieSlot: GLOBEX.slot }, ACME.slot), false);
  assert.equal(logoutMessageAffectsSlot({ type: 'logout', cookieSlot: ACME.slot }, ACME.slot), true);
  assert.equal(logoutMessageAffectsSlot({ type: 'logout' }, ACME.slot), true, 'slot-less is origin-wide');
  assert.equal(logoutMessageAffectsSlot({ type: 'logout', cookieSlot: ORIGIN_COOKIE_SLOT }, ORIGIN_COOKIE_SLOT), true);
  assert.equal(logoutMessageAffectsSlot({ type: 'other', cookieSlot: ACME.slot }, ACME.slot), false);
});

test('NAN-3548: the route slug selects the cookie slot, matching the server refresh selector', () => {
  const acmeScope = {
    kind: 'enterprise_shared' as const,
    userId: 'user-ann',
    roles: [],
    tenant: { id: 'tenant-acme', slug: 'acme' },
  } as unknown as Parameters<typeof cookieSlotForScope>[0];
  assert.equal(cookieSlotForScope(acmeScope), tenantCookieSlot('acme'));
  // A acme-scoped runtime on a globex route refreshes globex's pair.
  assert.equal(cookieSlotForScope(acmeScope, 'globex'), tenantCookieSlot('globex'));
  assert.throws(() => tenantCookieSlot('  '));
});

// NAN-3768: open core is served over plain http://<lan-ip>, an insecure
// context where neither navigator.locks nor crypto.randomUUID exists. The
// BroadcastChannel fallback lock must still elect this tab and run the refresh
// request; it used to throw "crypto.randomUUID is not a function" before any
// network call, so every scheduled/401/reload refresh logged the user out
// ~TTL-60 s (14 min) after login.
test('insecure-context refresh (no Web Locks, no randomUUID) still runs the refresh request', async () => {
  const cryptoDesc = Object.getOwnPropertyDescriptor(globalThis, 'crypto')!;
  const navDesc = Object.getOwnPropertyDescriptor(globalThis, 'navigator')!;
  const realCrypto = globalThis.crypto;
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    enumerable: true,
    // getRandomValues IS exposed over plain http; randomUUID is not.
    value: { getRandomValues: realCrypto.getRandomValues.bind(realCrypto) },
  });
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    enumerable: true,
    value: { userAgent: 'insecure-context-test' },
  });
  try {
    assert.equal(typeof (globalThis.crypto as { randomUUID?: unknown }).randomUUID, 'undefined');
    assert.equal(typeof (navigator as { locks?: unknown }).locks, 'undefined');
    let calls = 0;
    const result = await coordinateBrowserRefresh(async () => {
      calls += 1;
      return { access_token: 'fresh', expires_in: 900 };
    }, { scopeKey: 'dedicated', cookieSlot: ORIGIN_COOKIE_SLOT, timeoutMs: 2_000 });
    assert.equal(calls, 1);
    assert.deepEqual(result, { access_token: 'fresh', expires_in: 900 });
  } finally {
    Object.defineProperty(globalThis, 'crypto', cryptoDesc);
    Object.defineProperty(globalThis, 'navigator', navDesc);
  }
});
