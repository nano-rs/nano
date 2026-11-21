// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5729: the token store tracks whose token it holds, synchronously, so
// async UI work can tell a user swap apart from a same-user refresh.
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  authSessionGuard, clearAccessToken, getAuthSessionGeneration, onAuthSessionChange, setAccessToken,
} from './auth-token';

afterEach(() => clearAccessToken());

describe('auth session generation (NAN-5729)', () => {
  it('a same-user refresh keeps the session; a user swap or logout ends it', () => {
    setAccessToken('a1', 900, 'uA');
    const live = authSessionGuard();
    setAccessToken('a2', 900, 'uA');
    expect(live()).toBe(true);
    setAccessToken('b1', 900, 'uB');
    expect(live()).toBe(false);

    const liveB = authSessionGuard();
    clearAccessToken();
    expect(liveB()).toBe(false);
  });

  it('notifies listeners synchronously with the previous and next owner', () => {
    setAccessToken('a1', 900, 'uA');
    const seen = vi.fn();
    const off = onAuthSessionChange(seen);
    const before = getAuthSessionGeneration();
    setAccessToken('b1', 900, 'uB');
    expect(seen).toHaveBeenCalledWith('uA', 'uB');
    expect(getAuthSessionGeneration()).toBe(before + 1);
    clearAccessToken();
    expect(seen).toHaveBeenLastCalledWith('uB', null);
    off();
    setAccessToken('c1', 900, 'uC');
    expect(seen).toHaveBeenCalledTimes(2);
  });
});
