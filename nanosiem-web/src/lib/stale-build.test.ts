// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5273: stale-build detection and the one-shot reload guard.
import { expect, it, vi } from 'vitest';
import {
  ProviderMissingError,
  STALE_BUILD_RELOAD_KEY,
  STALE_BUILD_RELOAD_WINDOW_MS,
  isStaleBuildError,
  tryStaleBuildReload,
} from './stale-build';

function memoryStorage() {
  const map = new Map<string, string>();
  return { getItem: (k: string) => map.get(k) ?? null, setItem: (k: string, v: string) => void map.set(k, v), map };
}

it('recognizes chunk failures, dynamic-import failures and provider mismatches', () => {
  expect(isStaleBuildError(new ProviderMissingError('useAuth', 'AuthProvider'))).toBe(true);
  expect(isStaleBuildError(new Error('useAuth must be used within an AuthProvider'))).toBe(true);
  expect(isStaleBuildError(new TypeError('Failed to fetch dynamically imported module: /assets/Dashboard-abc.js'))).toBe(true);
  expect(isStaleBuildError(Object.assign(new Error('Loading chunk 12 failed'), { name: 'ChunkLoadError' }))).toBe(true);
  expect(isStaleBuildError(new TypeError('Importing a module script failed.'))).toBe(true);
  expect(isStaleBuildError(new TypeError("Cannot read properties of undefined (reading 'map')"))).toBe(false);
  expect(isStaleBuildError('boom')).toBe(false);
});

it('reloads once, then refuses inside the window, then allows again after it', () => {
  const storage = memoryStorage();
  const reload = vi.fn();
  let now = 1_000_000;
  const deps = { storage, reload, now: () => now };
  expect(tryStaleBuildReload(deps)).toBe(true);
  expect(storage.map.get(STALE_BUILD_RELOAD_KEY)).toBe(String(1_000_000));
  now += 1000;
  expect(tryStaleBuildReload(deps)).toBe(false);
  now += STALE_BUILD_RELOAD_WINDOW_MS;
  expect(tryStaleBuildReload(deps)).toBe(true);
  expect(reload).toHaveBeenCalledTimes(2);
});

it('never reloads without a working sessionStorage guard', () => {
  const reload = vi.fn();
  const throwing = { getItem: () => { throw new Error('denied'); }, setItem: () => { throw new Error('denied'); } };
  expect(tryStaleBuildReload({ storage: throwing, reload })).toBe(false);
  const dropping = { getItem: () => null, setItem: () => {} };
  expect(tryStaleBuildReload({ storage: dropping, reload })).toBe(false);
  expect(reload).not.toHaveBeenCalled();
});
