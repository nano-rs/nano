// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, expect, it, vi } from 'vitest';
import { reloadRouteChunk } from './reload-route-chunk';

afterEach(() => vi.unstubAllGlobals());
function browser() {
  const storage = new Map<string, string>();
  const reload = vi.fn();
  const replaceState = vi.fn();
  vi.stubGlobal('window', {
    location: { pathname: '/t/ops/search', search: '?q=UNION+SELECT', hash: '#start=1', reload },
    history: { state: { idx: 2 }, replaceState },
    sessionStorage: { getItem: (key: string) => storage.get(key), setItem: (key: string, value: string) => storage.set(key, value) },
  });
  return { reload, replaceState };
}

it('does not turn arbitrary module errors into full document loads', () => {
  const { reload } = browser();
  const error = new Error('render failed');
  expect(() => reloadRouteChunk(error)).toThrow(error);
  expect(reload).not.toHaveBeenCalled();
});

it('moves legacy search state before chunk recovery and guards reload loops', () => {
  const { reload, replaceState } = browser();
  const error = new Error('Failed to fetch dynamically imported module');
  reloadRouteChunk(error);
  expect(replaceState).toHaveBeenCalledWith({ idx: 2 }, '', '/t/ops/search#q=UNION+SELECT&start=1');
  expect(reload).toHaveBeenCalledOnce();
  expect(() => reloadRouteChunk(error)).toThrow(error);
  expect(reload).toHaveBeenCalledOnce();
});
