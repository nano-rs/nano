// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Review finding on #10108 (NAN-5706): the notebook list moved into the
// tab-lifetime React Query cache. Logout does not reload the SPA, so the
// list must be dropped when the user signs out or changes.
import { cleanup, render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';

const auth = vi.hoisted(() => ({ user: null as { id: string } | null }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ user: auth.user }) }));

import { SessionQueryCacheGuard } from './SessionQueryCacheGuard';
import { clearAccessToken, setAccessToken } from '@/lib/auth-token';

afterEach(cleanup);

// A user-keyed private list (shape of the enterprise notebooks list key). The
// guard clears every query, so the core test needs no enterprise import.
const PRIVATE_LIST_KEY = ['notebooks', 'list', 'u_a'] as const;

function setup(initialUser: string | null) {
  auth.user = initialUser ? { id: initialUser } : null;
  const client = new QueryClient();
  client.setQueryData(PRIVATE_LIST_KEY, [{ id: 'nb_private' }]);
  client.setQueryData(['detections'], ['rules']);
  client.setQueryData(['case-notebook', 'case_1'], { id: 'nb_case' });
  client.setQueryData(['notebook-entries', 'nb_case'], [{ id: 'e1' }]);
  const view = render(
    <QueryClientProvider client={client}>
      <SessionQueryCacheGuard />
    </QueryClientProvider>,
  );
  const rerenderAs = (id: string | null) => {
    auth.user = id ? { id } : null;
    view.rerender(
      <QueryClientProvider client={client}>
        <SessionQueryCacheGuard />
      </QueryClientProvider>,
    );
  };
  return { client, rerenderAs };
}

describe('SessionQueryCacheGuard', () => {
  // NAN-5729: an allowlist went stale (case notebooks, entries, case lists
  // leaked), and per-role data scoping makes any cached response private.
  it('drops EVERY cached query on logout', () => {
    const { client, rerenderAs } = setup('u_a');
    rerenderAs(null);
    expect(client.getQueryData(PRIVATE_LIST_KEY)).toBeUndefined();
    expect(client.getQueryData(['case-notebook', 'case_1'])).toBeUndefined();
    expect(client.getQueryData(['notebook-entries', 'nb_case'])).toBeUndefined();
    expect(client.getQueryData(['detections'])).toBeUndefined();
  });

  it('a late in-flight response cannot repopulate the cache for the next user', async () => {
    const { client, rerenderAs } = setup('u_a');
    let resolveFetch!: (v: unknown) => void;
    const inflight = client.fetchQuery({
      queryKey: ['case', 'case_1'],
      queryFn: () => new Promise(r => { resolveFetch = r; }),
    }).catch(() => 'cancelled');
    rerenderAs('u_b');
    resolveFetch({ title: 'A private case' });
    await inflight;
    expect(client.getQueryData(['case', 'case_1'])).toBeUndefined();
  });

  it('purges synchronously when the token changes hands, before React re-renders', () => {
    setAccessToken('token-a', 900, 'u_a');
    const { client } = setup('u_a');
    // refreshAuth installed B's token; auth state (and this guard) not re-rendered yet.
    setAccessToken('token-b', 900, 'u_b');
    expect(client.getQueryData(['case-notebook', 'case_1'])).toBeUndefined();
    expect(client.getQueryData(['detections'])).toBeUndefined();
    clearAccessToken();
  });

  it('a same-user token refresh keeps the cache', () => {
    setAccessToken('token-a', 900, 'u_a');
    const { client } = setup('u_a');
    setAccessToken('token-a2', 900, 'u_a');
    expect(client.getQueryData(['detections'])).toEqual(['rules']);
    clearAccessToken();
  });

  it('drops it when another user takes over the tab', () => {
    const { client, rerenderAs } = setup('u_a');
    rerenderAs('u_b');
    expect(client.getQueryData(PRIVATE_LIST_KEY)).toBeUndefined();
  });

  it('keeps it across re-renders of the same user and on first sign-in', () => {
    clearAccessToken();
    const { client, rerenderAs } = setup(null);
    setAccessToken('token-a', 900, 'u_a');
    rerenderAs('u_a');
    rerenderAs('u_a');
    expect(client.getQueryData(PRIVATE_LIST_KEY)).toEqual([{ id: 'nb_private' }]);
    expect(client.getQueryData(['detections'])).toEqual(['rules']);
    clearAccessToken();
  });
});
