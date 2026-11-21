// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5706 / NAN-5729: logging out does not reload the SPA, and the
// QueryClient lives for the whole tab. Mounted once under AuthProvider
// (including on /login), this drops EVERY cached query when the signed-in user goes away or changes, so the next user never
// sees the previous user's data, even for a moment. An allowlist of
// "private" roots goes stale as features add keys (case notebooks, entries,
// case lists all leaked); per-role data scoping makes any cached response
// another user's.
//
// The purge runs synchronously when the auth token changes hands, before
// React renders the new user, so no component built for the new user can pick
// up an old cache entry. A user change seen only through auth state (no token
// change) is caught by the effect below.
import { useCallback, useEffect, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/contexts/AuthContext';
import { onAuthSessionChange } from '@/lib/auth-token';

export function SessionQueryCacheGuard() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const userId = user?.id;
  const previous = useRef(userId);
  const purgedAtTokenChange = useRef(false);

  // Removal alone stops a late response from coming back: an in-flight fetch
  // settles into the removed query object, never into the cache. Queries are
  // deliberately NOT cancelled: cancelling reverts a query to its pre-fetch
  // state, which would leave an observer that outlives the swap (above the
  // user-keyed app subtree) loading forever.
  const purge = useCallback(() => {
    queryClient.clear();
  }, [queryClient]);

  useEffect(() => onAuthSessionChange((prevOwner) => {
    // First sign-in (no previous owner) has nothing to clear.
    if (prevOwner === null) return;
    purge();
    purgedAtTokenChange.current = true;
  }), [purge]);

  useEffect(() => {
    const prev = previous.current;
    previous.current = userId;
    const alreadyPurged = purgedAtTokenChange.current;
    purgedAtTokenChange.current = false;
    // Signing in from nothing has nothing to clear; logout (id → none) and a
    // user switch (id → other id) do.
    if (prev && prev !== userId && !alreadyPurged) purge();
  }, [userId, purge]);

  return null;
}
