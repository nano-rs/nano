// SPDX-License-Identifier: AGPL-3.0-or-later

// Live-run signal (NAN-1602).
//
// A search the user explicitly ran should be LIVE — never served from the
// server cache, and never showing the "cached Ns ago" badge. The badge only
// belongs on PASSIVE loads (a shared/pasted link, URL/short-link restore) where
// the viewer didn't trigger the query and staleness actually matters.
//
// The main /api/search bypasses the cache directly for a user run, but the
// special two-phase views (retro / cloud / asset / metric / services) fetch
// their own data from companion endpoints and need the same signal. This
// context carries it from Search.tsx down to those views' fetch hooks without
// prop-drilling through SearchResults.
//
// Defaults to `false` so the same view components reused in the Observability
// console (which has no provider) fetch normally — never force a bypass there.

import { createContext, useContext } from 'react';

const LiveRunContext = createContext<boolean>(false);

export const LiveRunProvider = LiveRunContext.Provider;

/** True when the currently-displayed search was an explicit user run (→ the
 * view's initial fetch should bypass the cache). False on passive loads and
 * outside the search page. */
export function useIsLiveRun(): boolean {
  return useContext(LiveRunContext);
}
