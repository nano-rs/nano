// SPDX-License-Identifier: AGPL-3.0-or-later

// Per-route context surface that feeds the pivt "Here" card. A page can
// either rely on the default pageKey (derived from `useLocation`) and
// the static `HERE_CARDS` registry in `components/pivt/HereCard.tsx`,
// or override the card dynamically with `useHereCardOverride` to surface
// live page state (current query, case id, counts, etc.).
//
// Design decisions:
// - One provider mounted at app root (above `AppLayout`).
// - `pageKey` is derived from the URL so the card still works on pages
//   that haven't opted in — the default static variant covers basics.
// - `hereCard` is a plain object (no React nodes in state) so it stays
//   serialisable and cheap to compare.
// - `useHereCardOverride` is a fire-and-forget effect: pages call it on
//   mount, and it clears on unmount so navigating away resets to the
//   static default.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { useLocation } from 'react-router-dom';

/** Labelled pair rendered in the Here card meta block. */
export interface HereCardLine {
  label: string;
  value: string;
}

/** Shape of a Here-card payload. Mirrors the `PIVT_HERE_CARDS` entries in
    `design-ref/shadcn/pivt-data.jsx`. Icon is a Lucide name so the type
    doesn't bleed into JSX at the context boundary. */
export interface HereCardData {
  icon?: string;
  title: string;
  tags?: string[];
  lines?: HereCardLine[];
  suggestions?: string[];
}

interface PageContextValue {
  /** Short slug derived from the URL. Stable per-route; pages can't
      change it, only override the card content via `setHereCard`. */
  pageKey: string;
  /** Live override, if any. `null` means "fall back to the static
      registry for `pageKey`". */
  hereCard: HereCardData | null;
  setHereCard: (data: HereCardData | null) => void;
}

const PageContextImpl = createContext<PageContextValue | null>(null);

/**
 * Map a pathname to a pivt pageKey. Kept intentionally broad — unknown
 * routes fall through to `'home'` so the card always has something to
 * render. Tests go in `PageContext.test.ts` alongside this file if a
 * later chunk needs regression coverage.
 */
export function pageKeyFor(pathname: string): string {
  if (pathname === '/' || pathname === '/home') return 'home';
  if (pathname.startsWith('/search')) return 'search';
  if (pathname.startsWith('/cases')) return 'case';
  if (pathname.startsWith('/rules/coverage')) return 'mitre-coverage';
  if (pathname.startsWith('/rules/tuning')) return 'ai-tuning';
  if (pathname.startsWith('/rules/repositories')) return 'rule-repositories';
  if (pathname.startsWith('/rules')) return 'rules';
  if (pathname.startsWith('/playbooks/repositories')) return 'playbook-repositories';
  if (pathname.startsWith('/playbooks')) return 'playbooks';
  if (pathname.startsWith('/dashboards')) return 'dashboards';
  if (pathname.startsWith('/notebooks')) return 'notebook';
  if (pathname.startsWith('/prevalence')) return 'prevalence';
  if (pathname.startsWith('/risk')) return 'risk';
  if (pathname.startsWith('/ingestion/log-sources')) return 'log-sources';
  if (pathname.startsWith('/ingestion/source-configurations')) return 'source-configs';
  if (pathname.startsWith('/ingestion/credentials')) return 'credentials';
  if (pathname.startsWith('/ingestion')) return 'log-sources';
  if (pathname.startsWith('/matches')) return 'matches';
  if (pathname.startsWith('/settings')) return 'settings';
  if (pathname.startsWith('/enrichments')) return 'enrichments';
  if (pathname.startsWith('/platform/health')) return 'health';
  return 'home';
}

interface PageContextProviderProps {
  children: ReactNode;
}

export function PageContextProvider({ children }: PageContextProviderProps) {
  const location = useLocation();
  const pageKey = useMemo(() => pageKeyFor(location.pathname), [location.pathname]);
  // An override belongs to the page that set it. NAN-4597: this used to be
  // cleared by a `[pageKey]` effect, but parent effects run after child
  // effects, so the reset wiped the override a page had just registered on
  // mount (and on every navigation) and the Here card fell back to the
  // static entry. Tagging the override with its pageKey resets it on route
  // changes without racing the page's own effect.
  const [override, setOverride] = useState<{ pageKey: string; card: HereCardData } | null>(null);
  const hereCard = override && override.pageKey === pageKey ? override.card : null;

  const setHereCard = useCallback(
    (data: HereCardData | null) => {
      setOverride(data ? { pageKey, card: data } : null);
    },
    [pageKey],
  );

  const value = useMemo<PageContextValue>(
    () => ({ pageKey, hereCard, setHereCard }),
    [pageKey, hereCard, setHereCard]
  );

  return <PageContextImpl.Provider value={value}>{children}</PageContextImpl.Provider>;
}

/**
 * Returns the current page context. Safe to call outside the provider —
 * returns a neutral default so pivt doesn't crash on pages that forget
 * to wrap (which shouldn't happen, but defending the dev loop is cheap).
 */
export function usePageContext(): PageContextValue {
  const ctx = useContext(PageContextImpl);
  if (ctx) return ctx;
  return { pageKey: 'home', hereCard: null, setHereCard: () => {} };
}

/**
 * Register a dynamic Here-card for the duration of a page's mount.
 * Call this at the top of a page component to override the static
 * registry with live data (current query, case id, counts, etc.).
 *
 * ```tsx
 * useHereCardOverride({
 *   icon: 'Search',
 *   title: 'Search',
 *   lines: [
 *     { label: 'query', value: query },
 *     { label: 'results', value: `${total.toLocaleString()} events` },
 *   ],
 *   suggestions: ['Summarize these results', 'Pivot by src_ip'],
 * });
 * ```
 *
 * Passing `null` keeps the static registry entry.
 *
 * Call it only from a component mounted by its route (a page). The override
 * is tagged with the pageKey current when it registers, and `setHereCard`
 * changes with every route, so a component that stays mounted across routes
 * (layout, rail, pivt panel) would re-register on each navigation and its
 * card would replace the Here card on every page.
 */
export function useHereCardOverride(card: HereCardData | null): void {
  const { setHereCard } = usePageContext();
  // Stringify the payload so the effect only re-fires when contents
  // actually change — callers don't need to `useMemo` their object.
  const key = card ? JSON.stringify(card) : null;
  useEffect(() => {
    setHereCard(card);
    return () => setHereCard(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, setHereCard]);
}
