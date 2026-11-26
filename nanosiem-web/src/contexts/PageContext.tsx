// SPDX-License-Identifier: AGPL-3.0-or-later

// Per-route context surface that feeds the PIVT "Here" card. A page can
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
import { matchPath, useLocation } from 'react-router-dom';

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
 * Route table → PIVT pageKey (NAN-5571). Matched with React Router's
 * `matchPath`, so segments are exact (`/risk` no longer matches `/risky`) and
 * a detail route gets its own key (`/alerts/:id` → `alert`). First match wins:
 * literal routes sit above the `:param` routes at the same depth. Unknown
 * routes fall through to `'home'` so the card always has something to render.
 * Pages that register with `usePivtPage` may name their own key.
 */
const PAGE_ROUTES: ReadonlyArray<readonly [pattern: string, pageKey: string]> = [
  ['/', 'home'],
  ['/home', 'home'],
  ['/search', 'search'],
  ['/trace/:traceId', 'trace'],
  ['/observability/*', 'observability'],
  ['/reports', 'reports'],
  ['/getting-started', 'onboarding'],

  ['/alerts', 'alerts'],
  ['/alerts/:id', 'alert'],
  ['/rules/:id/matches', 'matches'],

  ['/rules/coverage', 'mitre-coverage'],
  ['/rules/tuning', 'ai-tuning'],
  ['/rules/tuning/:id', 'tuning-proposal'],
  ['/rules/ideas', 'rule-ideas'],
  ['/rules/repositories', 'rule-repositories'],
  ['/rules/editor/*', 'rule-editor'],
  ['/rules/retro-hunt/*', 'retro-hunt'],
  ['/rules/ioc-lists', 'ioc-lists'],
  ['/rules/lookup-tables/*', 'lookup-tables'],
  ['/rules', 'rules'],

  ['/hunts', 'hunts'],
  ['/hunts/leads', 'hunt-leads'],
  ['/hunts/leads/decisions', 'hunt-decisions'],
  ['/hunts/leads/:id', 'hunt-lead'],
  ['/hunts/knowledge', 'hunt-knowledge'],
  // NAN-5850: old hunt settings routes that redirect to their new homes;
  // listed so they never read as a hunt id.
  ['/hunts/memory', 'hunt-knowledge'],
  ['/hunts/suppressions', 'hunt-knowledge'],
  ['/hunts/rulings', 'hunt-decisions'],
  ['/hunts/runners', 'settings-hunts'],
  ['/hunts/rule-ideas', 'rule-ideas'],
  // NAN-5859: Campaigns became Actors. The old paths redirect; listed so
  // they never read as a hunt id.
  ['/hunts/actors', 'hunt-actors'],
  ['/hunts/actors/review', 'hunt-actor-review'],
  ['/hunts/actors/:id', 'hunt-actor'],
  ['/hunts/campaigns', 'hunt-actors'],
  ['/hunts/campaigns/candidates', 'hunt-actor-review'],
  ['/hunts/campaigns/:id', 'hunt-actor'],
  ['/hunts/escalations', 'hunt-escalations'],
  ['/hunts/profile', 'hunt-profile'],
  ['/hunts/:id', 'hunt'],

  ['/inbox', 'inbox'],
  ['/cases', 'inbox'],
  ['/cases/search', 'case-search'],
  ['/cases/:id', 'case'],

  ['/playbooks', 'playbooks'],
  ['/playbooks/new', 'playbook-editor'],
  ['/playbooks/repositories', 'playbook-repositories'],
  ['/automation/flows', 'automation-flows'],
  ['/automation/flows/:id', 'automation-flow'],
  ['/automation/capabilities', 'automation-capabilities'],
  ['/automation/*', 'automation-runs'],

  ['/dashboards', 'dashboards'],
  ['/dashboards/:id', 'dashboard'],
  ['/notebooks', 'notebooks'],
  ['/notebooks/:id', 'notebook'],

  ['/ingestion/log-sources', 'log-sources'],
  ['/ingestion/log-sources/new', 'add-source'],
  ['/ingestion/log-sources/onboarding', 'add-source'],
  ['/ingestion/log-sources/wizard', 'add-source'],
  ['/ingestion/log-sources/credentials', 'ingest-credentials'],
  ['/ingestion/log-sources/cloud-pull', 'cloud-pull'],
  ['/ingestion/log-sources/pull-feeds', 'pull-feeds'],
  ['/ingestion/log-sources/repositories', 'parser-repositories'],
  ['/ingestion/log-sources/inputs/:id', 'source-config'],
  ['/ingestion/log-sources/:id', 'log-source'],
  ['/ingestion/pipelines', 'pipelines'],
  ['/ingestion/pipelines/:id', 'pipeline'],
  ['/ingestion/*', 'log-sources'],
  ['/integrations/custom/*', 'custom-integration'],

  ['/marketplace', 'marketplace'],
  ['/enrichments/*', 'enrichments'],
  ['/prevalence', 'prevalence'],
  ['/risk', 'risk'],
  ['/risk/watchlists', 'risk-watchlists'],
  ['/platform/health', 'health'],
  ['/settings/hunts/*', 'settings-hunts'],
  ['/settings/*', 'settings'],
];

/** Map a pathname to a PIVT pageKey. See `PAGE_ROUTES`. */
export function pageKeyFor(pathname: string): string {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  for (const [pattern, key] of PAGE_ROUTES) {
    if (matchPath({ path: pattern, end: true }, path)) return key;
  }
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
 * returns a neutral default so PIVT doesn't crash on pages that forget
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
