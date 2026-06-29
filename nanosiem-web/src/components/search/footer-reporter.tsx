// SPDX-License-Identifier: AGPL-3.0-or-later

// Phase-2 footer reporter contract (NAN-1598).
//
// Several special display modes are TWO-PHASE: the primary `/api/search`
// returns a tiny synthetic marker row, then the view component fires its own
// fetch to do the real work. The footer (`SearchStatsBar`) is driven by
// Search.tsx state set from the marker response, so without this contract it
// flips to "Query complete · ~0 hits · 0ms" the instant the marker lands —
// while the real view is still loading.
//
// This module gives a phase-2 view a channel to publish its status back to the
// footer. Search.tsx provides the reporter; a view consumes it via
// `useReportPhase2()` and calls it on fetch start / resolve.

import { createContext, useContext, useEffect, useRef } from 'react';
import type { DisplayType } from '@/lib/api/types';

export interface Phase2Status {
  /** True while the phase-2 fetch is in flight. */
  loading: boolean;
  /** Real query time. Omit when unknown — the footer then shows no time rather
   * than a misleading 0. */
  executionTimeMs?: number;
  /** Headline hit count for the mode (e.g. span count for a trace). */
  totalCount?: number;
}

export type Phase2Reporter = (status: Phase2Status) => void;

const noop: Phase2Reporter = () => {};

const SearchFooterContext = createContext<Phase2Reporter>(noop);

export const SearchFooterProvider = SearchFooterContext.Provider;

/**
 * Phase-2 search views publish `{ loading, executionTimeMs, totalCount }` to the
 * footer via this hook. Returns a no-op when rendered outside the provider —
 * e.g. the same view component reused inside the Observability console, which
 * owns its own status UI and must not be coupled to the search footer.
 */
export function useReportPhase2(): Phase2Reporter {
  return useContext(SearchFooterContext);
}

/**
 * Convenience adapter for the common shape: a phase-2 view with a `loading`
 * flag and a settled (`data || error`) state. Measures the fetch client-side
 * and reports `loading` then `{ executionTimeMs, totalCount }` on settle.
 * Robust to an instant cache hit (reports done even with no observed loading
 * transition) so the footer never hangs; omits the time when no real fetch was
 * measured rather than reporting a misleading 0ms. No-op outside the provider.
 */
export function useReportPhase2Status(opts: {
  loading: boolean;
  /** True once the fetch has resolved (data present) or errored. */
  settled: boolean;
  error?: unknown;
  /** Headline hit count for the mode; omit while unknown. */
  totalCount?: number;
}): void {
  const { loading, settled, error, totalCount } = opts;
  const report = useReportPhase2();
  const startRef = useRef<number | null>(null);
  useEffect(() => {
    if (loading) {
      if (startRef.current == null) startRef.current = performance.now();
      report({ loading: true });
      return;
    }
    if (settled) {
      const ms = startRef.current != null ? Math.round(performance.now() - startRef.current) : undefined;
      startRef.current = null;
      report(error ? { loading: false } : { loading: false, executionTimeMs: ms, totalCount });
    }
  }, [loading, settled, error, totalCount, report]);
}

/**
 * Display modes whose phase-2 view actually calls `reportPhase2`. The footer's
 * "suppress Query-complete until phase-2 reports" gate applies ONLY to these.
 *
 * IMPORTANT: adding a mode here without its view adopting the reporter would
 * hang the footer on the spinner forever. Adopt the reporter first, then list
 * the mode. trace = NAN-1599; retro / cloud / service(s) / metric = NAN-1600.
 */
export const PHASE2_REPORTING_MODES: ReadonlySet<DisplayType> = new Set<DisplayType>([
  'trace',
  'retro',
  'cloud',
  'service',
  'services',
  'metric',
]);
