// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Prevalence coverage copy (NAN-4902 lane E; main's explorerStatus /
 * detailWarming, re-based on the ClickHouse `product_state`).
 *
 * A miss is only "not seen" when prevalence covers the window. While it warms
 * up (young install) or covers only part of the window, the API returns
 * `host_count: null` and these labels say why, instead of a misleading zero.
 */
import type { PrevalenceProductState } from '@/lib/api/types';

/** How often the page re-polls while warming / stale (the snapshot refreshes every 10 min). */
export const PREVALENCE_STATUS_POLL_MS = 60_000;

function minutes(seconds: number | undefined): number | null {
  if (seconds === undefined || !Number.isFinite(seconds) || seconds <= 0) return null;
  return Math.max(1, Math.ceil(seconds / 60));
}

/** One-line status for a list / explorer response, or null when ready. */
export function prevalenceStatusLabel(state: PrevalenceProductState | undefined | null): string | null {
  if (!state) return null;
  if (state.warming) {
    const m = minutes(state.retry_after_s);
    return state.covered_since
      ? `Warming up: prevalence starts ${state.covered_since.slice(0, 16).replace('T', ' ')} UTC, inside this window. Results fill in as it ages${m ? `; next refresh in about ${m} min` : ''}.`
      : `Warming up: no prevalence aggregated yet${m ? `; first results in about ${m} min after artifact events arrive` : ''}.`;
  }
  if (state.stale) {
    const m = minutes(state.age_s);
    return `Showing an older snapshot${m ? ` (${m} min old)` : ''}: waiting for the next refresh.`;
  }
  if (state.partial) {
    return 'Partial coverage: prevalence starts inside this window, so earlier activity is missing from these counts.';
  }
  return null;
}

/** Whether a response should be re-polled until its state settles. */
export function shouldPollPrevalence(state: PrevalenceProductState | undefined | null): boolean {
  return Boolean(state?.warming || state?.stale);
}

/** Label for one artifact whose host count is unknown (`host_count: null`). */
export const UNKNOWN_HOSTS_LABEL = 'Unknown: prevalence does not cover this window yet';
