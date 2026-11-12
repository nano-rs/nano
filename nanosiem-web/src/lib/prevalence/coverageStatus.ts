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

function utcMinute(iso: string): string {
  return iso.slice(0, 16).replace('T', ' ');
}

/**
 * When prevalence will cover the whole window: its first bucket plus the
 * window length. NAN-5285: the old copy promised "next refresh in about 10
 * min", but a young install warms until prevalence spans the whole window
 * (30 days for the Rarity view), so the label must say that date.
 */
function fullyCoveredAt(state: PrevalenceProductState, nowMs: number): string | null {
  if (!state.covered_since) return null;
  const since = Date.parse(state.covered_since);
  const start = Date.parse(state.window_start);
  if (!Number.isFinite(since) || !Number.isFinite(start)) return null;
  const windowMs = Math.max(0, nowMs - start);
  return utcMinute(new Date(since + windowMs).toISOString());
}

/** One-line status for a list / explorer response, or null when ready. */
export function prevalenceStatusLabel(
  state: PrevalenceProductState | undefined | null,
  nowMs: number = Date.now(),
): string | null {
  if (!state) return null;
  if (state.warming) {
    const m = minutes(state.retry_after_s);
    if (state.covered_since) {
      const at = fullyCoveredAt(state, nowMs);
      return `Warming up: prevalence started ${utcMinute(state.covered_since)} UTC on this install, inside this window${at ? `. The window is fully covered from about ${at} UTC` : ''}. Until then an artifact's host count is unknown, not rare.`;
    }
    return `Warming up: no prevalence yet for at least one artifact kind in this view (file hashes, domains or IPs). It starts within about ${m ?? 10} min of the first event that carries that kind; with no such events (for example no DNS or proxy logs) that kind stays unknown.`;
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
