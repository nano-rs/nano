// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Hold the EVENT STREAM across a re-run of the same search (NAN-3273).
 *
 * A fresh run clears the histogram so a different search cannot briefly show
 * the previous one's buckets, and the run's own read installs the
 * replacement. The timeline's "N events" is that histogram's sum, so every
 * re-run of the *same* search over a moved window (a live-tail re-run, a
 * time-window roll, a refresh) read "0 events" and drew an empty chart until
 * the read landed (live: 19 one-sample "0 events" blips in 10.5 min of tail).
 *
 * The page therefore keeps the last timeline it had for a search identity
 * (query, mode, dataset, rarity filter; deliberately not the time range) and
 * shows it while a re-run of that identity is pending. Whatever the run then
 * installs, an empty read included, replaces it: a window that is genuinely
 * empty still reads 0 once its read lands.
 */

import type { HistogramBucket } from './search-tail-histogram';

export interface TimelineIdentityInput {
  query: string;
  mode: string;
  dataset: string;
  prevalenceMax: number;
}

/** The search a timeline belongs to, independent of its time range. */
export function searchTimelineIdentity({ query, mode, dataset, prevalenceMax }: TimelineIdentityInput): string {
  return JSON.stringify([query.trim(), mode, dataset, prevalenceMax]);
}

/**
 * The histogram a run installs when it starts. Only this exact (empty) array
 * means "this run's read has not landed": anything the run installs, an empty
 * read included, is a different array and is shown as is. Never mutated.
 */
export const PENDING_TIMELINE: HistogramBucket[] = [];

export interface HeldTimeline {
  identity: string;
  histogram: HistogramBucket[];
}

/**
 * What a fresh run should hold on screen while its own read is pending.
 *
 * - A run of a different search holds nothing (its chart starts empty).
 * - A re-run of the same search holds the timeline on screen, or, when a
 *   previous re-run is itself still pending (`PENDING_TIMELINE` on screen),
 *   the timeline that one was holding.
 */
export function holdTimelineForRun(
  onScreen: { identity: string | null; histogram: HistogramBucket[] },
  pendingHold: HeldTimeline | null,
  nextIdentity: string,
): HeldTimeline | null {
  if (onScreen.identity !== nextIdentity) return null;
  if (onScreen.histogram.length > 0) return { identity: nextIdentity, histogram: onScreen.histogram };
  // Only a run still pending (nothing installed yet) carries its hold over; a
  // read that landed empty is the answer, and a later re-run starts from it.
  if (onScreen.histogram === PENDING_TIMELINE && pendingHold
    && pendingHold.identity === nextIdentity && pendingHold.histogram.length > 0) return pendingHold;
  return null;
}

/** The histogram the timeline renders: the committed one, or the held one while a re-run is pending. */
export function displayedHistogram(histogram: HistogramBucket[], hold: HeldTimeline | null): HistogramBucket[] {
  return histogram === PENDING_TIMELINE && hold ? hold.histogram : histogram;
}
