// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ArtifactDetailCoverage } from '@/lib/api/types';

/**
 * NAN-3766: a very common artifact's detail is counted newest-first within a
 * fixed budget, so its facets may cover only the newest part of the window.
 * These helpers disclose that the same way the FieldsPanel discloses a
 * sampled field ("sample · last 1h"): never present partial counts as exact.
 */

/** Whether the counts are anything other than the whole window, exactly. */
export function isPartialCoverage(coverage: ArtifactDetailCoverage | undefined): coverage is ArtifactDetailCoverage {
  return coverage != null && (!coverage.complete || coverage.approximate);
}

/** "45m", "6h", "2d 4h": rounded down, so the label never overstates coverage. */
export function coverageSpan(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return '0m';
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 60) return `${Math.max(minutes, 1)}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h`;
  const days = Math.floor(hours / 24);
  const rest = hours % 24;
  return rest === 0 ? `${days}d` : `${days}d ${rest}h`;
}

function scannedMs(coverage: ArtifactDetailCoverage): number {
  return Date.parse(coverage.scanned_end) - Date.parse(coverage.scanned_start);
}

/** "partial · last 6h of 7d" (plus "· approx" / "· refining…"), or null when exact. */
export function detailCoverageLabel(coverage: ArtifactDetailCoverage | undefined, window: string): string | null {
  if (!isPartialCoverage(coverage)) return null;
  const parts = [coverage.complete ? 'approximate' : `partial · last ${coverageSpan(scannedMs(coverage))} of ${window}`];
  if (!coverage.complete && coverage.approximate) parts.push('approx');
  if (coverage.refining) parts.push('refining…');
  return parts.join(' · ');
}

/** The hover explanation of [`detailCoverageLabel`]. */
export function detailCoverageTitle(coverage: ArtifactDetailCoverage, window: string): string {
  const sentences: string[] = [];
  if (!coverage.complete) {
    sentences.push(
      `Partial: counted over ${coverage.scanned_start} – ${coverage.scanned_end}, the newest ` +
        `${coverageSpan(scannedMs(coverage))} of this ${window} window. Counts cover only that range.`,
    );
  }
  if (coverage.approximate) {
    sentences.push('Approximate: a facet had too many distinct values to count exactly; counts can be lower bounds.');
  }
  sentences.push(coverage.refining ? 'A wider answer is still being built.' : 'Search events for exact counts over the whole window.');
  return sentences.join(' ');
}
