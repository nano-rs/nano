// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Sentinel `dimension_details` values that mean "no per-dimension prose",
 * mirroring `HEURISTIC_DIMENSION_DETAIL` in
 * `nanosiem-core/src/siem_health/analyzer.rs` (which is edition-aware).
 *
 * Two consumers must agree on this and used to drift (NAN-2357): the Health
 * page decides whether to render the "Analysis" block, and the global footer
 * decides whether to show the ingestion detail. The footer only knew about the
 * enterprise string, so the open-edition placeholder would have surfaced as
 * "Scored from live metrics" in the status bar in place of a real score.
 *
 * Match on the value, NOT on the meloD capability. A Fresh or Stalled report
 * fills these fields with genuinely useful deterministic prose ("No events in
 * the last 48h…"), and gating on the capability would throw that away in open.
 */
const PLACEHOLDER_DIMENSION_DETAILS: readonly string[] = [
  'AI analysis unavailable',
  'Scored from live metrics',
];

/** True when the detail carries no real prose and should not be rendered. */
export function isPlaceholderDimensionDetail(detail?: string | null): boolean {
  if (!detail) return true;
  return PLACEHOLDER_DIMENSION_DETAILS.includes(detail.trim());
}
