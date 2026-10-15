// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Parse a timestamp string as UTC.
 *
 * Database/lake-sourced timestamps commonly arrive NAIVE
 * ("YYYY-MM-DD HH:MM:SS.ffffff", no zone suffix); a bare `new Date(...)` on
 * that parses as LOCAL time and shifts every rendered time by the viewer's
 * UTC offset. Append `Z` only when no zone info is present. Extracted from
 * TimelineVisualization so every timestamp-consuming surface shares the one
 * correct parse.
 *
 * A missing/empty input yields an INVALID Date, never `new Date()`. The inline
 * version this was extracted from returned "now", which silently turns "this
 * event has no timestamp" into "this event happened just now" — on a rarity
 * chart that reads as a fresh sighting at the right-hand edge. Callers that
 * structurally need a Date must decide what an unknown time means (usually:
 * drop the row) rather than inherit a fabricated one. `lib/date-utils.ts`
 * re-exports this so the two copies cannot drift apart again.
 */
export function parseTimestampAsUTC(timestamp: string | Date | null | undefined): Date {
  if (!timestamp) return new Date(NaN);
  if (timestamp instanceof Date) return timestamp;

  // If it already has timezone info (Z or +/-), parse directly
  if (timestamp.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(timestamp)) {
    return new Date(timestamp);
  }

  // Database format: "YYYY-MM-DD HH:MM:SS.ffffff" - append Z to treat as UTC
  const isoString = timestamp.replace(' ', 'T') + 'Z';
  return new Date(isoString);
}
