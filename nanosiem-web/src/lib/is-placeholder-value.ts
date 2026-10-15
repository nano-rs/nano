// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Is this a "no value" sentinel rather than a real entity/label?
 *
 * OCSF fields the parser had nothing to fill (no hostname on this event, no
 * domain in this URL, ...) commonly carry the literal placeholder `"-"`
 * rather than being left null/absent. Every grouping/labeling call site
 * (tree nodes, lateral-movement graph nodes, sequence/transaction/flow/
 * timechart series, asset artifact rows, ...) must reject this BEFORE
 * treating the value as a real artifact -- otherwise "-" becomes a plotted
 * node, a clickable pivot target, or a "rare artifact" in its own right.
 * `baseline.rs`/`baseline/mod.rs` already filter this server-side; this is
 * the client-side equivalent for the views that build labels from raw rows.
 */
export function isPlaceholderValue(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  const s = typeof value === 'string' ? value : String(value);
  const trimmed = s.trim();
  return trimmed === '' || trimmed === '-' || trimmed === '--';
}
