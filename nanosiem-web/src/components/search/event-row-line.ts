// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The line shown for each event in the search results stream (RawView).
 *
 * Every source renders the same way: a compact JSON line of the row's REAL
 * ingested fields. A top-level `message` (e.g. windows_event's "An account
 * failed to log on.") is NOT promoted to the row line — it stays a normal key
 * inside the JSON, like every other field (NAN-3010). Before that fix, rows with
 * `message` rendered the bare text while sysmon/conduit/apache/cloudtrail rows
 * rendered JSON, so one result list mixed two formats.
 *
 * Internal `_*` markers, `id`, and `timestamp` (already shown above the line)
 * are excluded, as are null/empty values. Nothing is stored or fabricated.
 * Returns null if there is nothing to show. `pretty` produces the indented form.
 */
export function buildEventRowLine(
  fields: Record<string, unknown> | undefined,
  pretty = false,
): string | null {
  if (!fields) return null;
  const obj: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (k.startsWith('_') || k === 'id' || k === 'timestamp') continue;
    if (v == null || v === '') continue;
    obj[k] = v;
  }
  if (Object.keys(obj).length === 0) return null;
  return pretty ? JSON.stringify(obj, null, 2) : JSON.stringify(obj);
}
