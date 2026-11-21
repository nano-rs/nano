// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5702: the columns a results table shows, in display order.
 *
 * The backend's `column_order` is derived from the pipeline's `stats` / `eval`
 * / `table` commands. Commands after them can add columns it does not name,
 * such as a `join`'s subsearch fields, a `lookup`, `rex` or `rename`. Filtering
 * the rows' keys by `column_order` alone hid those columns although every row
 * carried them. The known order comes first, then every other column the rows
 * carry, in first-seen order, so no output column is ever dropped.
 */
export function completeColumnOrder(
  columnOrder: readonly string[] | undefined | null,
  rows: ReadonlyArray<Record<string, unknown> | undefined | null>,
): string[] {
  const present: string[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    if (!row) continue;
    for (const key of Object.keys(row)) {
      if (!seen.has(key)) {
        seen.add(key);
        present.push(key);
      }
    }
  }
  if (!columnOrder || columnOrder.length === 0) return present;
  const ordered = columnOrder.filter((key, i) => seen.has(key) && columnOrder.indexOf(key) === i);
  const named = new Set(ordered);
  return [...ordered, ...present.filter((key) => !named.has(key))];
}
