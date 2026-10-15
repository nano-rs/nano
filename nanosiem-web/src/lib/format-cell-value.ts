// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Format a raw result-field value for display in a table/list cell.
 *
 * NAN-1466: `Array(String)` columns (hashes, url.categories, tags, ...) are
 * common in OCSF -- even a "single" hash is stored as a one-element array.
 * Rendered as a comma-join rather than a JSON blob, so `["abc123"]` reads as
 * `abc123` instead of leaking ClickHouse's on-wire array shape into the UI.
 * Nested arrays/objects (no sane scalar join) still fall through to JSON.
 */
export function formatCellValue(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (Array.isArray(value)) {
    if (value.every((v) => v === null || typeof v !== 'object')) {
      return value.filter((v) => v !== null && v !== undefined).map(String).join(', ');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
