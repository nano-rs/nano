// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Parse a string value into the appropriate type for a lookup table column.
 * Used by both LookupTableCreate (schema mode) and LookupTableView (inline edit).
 */
export function parseValueForType(value: string, dataType: string): unknown {
  if (value === '' || value === 'null') return null;

  switch (dataType) {
    case 'integer': {
      const n = parseInt(value, 10);
      return isNaN(n) ? value : n;
    }
    case 'float': {
      const f = parseFloat(value);
      return isNaN(f) ? value : f;
    }
    case 'boolean':
      return value.toLowerCase() === 'true' || value === '1';
    case 'json':
      try { return JSON.parse(value); } catch { return value; }
    default:
      return value;
  }
}
