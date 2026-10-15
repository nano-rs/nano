// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Spreadsheet-safe CSV cells — the one helper every client-side CSV export uses.
 * Mirrors `nanosiem-core/src/csv_safe.rs`: a cell a spreadsheet would evaluate
 * (leading `=`, `+`, `-`, `@`, also behind whitespace, or a leading tab/CR/LF)
 * gets a single `'` "treat as text" prefix. Genuine numbers (`-5`, `-1.25`) stay
 * numeric. A cell that is already `'`-guarded formula text gets one more `'`, so
 * the mapping stays reversible for importers.
 */
const PLAIN_NUMBER = /^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/u;

function isFormulaLike(value: string): boolean {
  if (/^[\t\r\n]/u.test(value)) return true;
  const trimmed = value.trimStart();
  return /^[=+\-@]/u.test(trimmed) && !PLAIN_NUMBER.test(trimmed.trimEnd());
}

/** Prefix `'` to a cell a spreadsheet would evaluate as a formula. */
export function neutralizeCsvFormula(value: string): string {
  return isFormulaLike(value.replace(/^'+/u, '')) ? `'${value}` : value;
}

/** Neutralize, then quote per RFC 4180 when the cell holds `,` `"` CR or LF. */
export function csvCell(value: unknown): string {
  const safe = neutralizeCsvFormula(value == null ? '' : String(value));
  return /[",\n\r]/u.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

/** {@link csvCell} that always wraps the cell in quotes. */
export function csvCellQuoted(value: unknown): string {
  return `"${neutralizeCsvFormula(value == null ? '' : String(value)).replace(/"/g, '""')}"`;
}
