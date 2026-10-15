// SPDX-License-Identifier: AGPL-3.0-or-later
import { csvCell } from './csv-safe.ts';

/** Escape a search result or column name for a spreadsheet CSV export. */
export function searchCsvCell(value: string): string {
  return csvCell(value);
}
