// SPDX-License-Identifier: AGPL-3.0-or-later
import { csvCellQuoted } from './csv-safe.ts';

/** Audit fields can contain attacker-controlled names and resource text. */
export function auditCsvCell(value: string): string {
  return csvCellQuoted(value);
}
