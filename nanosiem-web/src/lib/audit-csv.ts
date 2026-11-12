// SPDX-License-Identifier: AGPL-3.0-or-later
import type { AuditLogEntry } from './api/types';
import { auditActorLabel } from './audit-feed';
import { csvCellQuoted } from './csv-safe';

/** Audit fields can contain attacker-controlled names and resource text. */
export function auditCsvCell(value: string): string {
  return csvCellQuoted(value);
}

export const AUDIT_CSV_HEADERS = [
  'Timestamp',
  'Actor',
  'API Key',
  'Source',
  'Action',
  'Resource Type',
  'Resource Name',
  'IP Address',
  'Success',
  'Details',
] as const;

/**
 * The CSV for exactly the rows the table shows (same order, same actor label),
 * every cell quoted and formula-neutralized (NAN-3793).
 */
export function auditCsv(rows: AuditLogEntry[]): string {
  const body = rows.map((log) => [
    log.timestamp,
    auditActorLabel(log),
    log.api_key_name || log.api_key_id || '',
    log.source || '',
    log.action || '',
    log.resource_type || '',
    log.resource_name || '',
    log.ip_address || '',
    log.success ? 'Yes' : 'No',
    // NAN-5324: scopes granted, old → new values, denial reasons.
    log.details ? JSON.stringify(log.details) : '',
  ]);
  return [[...AUDIT_CSV_HEADERS], ...body].map((row) => row.map(auditCsvCell).join(',')).join('\n');
}
