// SPDX-License-Identifier: AGPL-3.0-or-later

import { readSchemaFieldEntry, readSchemaFieldString, type SemanticField } from '@/lib/schema-fields';

function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

/**
 * The "source" label of a search result row (the CSV `source` column, the tail
 * view): a finding's risk entity, else the host, else the source IP.
 *
 * NAN-5271: this read the UDM `src_host` / `src_ip` keys only, so every OCSF
 * row was "unknown". The concepts resolve through `schema-fields`, which tries
 * the UDM key and the OCSF columns (`device.hostname`, `src_endpoint.hostname`,
 * `src_endpoint.ip`); a UDM row reads exactly what it did before.
 */
export function resultRowSource(row: Record<string, unknown> | null | undefined): string {
  if (!row) return 'unknown';
  if (row.source_type === 'findings' || row['metadata.log_source'] === 'findings') {
    const metadata = row.metadata as Record<string, unknown> | undefined;
    const unmapped = row.unmapped as Record<string, unknown> | undefined;
    return (
      str(metadata?.risk_entity) ||
      str(row['unmapped.risk_entity']) ||
      str(unmapped?.risk_entity) ||
      'finding'
    );
  }
  return (
    readSchemaFieldString(row, 'host') ||
    readSchemaFieldString(row, 'srcIp') ||
    'unknown'
  );
}

const KEY_FIELD_CONCEPTS: readonly SemanticField[] = ['srcIp', 'destIp', 'user', 'url', 'host'];

/**
 * A short `key: value` summary of a result row's entities for the pivt
 * conversation context, keyed by the row's own column names (OCSF paths on an
 * OCSF row).
 */
export function resultRowKeyFields(row: Record<string, unknown> | null | undefined): string {
  const parts: string[] = [];
  for (const concept of KEY_FIELD_CONCEPTS) {
    const entry = readSchemaFieldEntry(row, concept);
    if (entry) parts.push(`${entry.key}: ${String(entry.value)}`);
  }
  return parts.join(', ');
}
