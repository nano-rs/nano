// SPDX-License-Identifier: AGPL-3.0-or-later

/** A result row as the Search page holds it. */
export interface ResultRow {
  id: string;
  fields: Record<string, unknown>;
}

/**
 * Stable identity for a result row (NAN-2551). Offset-derived `result-N` ids
 * are positional, so they cannot be compared across requests (a live-tail
 * prepend or a re-run shifts every one of them). The event's own identity can:
 * OCSF `metadata.uid` when the row carries it, else the ClickHouse event `id`
 * that every `table_view` row returns.
 */
export function rowKey(row: ResultRow): string {
  const metadata = row.fields.metadata;
  const uid = row.fields['metadata.uid']
    ?? (metadata && typeof metadata === 'object' ? (metadata as Record<string, unknown>).uid : undefined);
  if (typeof uid === 'string' && uid.length > 0) return `uid:${uid}`;
  const eventId = row.fields.id;
  if (typeof eventId === 'string' && eventId.length > 0) return `event:${eventId}`;
  return `id:${row.id}`;
}
