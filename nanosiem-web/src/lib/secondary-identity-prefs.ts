// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Shared "secondary identity" preference lists for card/sequence subheaders
 * (NAN-1241). Transaction cards and the sequence view both pick a secondary
 * identity column (host / user / ip) to label a group when the primary grouping
 * field isn't itself an identity.
 *
 * Historically each view hardcoded a UDM-only list, so under OCSF the dotted
 * promoted columns (`src_endpoint.ip`, `actor.user.name`, …) never matched and
 * the subheader was blank. These builders take a `SchemaFieldsResponse` and
 * return the UDM base list (byte-identical when the schema is UDM or unknown)
 * unioned with the active schema's identity field names. UDM rows never carry
 * the OCSF dotted keys, so appending them is inert under UDM.
 */

import type { SchemaFieldsResponse } from '@/lib/api/types';

/** UDM base preference list for the transaction-card subheader (host/ip first). */
export const TRANSACTION_SECONDARY_BASE: readonly string[] = [
  'host', 'hostname', 'src_host', 'dest_host', 'dest_ip', 'src_ip', 'dest_host_name',
];

/** UDM base preference list for the sequence-view secondary line (user/host). */
export const SEQUENCE_SECONDARY_BASE: readonly string[] = [
  'user', 'user_name', 'username', 'host', 'hostname', 'src_host', 'dest_host',
];

/**
 * Append the active schema's host/user/ip identity field names to a UDM base
 * list, preserving base order first (so UDM output is byte-identical) and
 * de-duplicating. Under UDM (or before the schema loads) the base list is
 * returned unchanged.
 */
export function buildSecondaryPrefs(
  base: readonly string[],
  schemaFields: SchemaFieldsResponse | undefined,
): string[] {
  if (!schemaFields || schemaFields.schema === 'udm') {
    return [...base];
  }
  const seen = new Set(base);
  const out = [...base];
  for (const f of schemaFields.fields) {
    const et = f.entity_type;
    if (et === 'host' || et === 'user' || et === 'ip') {
      if (!seen.has(f.name)) {
        seen.add(f.name);
        out.push(f.name);
      }
    }
  }
  return out;
}
