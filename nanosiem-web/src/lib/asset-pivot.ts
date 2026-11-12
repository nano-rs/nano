// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Asset-view pivots (`| asset`) built from a clicked field, the asset's
 * primary identifier, or its Investigate action (NAN-5312).
 *
 * `| asset field=<f>` accepts both the UDM names and the OCSF paths of the
 * host / IP / user concepts (nanosiem-core `canonical_entity_field`, NAN-5277).
 * Under OCSF the pivot therefore keeps the clicked OCSF path instead of
 * rewriting it to UDM `src_host`. A field the schema tags as a host entity but
 * that `| asset` cannot seed from (`device.uid`, a device identifier rather
 * than a hostname) gets no asset pivot, instead of being searched as if it
 * were a hostname.
 */

import {
  buildFieldFilter,
  type SchemaProfileId,
  type SemanticField,
} from './schema-fields';

/**
 * OCSF fields `| asset field=` seeds from, mirroring
 * `nanosiem-core/src/schema/entities.rs` (`ocsf_columns` +
 * `ocsf_indexed_column` for the SrcHost / DestHost / SrcIp / DestIp / User
 * kinds). UDM canonical names are accepted too, since the OCSF query resolver
 * maps them. `asset-pivot.drift.test.ts` fails when this drifts from the Rust.
 */
export const OCSF_ASSET_SEED_FIELDS: ReadonlySet<string> = new Set([
  'device.hostname',
  'src_endpoint.hostname',
  'dst_endpoint.hostname',
  'src_host_unified',
  'src_endpoint.ip',
  'dst_endpoint.ip',
  'user.name',
  'actor.user.name',
  'user_unified',
  'src_host',
  'dest_host',
  'src_ip',
  'dest_ip',
  'user',
]);

/** UDM: entity type → the canonical field `| asset` resolves (NAN-1452). */
const UDM_ENTITY_TYPE_TO_ASSET_FIELD: Record<string, string> = {
  ip: 'src_ip',
  host: 'src_host',
  user: 'user',
};

/**
 * The field an "Open asset view" pivot filters on and passes as
 * `| asset field=`, or null when this field cannot seed an asset view.
 */
export function assetPivotField(
  fieldName: string,
  entityType: string | undefined,
  profile: SchemaProfileId,
): string | null {
  const field = fieldName.trim();
  if (profile === 'ocsf') {
    return OCSF_ASSET_SEED_FIELDS.has(field) ? field : null;
  }
  // UDM: unchanged legacy mapping onto the canonical identifier.
  return UDM_ENTITY_TYPE_TO_ASSET_FIELD[entityType ?? ''] ?? field;
}

/** UDM canonical identifier → the concept whose columns hold it. */
const CANONICAL_TO_CONCEPT: Record<string, SemanticField> = {
  src_host: 'host',
  dest_host: 'destHost',
  src_ip: 'srcIp',
  dest_ip: 'destIp',
  user: 'user',
};

/**
 * Translate an Investigate / primary-identifier filter into the active
 * profile's columns. `| asset` reports its primary identifier by UDM
 * canonical name (`src_host`) even under OCSF; this turns that into an OR over
 * the OCSF columns (`device.hostname` / `src_endpoint.hostname`) so the pivot
 * names OCSF fields. UDM output is unchanged.
 */
export function profileEntityFilter(
  filters: Record<string, unknown>,
  profile: SchemaProfileId,
): Record<string, unknown> {
  if (profile !== 'ocsf') return filters;
  const out: Record<string, unknown> = {};
  const clauses: string[] = [];
  for (const [key, value] of Object.entries(filters)) {
    const concept = CANONICAL_TO_CONCEPT[key];
    if (concept && typeof value === 'string' && value !== '') {
      clauses.push(buildFieldFilter(profile, concept, value));
    } else {
      out[key] = value;
    }
  }
  if (clauses.length === 0) return out;
  const existing = typeof out._rawClause === 'string' && out._rawClause ? [out._rawClause] : [];
  out._rawClause = [...existing, ...clauses].join(' AND ');
  return out;
}

/** Which identity bucket a primary identifier field belongs to. */
export function primaryIdentityKind(field: string): 'hostname' | 'ip' | 'user' | null {
  switch (field.trim()) {
    case 'src_host':
    case 'dest_host':
    case 'host':
    case 'hostname':
    case 'device.hostname':
    case 'src_endpoint.hostname':
    case 'dst_endpoint.hostname':
    case 'src_host_unified':
      return 'hostname';
    case 'src_ip':
    case 'dest_ip':
    case 'src_endpoint.ip':
    case 'dst_endpoint.ip':
      return 'ip';
    case 'user':
    case 'src_user':
    case 'user.name':
    case 'actor.user.name':
    case 'user_unified':
      return 'user';
    default:
      return null;
  }
}
