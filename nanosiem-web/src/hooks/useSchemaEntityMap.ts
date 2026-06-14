// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * useSchemaEntityMap — schema-aware field → entity-type resolution (NAN-1241).
 *
 * The active schema profile (UDM default, or OCSF when `NANO_SCHEMA_PROFILE=ocsf`)
 * exposes its field set through `GET /api/schema/fields` / `api.getSchemaFields()`.
 * Each field carries an optional `entity_type` (`ip` | `host` | `user` | `hash` |
 * `domain` | `url`) describing the security entity it denotes.
 *
 * Before this hook, consumers hardcoded UDM-only `FIELD_TO_ENTITY_TYPE` maps, so
 * OCSF result rows (`src_endpoint.ip`, `actor.user.name`, …) silently extracted
 * no entities: no notebook buttons, no identity popovers, no drilldowns.
 *
 * The resolver returned here:
 *   1. Looks the field up in the schema-derived map (exact, then dotted-suffix
 *      match so `src_endpoint.ip` resolves via its `.ip` tail when only the leaf
 *      is registered — OCSF promoted columns are dotted).
 *   2. Falls back to the consumer-supplied legacy UDM map, which guarantees the
 *      UDM output stays byte-identical (the schema map for UDM returns the same
 *      values the legacy map did, and the legacy map covers any name the schema
 *      response happens to omit).
 *
 * Backend entity vocabulary is the snake_case `EntityType` enum: `host` (not
 * `hostname`). Consumers that historically used `hostname` pass a `normalize`
 * option so their legacy vocabulary is preserved byte-for-byte.
 */

import { useQuery } from '@tanstack/react-query';
import { useMemo, useCallback } from 'react';
import { api } from '@/lib/api';
import type { SchemaFieldsResponse } from '@/lib/api/types';

/** Canonical entity-type vocabulary as emitted by the backend schema profile. */
export type SchemaEntityType = 'ip' | 'host' | 'user' | 'hash' | 'domain' | 'url';

export interface UseSchemaEntityMapOptions {
  /**
   * Legacy hardcoded `field → entityType` map for the consuming surface. Used as
   * the fallback when the active schema response doesn't classify a field. This
   * keeps UDM output byte-identical for any name not covered by the schema set.
   */
  fallback?: Record<string, string>;
  /**
   * Optional remap of the backend's canonical entity-type strings onto the
   * consumer's local vocabulary (e.g. `{ host: 'hostname' }`). Applied only to
   * schema-derived hits; fallback values are returned verbatim.
   */
  normalize?: Partial<Record<SchemaEntityType, string>>;
}

export interface SchemaEntityMap {
  /** True once `/api/schema/fields` has resolved. */
  ready: boolean;
  /** Active schema discriminator (`udm` | `ocsf`), undefined until loaded. */
  schema: string | undefined;
  /** Raw schema response (memo-stable via React Query cache). */
  schemaFields: SchemaFieldsResponse | undefined;
  /**
   * Resolve a result-row field name to an entity type, or `undefined` when the
   * field denotes no security entity. Suffix-aware for dotted OCSF names; falls
   * back to the supplied legacy UDM map.
   */
  resolveEntityType: (fieldName: string) => string | undefined;
}

/**
 * Build a `field-name (lowercased) → entityType` map from a schema response,
 * indexing both the full dotted name and its trailing leaf segment so dotted
 * OCSF columns resolve by suffix.
 *
 * Suffix matching is deliberately conservative (NAN-1448). OCSF reuses generic
 * leaves across entity and non-entity fields: `.name` tails `user.name` (→user)
 * but also `module.file.name`, `process.name`, `file.name`, … (all
 * `entity_type: null`); `.uid` and `.hostname` are likewise mixed/conflicting.
 * Indexing the bare leaf made every `.name` field resolve to `user`, so
 * `module.file.name` wrongly offered "Open entity page". A leaf is therefore
 * only suffix-eligible when EVERY field sharing it is an entity AND they all
 * agree on a single type. Fields the schema explicitly marks non-entity are
 * collected into `nonEntity` so resolution honors that decision instead of
 * falling through to a suffix guess.
 */
function buildSchemaMap(
  resp: SchemaFieldsResponse | undefined,
  normalize?: Partial<Record<SchemaEntityType, string>>,
): { exact: Map<string, string>; suffix: Map<string, string>; nonEntity: Set<string> } {
  const exact = new Map<string, string>();
  const nonEntity = new Set<string>();
  if (!resp) return { exact, suffix: new Map(), nonEntity };

  // Per-leaf accounting: the distinct entity types seen on that leaf, and
  // whether any field sharing it is a non-entity. Either ambiguity disqualifies
  // the leaf from suffix matching.
  const leafTypes = new Map<string, Set<string>>();
  const leafHasNonEntity = new Set<string>();

  for (const f of resp.fields) {
    const name = f.name.toLowerCase();
    const dot = name.lastIndexOf('.');
    const leaf = dot >= 0 ? name.slice(dot + 1) : '';

    if (!f.entity_type) {
      nonEntity.add(name);
      if (leaf) leafHasNonEntity.add(leaf);
      continue;
    }
    const raw = f.entity_type as SchemaEntityType;
    const mapped = normalize?.[raw] ?? raw;
    exact.set(name, mapped);
    if (leaf) {
      let types = leafTypes.get(leaf);
      if (!types) { types = new Set(); leafTypes.set(leaf, types); }
      types.add(mapped);
    }
  }

  const suffix = new Map<string, string>();
  for (const [leaf, types] of leafTypes) {
    if (types.size === 1 && !leafHasNonEntity.has(leaf)) {
      suffix.set(leaf, types.values().next().value as string);
    }
  }
  return { exact, suffix, nonEntity };
}

export function useSchemaEntityMap(options: UseSchemaEntityMapOptions = {}): SchemaEntityMap {
  const { fallback, normalize } = options;

  const { data: schemaFields } = useQuery({
    queryKey: ['schema-fields'],
    queryFn: () => api.getSchemaFields(),
    staleTime: Infinity,
    gcTime: Infinity,
  });

  const { exact, suffix, nonEntity } = useMemo(
    () => buildSchemaMap(schemaFields, normalize),
    [schemaFields, normalize],
  );

  // Under the UDM profile the consumers' legacy `fallback` maps ARE the
  // pre-existing behavior, and the backend's `infer_entity_type` diverges from
  // them (e.g. `dest_host` → `host` backend vs `domain` legacy; `process_name`/
  // `file_*` newly classified). Letting the schema-derived map win under UDM
  // would silently change UDM output, violating the byte-identical mandate
  // (NAN-1241). So we only consult the schema map for non-UDM schemas; UDM stays
  // fallback-only (exactly the old behavior). OCSF has no legacy baseline to
  // preserve, so schema-first is correct there.
  const useSchemaMap = schemaFields != null && schemaFields.schema !== 'udm';

  const resolveEntityType = useCallback(
    (fieldName: string): string | undefined => {
      if (!fieldName) return undefined;
      const lower = fieldName.toLowerCase();

      if (useSchemaMap) {
        // 1. Exact schema match (OCSF flat + dotted names).
        const direct = exact.get(lower);
        if (direct) return direct;

        // 2. Schema says this field is a non-entity — honor it rather than
        //    guessing from an ambiguous leaf (NAN-1448: `module.file.name` is
        //    `entity_type: null`, so it must NOT resolve to `user` via `.name`).
        if (nonEntity.has(lower)) return undefined;

        // 3. Suffix match on the dotted leaf (`event.src_endpoint.ip` → `.ip`),
        //    restricted to unambiguous leaves by buildSchemaMap.
        const dot = lower.lastIndexOf('.');
        if (dot >= 0) {
          const bySuffix = suffix.get(lower.slice(dot + 1));
          if (bySuffix) return bySuffix;
        }
      }

      // 4. Legacy UDM fallback — the sole source under UDM (byte-identical),
      //    and the OCSF safety net for names the schema response omits.
      return fallback?.[lower];
    },
    [useSchemaMap, exact, suffix, nonEntity, fallback],
  );

  return {
    ready: schemaFields != null,
    schema: schemaFields?.schema,
    schemaFields,
    resolveEntityType,
  };
}
