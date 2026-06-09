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
 */
function buildSchemaMap(
  resp: SchemaFieldsResponse | undefined,
  normalize?: Partial<Record<SchemaEntityType, string>>,
): { exact: Map<string, string>; suffix: Map<string, string> } {
  const exact = new Map<string, string>();
  const suffix = new Map<string, string>();
  if (!resp) return { exact, suffix };

  for (const f of resp.fields) {
    if (!f.entity_type) continue;
    const raw = f.entity_type as SchemaEntityType;
    const mapped = normalize?.[raw] ?? raw;
    const name = f.name.toLowerCase();
    exact.set(name, mapped);

    // Dotted OCSF names: index the trailing leaf (`src_endpoint.ip` → `ip`) so a
    // suffix lookup still classifies the field. First registration wins to avoid
    // an ambiguous leaf flipping types between equally-tailed fields.
    const dot = name.lastIndexOf('.');
    if (dot >= 0) {
      const leaf = name.slice(dot + 1);
      if (leaf && !suffix.has(leaf)) suffix.set(leaf, mapped);
    }
  }
  return { exact, suffix };
}

export function useSchemaEntityMap(options: UseSchemaEntityMapOptions = {}): SchemaEntityMap {
  const { fallback, normalize } = options;

  const { data: schemaFields } = useQuery({
    queryKey: ['schema-fields'],
    queryFn: () => api.getSchemaFields(),
    staleTime: Infinity,
    gcTime: Infinity,
  });

  const { exact, suffix } = useMemo(
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

        // 2. Suffix match on the dotted leaf (`event.src_endpoint.ip` → `.ip`).
        const dot = lower.lastIndexOf('.');
        if (dot >= 0) {
          const bySuffix = suffix.get(lower.slice(dot + 1));
          if (bySuffix) return bySuffix;
        }
      }

      // 3. Legacy UDM fallback — the sole source under UDM (byte-identical),
      //    and the OCSF safety net for names the schema response omits.
      return fallback?.[lower];
    },
    [useSchemaMap, exact, suffix, fallback],
  );

  return {
    ready: schemaFields != null,
    schema: schemaFields?.schema,
    schemaFields,
    resolveEntityType,
  };
}
