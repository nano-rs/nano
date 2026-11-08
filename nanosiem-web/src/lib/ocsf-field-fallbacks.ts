import { SEMANTIC_FIELDS, type SemanticField } from './schema-fields';

/**
 * OCSF native-column fallbacks for UDM-semantic concepts (NAN-1322/NAN-1324).
 *
 * Under OCSF the search/asset rows are keyed by NATIVE OCSF columns
 * (`process.name`, `user.name`, `dst_endpoint.hostname`, …) instead of UDM
 * names, so UDM-keyed accessors (`row.process_name`) read `undefined`. Resolve a
 * UDM concept through `fieldVal`: the UDM key is checked FIRST (so under UDM the
 * value is byte-identical), then the native OCSF column(s).
 *
 * NAN-4903: derived from the profile-aware field map (`./schema-fields`), the
 * single source of truth — keyed by each concept's UDM column, valued with the
 * union of the OCSF columns of every concept sharing that UDM column (`src_host`
 * is both `srcHost` and `host`, so it falls back to `src_endpoint.hostname` and
 * `device.hostname`). New code should name the concept and use
 * `readSchemaField` / `useSchemaFieldMap` directly.
 */
export const OCSF_FIELD_FALLBACKS: Record<string, string[]> = (() => {
  const out: Record<string, string[]> = {};
  for (const key of Object.keys(SEMANTIC_FIELDS) as SemanticField[]) {
    const def = SEMANTIC_FIELDS[key];
    const udm = def.udm[0];
    const list = out[udm] ?? [];
    for (const col of def.ocsf) if (col !== udm && !list.includes(col)) list.push(col);
    if (list.length) out[udm] = list;
  }
  return out;
})();

/** A value is "empty" if it's null/undefined/'' or the `"-"` placeholder that
 *  many sources (Sysmon, syslog) emit for an absent field. */
function isEmptyVal(v: unknown): boolean {
  return (
    v === null ||
    v === undefined ||
    v === '' ||
    (typeof v === 'string' && v.trim() === '-')
  );
}

/**
 * Resolve a UDM concept to the ACTUAL key it lives under + its value, checking
 * the UDM key first (byte-identical under UDM) then the native OCSF column(s).
 * Returns `null` when no non-empty value exists. The `key` is the matched
 * column, so callers can display the schema-native name (`process.name` under
 * OCSF, `process_name` under UDM) — keeping the collapsed summary consistent with
 * the native-keyed detail (NAN-1326). `"-"` placeholders are treated as empty, so
 * a Sysmon `dst_endpoint.hostname = "-"` falls through to the next candidate.
 */
export function fieldEntry(
  fields: Record<string, unknown>,
  concept: string,
): { key: string; value: unknown } | null {
  const direct = fields[concept];
  if (!isEmptyVal(direct)) return { key: concept, value: direct };
  for (const alt of OCSF_FIELD_FALLBACKS[concept] ?? []) {
    const v = fields[alt];
    if (!isEmptyVal(v)) return { key: alt, value: v };
  }
  return null;
}

/**
 * Resolve a UDM concept from a (possibly OCSF-native-keyed) flat field record.
 * UDM key first → byte-identical under UDM; then the native OCSF column(s).
 * Returns the original (possibly undefined/empty) UDM value when no native hit.
 */
export function fieldVal(fields: Record<string, unknown>, concept: string): unknown {
  return fieldEntry(fields, concept)?.value ?? fields[concept];
}
