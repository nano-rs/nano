// SPDX-License-Identifier: AGPL-3.0-or-later

import { UDM_COLUMNS } from '@/lib/udm-fields';
import { isClickHouseDefault } from '@/lib/utils';
import { isPrevalenceSentinelField } from '@/lib/prevalence-sentinels';

// OCSF `event` JSON expansion (NAN-1241 follow-up).
//
// Under the OCSF schema profile the row carries a raw `event` column holding the
// full nested OCSF record (e.g. `{actor:{process:{file:{path:"x"}}}}`). The UDM
// analog — the `ext` JSON column — is already flattened into top-level keys by
// the backend before it reaches the frontend, so each `ext.*` key shows as its
// own field in the inspector. The OCSF `event` object is NOT pre-flattened, so
// the inspector/inline views previously rendered it as one opaque blob.
//
// `expandEventLeaves` walks the `event` object and emits dotted leaf paths
// (`actor.process.file.path: "x"`) using the SAME dotted naming the OCSF schema
// field universe uses (`src_endpoint.ip`, `class_uid`, …). Promoted OCSF columns
// are also surfaced as top-level dotted keys on the row, so leaf paths that
// collide with an existing top-level key are skipped to avoid duplicates — the
// top-level value wins and is categorized normally.

const MAX_DEPTH = 12;

// NAN-1276: OCSF enum/array siblings that a promoted Core column derives from
// under a DIFFERENT name/shape, so the raw `event` leaf isn't caught by a plain
// name match. `activity_name` is the lone scalar rename (Core column `activity`
// ← event `activity_name`). Array-derived columns (e.g. `process.file.hashes.
// sha256` ← `process.file.hashes[]`) are handled by the parent-prefix rule
// below, not here.
const PROMOTED_SOURCE_ALIASES = new Set<string>(['activity_name']);

/**
 * Build the exclusion set for OCSF `event` expansion: every promoted column
 * name, every ANCESTOR path of one (so an array base like `process.file.hashes`
 * — whose `....sha256` is promoted — is hidden), and the known scalar aliases.
 * "Promoted-source only" dedup (NAN-1276): a leaf already represented in Core is
 * dropped from Extended; genuinely-distinct OCSF fields (process.file.name,
 * class_name, …) are kept.
 */
function buildPromotedExclusions(promotedNames: Iterable<string>): Set<string> {
  const excl = new Set<string>(PROMOTED_SOURCE_ALIASES);
  for (const name of promotedNames) {
    excl.add(name);
    // Add every dot-ancestor: `process.file.hashes.sha256` →
    // process, process.file, process.file.hashes.
    let idx = name.indexOf('.');
    while (idx !== -1) {
      excl.add(name.slice(0, idx));
      idx = name.indexOf('.', idx + 1);
    }
  }
  return excl;
}

/**
 * Flatten an OCSF `event` object into dotted leaf-path entries.
 *
 * - Nested objects recurse with a `.`-joined path.
 * - Arrays are emitted as a single JSON-stringified value at their path (matches
 *   the way the existing ext-derived array fields render: `formatValue` JSON-
 *   stringifies objects/arrays anyway, and keeping the array intact lets the
 *   FieldValueMenu treat it as one value).
 * - Scalars (string/number/boolean/null) are emitted directly.
 *
 * @param event   the parsed OCSF `event` object
 * @param existing top-level row keys already present (promoted columns); leaf
 *                 paths matching one of these are skipped to avoid duplication.
 * @param promotedNames the full promoted-column universe (from the schema field
 *                 list). Leaves that ARE a promoted column, an ancestor of one
 *                 (array bases), or a known promoted-source alias (activity_name)
 *                 are dropped — they're already shown in Core.
 */
export function expandEventLeaves(
  event: Record<string, unknown>,
  existing: Set<string>,
  promotedNames?: Iterable<string>,
): [string, unknown][] {
  const out: [string, unknown][] = [];
  const promotedExcl = promotedNames ? buildPromotedExclusions(promotedNames) : null;
  const skip = (path: string) =>
    existing.has(path) || (promotedExcl !== null && promotedExcl.has(path));

  const walk = (node: unknown, path: string, depth: number) => {
    if (
      depth < MAX_DEPTH &&
      node !== null &&
      typeof node === 'object' &&
      !Array.isArray(node)
    ) {
      const obj = node as Record<string, unknown>;
      const keys = Object.keys(obj);
      if (keys.length === 0) {
        // Empty object — emit as a leaf so it isn't silently dropped.
        if (path && !skip(path)) out.push([path, obj]);
        return;
      }
      for (const key of keys) {
        const childPath = path ? `${path}.${key}` : key;
        walk(obj[key], childPath, depth + 1);
      }
      return;
    }
    // Leaf (scalar, array, or object at max depth).
    if (path && !skip(path)) out.push([path, node]);
  };

  walk(event, '', 0);
  return out;
}

/**
 * Extract the OCSF `event` object from a row's field map, if present and
 * non-empty. Accepts either a parsed object or a JSON string (defensive — the
 * backend sends an object, but raw-SQL paths may surface a string).
 */
export function getEventObject(
  fields: Record<string, unknown>,
): Record<string, unknown> | null {
  const value = fields.event;
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  if (typeof value === 'string' && value.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(value);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      /* not JSON */
    }
  }
  return null;
}

// ============================================================================
// Shared field flattening + categorization
//
// Both the Event Inspector (right-hand panel) and the inline expanded-row view
// in the results list render the SAME field set with the SAME category buckets
// and colors. These used to be two hand-maintained copies (flattenFields vs
// flattenFieldsForExpand) that silently drifted — e.g. the inline copy never
// learned to expand the OCSF `unmapped` spill. They now share this one source.
// ============================================================================

// NAN-1447: the OCSF `unmapped` column is a JSON object (the true source spill).
// Flatten it into DOTTED `unmapped.<path>` leaf rows so it renders as individual
// inspectable rows instead of one raw JSON blob. Dotted (not underscore) on
// purpose — matches the Unmapped category match and the promoted OCSF columns'
// dotted form. Empty objects yield no rows.
export function flattenUnmapped(
  obj: Record<string, unknown>,
  prefix = 'unmapped',
): [string, unknown][] {
  const out: [string, unknown][] = [];
  for (const [k, v] of Object.entries(obj)) {
    const key = `${prefix}.${k}`;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      out.push(...flattenUnmapped(v as Record<string, unknown>, key));
    } else {
      out.push([key, v]);
    }
  }
  return out;
}

/**
 * Flatten a result row's field map into sorted `[key, value]` leaf entries,
 * expanding the OCSF `event` record and `unmapped` spill into dotted leaf paths,
 * dropping ClickHouse defaults / internal helper columns, and sorting by the
 * same category order both views render.
 */
export function flattenEventFields(
  fields: Record<string, unknown>,
  isOcsf = false,
  prefix = '',
  promotedNames?: Set<string>,
): [string, unknown][] {
  const result: [string, unknown][] = [];

  // OCSF (NAN-1241): the raw `event` column is the full nested OCSF record.
  // Expand it into dotted leaf paths (the UDM `ext` analog) so each nested field
  // is individually inspectable. Top level only; promoted top-level keys win.
  const topLevelKeys = prefix === '' ? new Set(Object.keys(fields)) : new Set<string>();

  for (const [key, value] of Object.entries(fields)) {
    const fullKey = prefix ? `${prefix}_${key}` : key;

    if (prefix === '' && isOcsf && key === 'event') {
      const eventObj = getEventObject(fields);
      if (eventObj) {
        topLevelKeys.delete('event');
        result.push(...expandEventLeaves(eventObj, topLevelKeys, promotedNames));
        continue;
      }
    }

    if (isPrevalenceSentinelField(key, value)) continue;
    if (key === 'risk_score' && (value === 0 || value === '0')) continue;

    // NAN-1446: `*_unified` entity columns are an internal query accelerator and
    // `event_bytes` is a sizing metric — neither is an OCSF spec field. Keep them
    // out of the record view so an OCSF row renders as pure spec.
    if (key.endsWith('_unified') || key === 'event_bytes') continue;

    const isPrevalence = key === 'host_count' || key === 'is_rare' || key === 'prevalence_score' ||
                         key === 'prevalence_type' || key === 'total_occurrences' ||
                         key === '_prevalence' || key.startsWith('_prevalence.');
    if (!isPrevalence && isClickHouseDefault(value, key)) continue;

    if (key === 'metadata') {
      let metadataObj: Record<string, unknown> | null = null;
      if (typeof value === 'object' && !Array.isArray(value) && value !== null) {
        metadataObj = value as Record<string, unknown>;
      } else if (typeof value === 'string' && value.startsWith('{')) {
        try {
          const parsed = JSON.parse(value);
          if (typeof parsed === 'object' && !Array.isArray(parsed)) metadataObj = parsed;
        } catch { /* not JSON */ }
      }
      if (metadataObj) {
        result.push(...flattenEventFields(metadataObj, isOcsf, 'metadata', promotedNames));
      } else if (value) {
        result.push([fullKey, value]);
      }
    } else if (key === '_prevalence') {
      if (typeof value === 'object' && !Array.isArray(value) && value !== null) {
        result.push(...flattenEventFields(value as Record<string, unknown>, isOcsf, '_prevalence', promotedNames));
      } else if (value) {
        result.push([fullKey, value]);
      }
    } else if (key === 'unmapped' && prefix === '') {
      // NAN-1447: expand the OCSF unmapped spill into dotted leaf rows instead of
      // one JSON blob. Accept a parsed object or a JSON string.
      let unmappedObj: Record<string, unknown> | null = null;
      if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        unmappedObj = value as Record<string, unknown>;
      } else if (typeof value === 'string' && value.startsWith('{')) {
        try {
          const parsed = JSON.parse(value);
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) unmappedObj = parsed;
        } catch { /* not JSON */ }
      }
      if (unmappedObj) {
        result.push(...flattenUnmapped(unmappedObj));
      } else if (value) {
        result.push([fullKey, value]);
      }
    } else {
      result.push([fullKey, value]);
    }
  }

  const getFieldCategory = (fieldName: string): number => {
    if (fieldName === 'risk_score' || fieldName === 'risk_entity' ||
        fieldName === 'risk_factors' || fieldName.startsWith('risk_')) return 1;
    if (fieldName.startsWith('ioc_')) return 2;
    if (fieldName.includes('_identity_') || fieldName.startsWith('identity_') || fieldName === 'is_nat_candidate') return 3;
    if (fieldName.startsWith('prevalence_') || fieldName === '_prevalence' ||
        fieldName.startsWith('_prevalence.') || fieldName === 'host_count' ||
        fieldName === 'is_rare' || fieldName === 'prevalence_score' ||
        fieldName === 'prevalence_type' || fieldName === 'prevalence_artifact' ||
        fieldName === 'total_occurrences' || fieldName === 'first_seen' ||
        fieldName === 'last_seen') return 4;
    if (fieldName.startsWith('lookup_')) return 5;
    if (fieldName.startsWith('enriched_')) return 6;
    // UDM flattens `metadata` with underscores; OCSF surfaces dotted leaves
    // (`metadata.version`) — match both (NAN-1448).
    if (fieldName.startsWith('metadata_') || fieldName.startsWith('metadata.')) return 7;
    if (isOcsf && fieldName.startsWith('unmapped.')) return 9; // OCSF unmapped spill last
    if (!UDM_COLUMNS.has(fieldName)) return 8;
    return 0;
  };

  return result.sort((a, b) => {
    const catA = getFieldCategory(a[0]);
    const catB = getFieldCategory(b[0]);
    if (catA !== catB) return catA - catB;
    return a[0].localeCompare(b[0]);
  });
}

// ---- Category predicates (shared by both views) ----------------------------

export function isIocField(fieldName: string): boolean {
  return fieldName.startsWith('ioc_');
}
export function isRiskField(fieldName: string): boolean {
  return fieldName === 'risk_score' || fieldName === 'risk_entity' || fieldName === 'risk_factors';
}
export function isPrevalenceField(fieldName: string): boolean {
  return fieldName === 'host_count' || fieldName === 'is_rare' ||
         fieldName === 'prevalence_score' || fieldName === 'prevalence_type' ||
         fieldName === 'prevalence_artifact' || fieldName === 'total_occurrences' ||
         fieldName === 'first_seen' || fieldName === 'last_seen' ||
         fieldName === '_prevalence' || fieldName.startsWith('_prevalence.') ||
         fieldName === 'prevalence_file_hash' || fieldName === 'prevalence_process_hash' ||
         fieldName === 'prevalence_dest_domain' || fieldName === 'prevalence_dest_ip' ||
         fieldName === 'prevalence_min';
}
export function isLookupField(fieldName: string): boolean {
  return fieldName.startsWith('lookup_');
}
export function isIdentityField(fieldName: string): boolean {
  // Resolved-identity dict fills (`user_identity_*`, `src_user_identity_*`,
  // `dest_user_identity_*`, NAN-1147); legacy `identity_*` / `is_nat_candidate`
  // kept for back-compat (NAN-1154).
  return fieldName.includes('_identity_') || fieldName.startsWith('identity_') ||
         fieldName === 'is_nat_candidate';
}

// ---- Enrichment-toggle hiding (shared) -------------------------------------

const ENRICHMENT_CATEGORIES: Record<string, (k: string) => boolean> = {
  ioc: (k) => k.startsWith('ioc_'),
  custom: (k) => k.startsWith('lookup_custom_'),
  prevalence: (k) => isPrevalenceField(k),
  lookup: (k) => k.startsWith('lookup_') && !k.startsWith('lookup_custom_'),
  geo: (k) => k.startsWith('enriched_'),
  identity: (k) => k.includes('_identity_') || k.startsWith('identity_') || k === 'is_nat_candidate',
  // `metadata_*` (UDM flattened) and `metadata.*` (OCSF dotted leaves) — NAN-1448.
  metadata: (k) => k.startsWith('metadata_') || k.startsWith('metadata.'),
};

export function isFieldHidden(fieldName: string, hiddenEnrichments: Set<string>): boolean {
  for (const [category, check] of Object.entries(ENRICHMENT_CATEGORIES)) {
    if (hiddenEnrichments.has(category) && check(fieldName)) return true;
  }
  return false;
}

// ---- Category grouping (shared label / color / tooltip definitions) --------

export interface FieldCategory {
  label: string;
  /** Tailwind text-color class — Core is neutral, everything else brand-accent. */
  color: string;
  tooltip: string;
  fields: [string, unknown][];
}

// Core (promoted/base columns) stays neutral; everything else — derived /
// enriched / extended data — shares one subtle brand accent so a reader can tell
// at a glance which fields are "added on top" of the base event.
const CATEGORY_NEUTRAL = 'text-muted-foreground';
const CATEGORY_ACCENT = 'text-primary/80';

/**
 * Bucket flattened `[key, value]` entries into the ordered category list both
 * the inspector and the inline view render. `knownSchemaFields` is the active
 * profile's promoted-column universe (empty under UDM); `isOcsf` routes the
 * `unmapped.*` spill to its own bucket.
 */
export function buildFieldCategories(
  flattenedFields: [string, unknown][],
  knownSchemaFields: Set<string>,
  isOcsf: boolean,
): FieldCategory[] {
  const categories: FieldCategory[] = [
    { label: 'Core', color: CATEGORY_NEUTRAL, tooltip: 'Promoted, indexed schema columns for fast search (UDM or OCSF)', fields: [] },
    { label: 'Risk', color: CATEGORY_ACCENT, tooltip: 'Risk scores and factors from detection rules', fields: [] },
    { label: 'IOC', color: CATEGORY_ACCENT, tooltip: 'Indicators of compromise from threat intelligence feeds', fields: [] },
    { label: 'Identity', color: CATEGORY_ACCENT, tooltip: 'Resolved identity from the user registry (department, title, groups, account status)', fields: [] },
    { label: 'Prevalence', color: CATEGORY_ACCENT, tooltip: 'Rarity metrics — how common this artifact is across your environment', fields: [] },
    { label: 'Lookup', color: CATEGORY_ACCENT, tooltip: 'Enrichments from lookup tables', fields: [] },
    { label: 'Enrichment', color: CATEGORY_ACCENT, tooltip: 'Auto-enriched fields (geo, ASN, reputation)', fields: [] },
    { label: 'Metadata', color: CATEGORY_ACCENT, tooltip: 'Parser metadata and processing info', fields: [] },
    // Non-promoted fields: UDM `ext` spill, or OCSF schema fields without a
    // promoted column (class_name, *.file.name, …). Still MAPPED — distinct from
    // `unmapped` below.
    { label: 'Extended', color: CATEGORY_ACCENT, tooltip: 'Non-promoted fields (UDM ext spill; OCSF schema fields without a promoted column)', fields: [] },
    // NAN-1278: OCSF's `unmapped` object is the TRUE source spill (no OCSF
    // attribute). Own bucket so it isn't conflated with non-promoted-but-mapped
    // OCSF fields. OCSF only; empty under UDM.
    { label: 'Unmapped', color: CATEGORY_ACCENT, tooltip: 'Source fields with no OCSF attribute (the unmapped.* spill)', fields: [] },
  ];

  for (const field of flattenedFields) {
    const [k] = field;
    if (Array.isArray(field[1]) && (field[1] as unknown[]).length === 0) continue;
    if (isRiskField(k)) categories[1].fields.push(field);
    else if (isIocField(k)) categories[2].fields.push(field);
    else if (isIdentityField(k)) categories[3].fields.push(field);
    else if (isPrevalenceField(k)) categories[4].fields.push(field);
    else if (isLookupField(k)) categories[5].fields.push(field);
    else if (k.startsWith('enriched_')) categories[6].fields.push(field);
    else if (k.startsWith('metadata_')) categories[7].fields.push(field);
    // Core = known to the ACTIVE schema profile (OCSF promoted fields) OR a base
    // UDM column (shared operational fields not in the OCSF universe). NAN-1241.
    else if (knownSchemaFields.has(k) || UDM_COLUMNS.has(k)) categories[0].fields.push(field);
    else if (isOcsf && (k === 'unmapped' || k.startsWith('unmapped.'))) categories[9].fields.push(field);
    else categories[8].fields.push(field);
  }

  return categories.filter(c => c.fields.length > 0);
}

/**
 * Render an OCSF dotted field path split into `{ namespace, leaf }` so a view can
 * de-emphasize the namespace and keep the leaf at full strength. Underscored UDM
 * names (no dot) return an empty namespace and the whole name as the leaf.
 */
export function splitFieldKey(k: string): { namespace: string; leaf: string } {
  const i = k.lastIndexOf('.');
  if (i === -1) return { namespace: '', leaf: k };
  return { namespace: k.slice(0, i + 1), leaf: k.slice(i + 1) };
}
