// SPDX-License-Identifier: AGPL-3.0-or-later

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
 * — whose `…​.sha256` is promoted — is hidden), and the known scalar aliases.
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
