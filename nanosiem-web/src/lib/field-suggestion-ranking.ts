// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Smart field ordering for nPL autocomplete (NAN-3812).
 *
 * Field suggestions come in four groups, in this order:
 *   1. Recent (you): fields from the caller's own search history (server-ranked).
 *   2. Popular in this workspace: fields most used across the tenant.
 *   3. Common: a curated cold-start list, `metadata.log_source` first.
 *   4. Everything else, alphabetical.
 * The typed prefix filters inside every group. A field appears in one group only.
 */

export type FieldSection = 'recent' | 'popular' | 'common' | 'other';

/** `GET /api/me/field-usage`: field names only, best first. */
export interface FieldUsage {
  recent: string[];
  popular: string[];
}

export interface RankableField {
  value: string;
  description?: string;
  category?: string;
}

export interface RankedField extends RankableField {
  section: FieldSection;
}

export const RECENT_GROUP_LIMIT = 5;
export const POPULAR_GROUP_LIMIT = 10;

/** Section labels and their fixed order in the popup. */
export const FIELD_SECTION_LABELS: Record<FieldSection, string> = {
  recent: 'Recent (you)',
  popular: 'Popular in this workspace',
  common: 'Common',
  other: 'All fields',
};
export const FIELD_SECTION_RANK: Record<FieldSection, number> = {
  recent: 0,
  popular: 1,
  common: 2,
  other: 3,
};

/**
 * Curated cold-start list for the OCSF schema: where analysts start a hunt.
 * Source scoping first, then the entity pivots (network, identity, host,
 * process, file, DNS/HTTP), then event classification.
 */
export const CURATED_OCSF_FIELDS: RankableField[] = [
  { value: 'metadata.log_source', description: 'Log source', category: 'Source' },
  { value: 'src_endpoint.ip', description: 'Source IP address', category: 'Network' },
  { value: 'dst_endpoint.ip', description: 'Destination IP address', category: 'Network' },
  { value: 'dst_endpoint.port', description: 'Destination port', category: 'Network' },
  { value: 'actor.user.name', description: 'Acting user', category: 'Identity' },
  { value: 'user.name', description: 'Target user', category: 'Identity' },
  { value: 'device.hostname', description: 'Device hostname', category: 'Host' },
  { value: 'src_endpoint.hostname', description: 'Source hostname', category: 'Host' },
  { value: 'dst_endpoint.hostname', description: 'Destination hostname', category: 'Host' },
  { value: 'process.name', description: 'Process name', category: 'Process' },
  { value: 'process.cmd_line', description: 'Process command line', category: 'Process' },
  { value: 'actor.process.name', description: 'Parent / acting process', category: 'Process' },
  { value: 'file.path', description: 'File path', category: 'File' },
  { value: 'file.hashes.value', description: 'File hash', category: 'File' },
  { value: 'query.hostname', description: 'DNS query name', category: 'DNS' },
  { value: 'http_request.url.hostname', description: 'HTTP host', category: 'HTTP' },
  { value: 'class_uid', description: 'OCSF event class', category: 'Event' },
  { value: 'activity_name', description: 'OCSF activity', category: 'Event' },
  { value: 'status', description: 'Event outcome', category: 'Event' },
  { value: 'severity', description: 'Event severity', category: 'Event' },
];

/**
 * Pick the curated list for the active field universe. OCSF (or unknown, e.g.
 * the schema fetch has not landed yet) gets the OCSF list filtered to fields
 * the tenant actually has, with `metadata.log_source` always kept. A legacy
 * UDM universe (no `metadata.log_source`) keeps the legacy list.
 */
export function curatedFieldsFor(
  universe: ReadonlyMap<string, RankableField>,
  legacy: RankableField[],
  override?: RankableField[],
): RankableField[] {
  if (override) return override;
  if (universe.size === 0) return CURATED_OCSF_FIELDS;
  if (!universe.has('metadata.log_source')) return legacy;
  return CURATED_OCSF_FIELDS.filter((f) => f.value === 'metadata.log_source' || universe.has(f.value));
}

/**
 * Order field suggestions into groups. `universe` is every known field (schema
 * fields, fields from the current results, legacy common fields) keyed by
 * name. Usage fields outside a complete universe are dropped (a typo or an
 * eval name from an old query); before the schema loads they are trusted.
 */
export function rankFieldSuggestions(input: {
  partial: string;
  universe: ReadonlyMap<string, RankableField>;
  /** False while the schema has not loaded: usage fields are then trusted as-is. */
  universeComplete?: boolean;
  usage: FieldUsage | null;
  curated: RankableField[];
}): RankedField[] {
  const partial = input.partial.toLowerCase();
  const matches = (name: string) => name.toLowerCase().startsWith(partial);
  const complete = input.universeComplete ?? input.universe.size > 0;
  const known = (name: string) => !complete || input.universe.has(name);
  const used = new Set<string>();
  const out: RankedField[] = [];

  const push = (field: RankableField, section: FieldSection) => {
    if (used.has(field.value)) return;
    used.add(field.value);
    out.push({ ...field, section });
  };
  const describe = (name: string): RankableField => input.universe.get(name) ?? { value: name };

  const take = (names: string[] | undefined, section: FieldSection, limit: number) => {
    let n = 0;
    for (const name of names ?? []) {
      if (n >= limit) break;
      if (used.has(name) || !known(name)) continue;
      // Count against the limit before prefix filtering so the group keeps the
      // same members as the user types; the prefix only hides some of them.
      n += 1;
      if (matches(name)) push(describe(name), section);
    }
  };

  take(input.usage?.recent, 'recent', RECENT_GROUP_LIMIT);
  take(input.usage?.popular, 'popular', POPULAR_GROUP_LIMIT);

  for (const field of input.curated) {
    if (matches(field.value)) {
      const info = input.universe.get(field.value);
      push({ ...field, ...(info?.description ? { description: info.description } : {}) }, 'common');
    }
  }

  const rest = [...input.universe.values()]
    .filter((f) => !used.has(f.value) && matches(f.value))
    .sort((a, b) => a.value.localeCompare(b.value));
  for (const field of rest) push(field, 'other');

  return out;
}
