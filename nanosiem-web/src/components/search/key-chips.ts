// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Per-event "key fields" summary chips (search results rows + event inspector),
 * built from the profile-aware field map (NAN-4903) so both surfaces show the
 * active schema's real column names.
 */

import type { SchemaFieldMap, SemanticField } from '@/lib/schema-fields';

export interface KeyChipSpec {
  /** Chip tag when no candidate column carries a value. */
  label: string;
  /** Row columns tried in order; the first non-empty one is shown and filtered on. */
  candidates: readonly string[];
  accent?: boolean;
}

function concept(map: SchemaFieldMap, key: SemanticField, accent?: boolean): KeyChipSpec {
  return { label: map.field(key), candidates: map.candidates(key), accent };
}

export function keyChipSpecs(map: SchemaFieldMap): KeyChipSpec[] {
  if (map.isOcsf) {
    return [
      // The routing key reads off the operational `source_type` column; the
      // tag shows its OCSF spelling.
      { label: map.field('logSource'), candidates: ['source_type', map.field('logSource')] },
      concept(map, 'srcIp'),
      concept(map, 'destIp'),
      concept(map, 'host'),
      concept(map, 'user'),
      concept(map, 'status'),
      { label: 'activity', candidates: ['activity', 'activity_name'], accent: true },
    ];
  }
  return [
    { label: 'sourcetype', candidates: [map.field('logSource')] },
    concept(map, 'srcIp'),
    concept(map, 'srcHost'),
    concept(map, 'destIp'),
    concept(map, 'destHost'),
    concept(map, 'user'),
    concept(map, 'destUser'),
    // NAN-2208: `event_type` is UDM's name for the physical `action` column; a
    // row cached before both read paths emitted `event_type` may carry only
    // `action`.
    { label: map.field('eventType'), candidates: [map.field('eventType'), 'action'], accent: true },
  ];
}

function isBlank(v: unknown): boolean {
  return v === undefined || v === null || v === '';
}

/**
 * Resolve a chip against a row. `field` is the column the value came from (used
 * as the display tag and the click-to-filter field); `label` is the tag.
 */
export function readKeyChip(
  spec: KeyChipSpec,
  row: Record<string, unknown> | null | undefined,
): { label: string; field: string; value: unknown } {
  for (const col of spec.candidates) {
    const v = row?.[col];
    if (!isBlank(v)) {
      // `action` is the legacy alias of event_type (keep the event_type tag and
      // filter field); under OCSF `source_type` is shown and filtered on as
      // `metadata.log_source`. Otherwise the column found is the tag.
      if (col === 'action') return { label: spec.label, field: spec.candidates[0], value: v };
      if (col === 'source_type') {
        return { label: spec.label, field: spec.label === 'sourcetype' ? col : spec.label, value: v };
      }
      return { label: col, field: col, value: v };
    }
  }
  return { label: spec.label, field: spec.candidates[0], value: undefined };
}
