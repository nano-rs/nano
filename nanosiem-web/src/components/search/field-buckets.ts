// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5265: the field buckets the search sidebar (FieldsPanel) and the event
// inspector (event-flatten `buildFieldCategories`) share — one set of labels and
// tooltips, and the one place that turns an on-demand JSON key from
// `/api/fields/ext` into the field name both views show and query.
//
// The API returns BARE keys for the spill on every profile (`error_code`,
// `event_data.utc_time`) and full dotted OCSF attribute paths for the
// Extended inventory (`module.file.company_name`). The spill namespace is added
// here exactly once.

/** On-demand sidebar buckets (the promoted columns are Selected / Available). */
export type OnDemandBucket = 'extended' | 'unmapped';

export const FIELD_BUCKET_LABELS = {
  core: 'Core',
  extended: 'Extended',
  unmapped: 'Unmapped',
} as const;

const UDM_EXTENDED_TOOLTIP = 'Non-indexed fields stored in the ext JSON';

export const FIELD_BUCKET_TOOLTIPS = {
  core: 'Indexed columns',
  extendedOcsf: 'Valid OCSF fields stored in the event JSON',
  extendedUdm: UDM_EXTENDED_TOOLTIP,
  unmapped: "Source fields the parser didn't map to OCSF",
} as const;

export function extendedTooltip(isOcsf: boolean): string {
  return isOcsf ? FIELD_BUCKET_TOOLTIPS.extendedOcsf : FIELD_BUCKET_TOOLTIPS.extendedUdm;
}

/** The namespace a spill key is shown and queried under. */
export function spillPrefix(isOcsf: boolean): 'unmapped.' | 'ext.' {
  return isOcsf ? 'unmapped.' : 'ext.';
}

/**
 * The field name for a BARE spill key: `ext.<key>` (UDM) / `unmapped.<key>`
 * (OCSF). Never doubles the namespace — `unmapped.unmapped.*` resolves to a
 * nested key that does not exist and matches nothing, and the search API now
 * rejects it.
 *
 * A key that itself starts with the namespace (an OCSF spill object literally
 * named `unmapped`) is addressed through the `ext.` alias instead, which the
 * OCSF profile resolves to the same spill path (`ext.unmapped.x` →
 * `unmapped."unmapped"."x"`). UDM keys are top-level segments and carry no dot.
 */
export function spillFieldName(key: string, isOcsf: boolean): string {
  const prefix = spillPrefix(isOcsf);
  if (key.startsWith(prefix)) {
    return isOcsf ? `ext.${key}` : key;
  }
  return `${prefix}${key}`;
}

/** Which sidebar bucket the profile's spill lands in. */
export function spillBucket(isOcsf: boolean): OnDemandBucket {
  return isOcsf ? 'unmapped' : 'extended';
}

export interface OnDemandField {
  field: string;
  bucket: OnDemandBucket;
}

/**
 * Build the on-demand sidebar entries from the two inventories, skipping names
 * already present as real columns and de-duplicating across buckets.
 *
 * - `spillKeys`: bare keys from the default `/api/fields/ext` inventory.
 * - `extendedPaths`: OCSF Extended attribute paths (`bucket: "extended"`); used
 *   as-is. Ignored under UDM, whose Extended bucket IS the spill.
 */
export function buildOnDemandFields(
  spillKeys: readonly string[] | undefined,
  extendedPaths: readonly string[] | undefined,
  isOcsf: boolean,
  present: ReadonlySet<string>,
): OnDemandField[] {
  const seen = new Set(present);
  const out: OnDemandField[] = [];
  const add = (field: string, bucket: OnDemandBucket) => {
    if (!field || seen.has(field)) return;
    seen.add(field);
    out.push({ field, bucket });
  };
  if (isOcsf) {
    for (const path of extendedPaths ?? []) add(path, 'extended');
  }
  for (const key of spillKeys ?? []) {
    if (key) add(spillFieldName(key, isOcsf), spillBucket(isOcsf));
  }
  return out;
}
