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

import { GLOSSARY } from '@/lib/glossary';

/** On-demand sidebar buckets (the promoted columns are Selected / Available). */
export type OnDemandBucket = 'extended' | 'unmapped';

export const FIELD_BUCKET_LABELS = {
  core: 'Core',
  extended: 'Extended',
  unmapped: 'Unmapped',
} as const;

const UDM_EXTENDED_TOOLTIP = 'Extra fields kept in the ext field instead of their own column. Searches on them are slower.';

/** NAN-5867: the same words as the glossary (core-field, extended-field, unmapped-field). */
export const FIELD_BUCKET_TOOLTIPS = {
  core: GLOSSARY['core-field'].short,
  extendedOcsf: GLOSSARY['extended-field'].short,
  extendedUdm: UDM_EXTENDED_TOOLTIP,
  unmapped: GLOSSARY['unmapped-field'].short,
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

/**
 * NAN-5485: the note a partial on-demand inventory carries in its section
 * header, or null when the list is complete. `failed` is a request that did
 * not return at all: the section still shows, labelled, rather than vanish.
 */
export function partialInventoryNote(
  inventory:
    | { partial: boolean; reason?: string | null; rows_examined?: number | null; row_limit?: number | null }
    | undefined,
  failed = false,
): string | null {
  if (failed) return 'This list could not be loaded; fields may be missing.';
  if (!inventory?.partial) return null;
  switch (inventory.reason) {
    case 'row_limit':
      return `Listed from the first ${(inventory.row_limit ?? 0).toLocaleString('en-US')} matching events; other events may carry more fields.`;
    case 'output_cap':
      return 'More fields than the list holds; filter to find the rest.';
    case 'scan_failed':
      return 'The scan for these fields failed; fields may be missing.';
    case 'query_not_scanned':
      return 'This query could not be scanned for these fields.';
    case 'subsearch_rows_not_scanned':
      return 'Rows added by append/join subsearches were not scanned for these fields.';
    case 'sampled_fallback':
      return 'Sampled from recent events per source; run a search for its full list.';
    case 'derived_fields_not_listed':
      return 'Fields this pipeline creates (eval, rex, spath, lookup, rename) are not stored, so they are not listed here.';
    case 'dataset_not_supported':
      return 'This dataset has no list of these fields.';
    default:
      return 'This list may be incomplete.';
  }
}

/** NAN-5485: how the panel's server field stats fall short, if they do. */
export interface FieldStatsGap {
  /** The stats were a head sample of this many matched events. */
  sampledFromRows?: number | null;
  /** The stats request failed: the panel shows stats of the loaded rows only. */
  unavailable?: boolean;
  /** Any other reason the server gave (`columns_dropped`). */
  partialReason?: string | null;
}

/** NAN-5485: the field-stats note for a gap, or null when the stats are complete. */
export function statsGapNote(gap: FieldStatsGap | null | undefined): string | null {
  if (!gap) return null;
  if (gap.unavailable) {
    return 'Field stats unavailable; values below come from the loaded events only.';
  }
  if (gap.sampledFromRows) {
    return `Stats from the first ${gap.sampledFromRows.toLocaleString('en-US')} matching events (primary-key order); fields only in later events may be missing.`;
  }
  if (gap.partialReason === 'columns_dropped') {
    return 'Some columns could not be computed for this search; their fields are missing.';
  }
  return gap.partialReason ? 'Field stats are partial.' : null;
}
