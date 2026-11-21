// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5704: the /prevalence "Search events" pivot on an OCSF deployment.
//
// A prevalence artifact is an aggregate keyed by VALUE: the OCSF prevalence
// MVs (`ocsf_{hash,domain,ip}_prevalence_summary_*_mv` and the
// source-attributed `*_prevalence_source_ocsf*_mv`) fold several event
// columns into one row per artifact and do not record which column a value
// came from. The pivot therefore searches every column the baseline reads for
// that artifact class. It used to search one concept column (`file.hashes.value`,
// `dst_endpoint.hostname`, `dst_endpoint.ip`), so a rare binary seen only in
// Process Activity, a domain seen only in DNS (`query.hostname`) and an IP
// seen only as a source opened Search on 0 events.
//
// Hashes: the MVs read the `*.file.hashes.sha256` scalars, which have no skip
// index. Each is the sha256 entry of the matching `*.file.hashes.value` array
// (lowercased at ingest, bloom_filter-indexed), so the pivot filters the
// arrays: same events, indexed, and md5/sha1 values match too.
//
// `pivot.test.ts` derives these lists from every prevalence MV in
// clickhouse/ocsf/init.sql and the OCSF migrations, and fails on drift.
// OCSF only: a UDM deployment keeps its schema-field-map pivot (Prevalence.tsx).

import type { PrevalenceArtifactType } from '@/lib/api/types';
import { nplExactEquals } from '@/lib/npl-quote';
import type { SchemaFieldMap, SemanticField } from '@/lib/schema-fields';

export type PrevalenceArtifactClass = 'hash' | 'domain' | 'ip';

/** The OCSF columns the pivot searches for each artifact class (see above). */
export const PREVALENCE_SOURCE_FIELDS: Record<PrevalenceArtifactClass, readonly string[]> = {
  // The indexed arrays behind `{file,process,actor.process}.file.hashes.sha256`.
  hash: ['file.hashes.value', 'process.file.hashes.value', 'actor.process.file.hashes.value'],
  domain: ['dst_endpoint.hostname', 'query.hostname', 'url.hostname', 'http_request.url.hostname'],
  ip: ['dst_endpoint.ip', 'src_endpoint.ip'],
};

/** The artifact class of a prevalence `artifact_type`. */
export function prevalenceArtifactClass(type: PrevalenceArtifactType | string): PrevalenceArtifactClass {
  if (type.startsWith('hash')) return 'hash';
  if (type.startsWith('ip_address')) return 'ip';
  return 'domain';
}

/**
 * nPL filter matching `artifact` in every column the baseline counted it from:
 * a parenthesized OR group (safe to AND with other terms).
 */
export function prevalencePivotFilter(type: PrevalenceArtifactType | string, artifact: string): string {
  const cols = PREVALENCE_SOURCE_FIELDS[prevalenceArtifactClass(type)];
  return `(${cols.map((c) => nplExactEquals(c, artifact)).join(' OR ')})`;
}

/** The Search time preset for a /prevalence window (`1h`, `24h`, `7d`, `30d`). */
const WINDOW_PRESETS: Record<string, string> = {
  '1h': 'Last hour',
  '24h': 'Last 24 hours',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
};

/**
 * The `/search#…` fragment for the pivot: the filter plus the prevalence
 * page's window, so Search covers the period the counts were taken over
 * instead of its own default (Last hour).
 */
export function prevalencePivotFragment(
  type: PrevalenceArtifactType | string,
  artifact: string,
  window: string,
): string {
  const params = new URLSearchParams();
  params.set('q', prevalencePivotFilter(type, artifact));
  const preset = WINDOW_PRESETS[window];
  if (preset) params.set('time', preset);
  return params.toString();
}

/**
 * The `/search#…` fragment for a /prevalence "Search events" click under the
 * deployment's schema. OCSF: the multi-column pivot above, over the page's
 * window. Legacy UDM: unchanged from NAN-4903 (one concept column, Search's
 * own time range); no UDM behavior is added here.
 */
export function prevalenceDrilldownFragment(
  fields: Pick<SchemaFieldMap, 'isOcsf' | 'filter'>,
  type: PrevalenceArtifactType | string,
  artifact: string,
  window: string,
): string {
  if (fields.isOcsf) return prevalencePivotFragment(type, artifact, window);
  const key: SemanticField = type.startsWith('hash') ? 'fileHash' : type.startsWith('ip_address') ? 'destIp' : 'destHost';
  return `q=${encodeURIComponent(fields.filter(key, artifact))}`;
}
