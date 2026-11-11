// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5270: which result-row fields the search Rarity view reads artifacts from.
//
// The Rarity scatter extracts hashes/domains client-side from search rows. It
// used to read UDM names only (`dest_host`, `file_hash`, `url`, ...), but OCSF
// parsers deliberately don't populate UDM, so an OCSF search (e.g. a MITM proxy
// with thousands of hostnames) yielded zero artifacts and Rarity read "0
// unique". OCSF rows arrive with FLAT dotted keys (`dst_endpoint.hostname`)
// from the search API; nested objects are accepted too.
//
// The OCSF paths mirror what the OCSF prevalence baseline reads
// (`domain_prevalence_source_ocsf_mv`: dst_endpoint/query/url hostname;
// `hash_prevalence_source_ocsf_mv`: file / process.file hashes.sha256), plus
// the HTTP-activity URL object and the `*_unified` projections the search
// service adds. The dict keys are lowercased; callers lowercase values.
//
// NAN-5280: the six field lists below are mirrored server-side in
// nanosiem-core/src/prevalence/artifact_fields.rs (POST
// /api/prevalence/query-artifacts). nanosiem-core/tests/
// prevalence_artifact_fields_parity.rs parses these arrays and fails on drift:
// edit both together, keep the `export const X = [...] as const;` shape.

/** UDM fields carrying a file hash. */
export const UDM_HASH_FIELDS = ['file_hash', 'process_hash', 'metadata.file_hash', 'metadata.process_hash'] as const;

/** OCSF fields carrying a file hash (scalar sha256 or hash arrays). */
export const OCSF_HASH_FIELDS = [
  'file.hashes.sha256',
  'process.file.hashes.sha256',
  'actor.process.file.hashes.sha256',
  'file.hashes.value',
  'process.file.hashes.value',
  'actor.process.file.hashes.value',
  'process_hash_unified',
] as const;

/** UDM fields carrying a bare domain / hostname. */
export const UDM_DOMAIN_FIELDS = ['dest_host', 'dest_domain', 'domain', 'query', 'url_domain', 'http_host'] as const;

/** OCSF fields carrying a bare domain / hostname. */
export const OCSF_DOMAIN_FIELDS = [
  'dst_endpoint.hostname',
  'query.hostname',
  'url.hostname',
  'http_request.url.hostname',
  'url_domain_unified',
] as const;

/** UDM fields that may carry a full URL (hostname parsed out). */
export const UDM_URL_FIELDS = ['url', 'http_referrer', 'file_path'] as const;

/** OCSF fields that may carry a full URL. */
export const OCSF_URL_FIELDS = [
  'url.url_string',
  'http_request.url.url_string',
  'http_request.referrer',
  'url_unified',
] as const;

/**
 * Read `path` from a result row: the flat dotted key first (what the search
 * API returns for OCSF columns), then a nested walk. A nested walk that meets
 * an array maps the rest of the path over its elements, so the native OCSF
 * shape `file.hashes = [{algorithm_id, value}]` yields `file.hashes.value` as
 * an array of values (the same shape as the flat `file.hashes.value` column).
 */
export function readField(fields: Record<string, unknown>, path: string): unknown {
  if (path in fields) return fields[path];
  return walk(fields, path.split('.'));
}

function walk(cur: unknown, parts: string[]): unknown {
  if (parts.length === 0) return cur;
  if (Array.isArray(cur)) {
    const out = cur.flatMap((el) => {
      const v = walk(el, parts);
      return v === undefined ? [] : Array.isArray(v) ? v : [v];
    });
    return out.length > 0 ? out : undefined;
  }
  if (cur == null || typeof cur !== 'object') return undefined;
  return walk((cur as Record<string, unknown>)[parts[0]], parts.slice(1));
}

function collect(fields: Record<string, unknown>, paths: readonly string[]): unknown[] {
  const out: unknown[] = [];
  for (const p of paths) {
    const v = readField(fields, p);
    if (Array.isArray(v)) out.push(...v);
    else if (v != null && v !== '') out.push(v);
  }
  return out;
}

/** Raw (unvalidated) artifact candidates from one row, UDM + OCSF. */
export function artifactCandidates(fields: Record<string, unknown>): {
  hashes: unknown[];
  domains: unknown[];
  urls: unknown[];
} {
  return {
    hashes: collect(fields, [...UDM_HASH_FIELDS, ...OCSF_HASH_FIELDS]),
    domains: collect(fields, [...UDM_DOMAIN_FIELDS, ...OCSF_DOMAIN_FIELDS]),
    urls: collect(fields, [...UDM_URL_FIELDS, ...OCSF_URL_FIELDS]),
  };
}
