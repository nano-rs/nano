// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Which result-row keys are threat-intel (IOC) or geo/ASN enrichment, under
 * either schema profile (NAN-5271).
 *
 * UDM writes them as flat `ioc_*` / `enriched_*` columns. OCSF writes the IOC
 * hits under `enrichments.ioc_*` (and `enrichments.custom_ioc_*`), and geo/ASN
 * on the endpoint objects (`src_endpoint.location.country`,
 * `dst_endpoint.autonomous_system.name`, …). Matching only the UDM prefixes
 * filed every OCSF IOC/geo hit under Core with no IOC styling, and the IOC /
 * geo toggles hid nothing.
 */

/** A threat-intel match column (`ioc_*`, `enrichments.ioc_*`, `enrichments.custom_ioc_*`). */
export function isIocField(key: string): boolean {
  return (
    key.startsWith('ioc_') ||
    key.startsWith('enrichments.ioc_') ||
    key.startsWith('enrichments.custom_ioc_')
  );
}

const OCSF_GEO_SEGMENTS = ['.location.', '.autonomous_system.'];

/**
 * A geo / ASN / other auto-enrichment column: UDM `enriched_*`, OCSF
 * `*.location.*` / `*.autonomous_system.*`, and the remaining `enrichments.*`
 * (custom tags, generic name/value) that are not IOC matches.
 */
export function isGeoEnrichmentField(key: string): boolean {
  if (key.startsWith('enriched_')) return true;
  if (key.startsWith('enrichments.')) return !isIocField(key);
  return OCSF_GEO_SEGMENTS.some((seg) => key.includes(seg));
}
