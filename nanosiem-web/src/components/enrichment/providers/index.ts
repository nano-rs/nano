// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Enrichment Provider Components
 *
 * Per-provider configuration UIs for *native* enrichment sources — the
 * ones that don't fit the Deno marketplace contract.
 *
 * IPinfo Lite is the only resident: its few-million-row gzipped-CSV
 * download + atomic staging→prod swap exceeds the marketplace's
 * single-shot `{records: [...]}` output ceiling. See the
 * `project_ipinfo_lite_stays_native` memory for the rationale.
 *
 * ThreatFox / Tor / VirusTotal moved to the marketplace in NAN-1111
 * (their providers were deleted from this directory). Anything that
 * fits the marketplace contract (`{records: [...]}`, heap-sized, IOC
 * or non-IOC schema) belongs in nano-rs/nano-enrichments instead.
 *
 * To add a new native provider:
 * 1. Create the component file (e.g., MaxMindProvider.tsx)
 * 2. Export it here
 * 3. Wire it into EnrichmentDetail.tsx's PROVIDER_BY_TYPE / PROVIDER_BY_ID maps
 */

export { IPinfoLiteProvider } from './IPinfoLiteProvider';
