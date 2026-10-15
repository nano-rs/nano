// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Tenant internal domains (NAN-3226) — `/api/settings/internal-domains`.
 *
 * DNS suffixes whose names are internal hosts, never internet domains. The
 * tenant list is unioned with the built-in suffixes (`local`, `corp`, ...).
 * Readable by any analyst (`search:execute`); writes need `settings:system`.
 */

export type InternalDomainsDistribution = 'published' | 'not_applicable' | 'failed';

export interface InternalDomainsSettings {
  /** Tenant-added suffixes, normalized lowercase, sorted. */
  suffixes: string[];
  /** Built-in suffixes that always apply. */
  builtin: string[];
  /** Entries of `suffixes` that are public TLDs / public suffixes. */
  public_suffix_warnings: string[];
  /** One explanation per `public_suffix_warnings` entry, same order (NAN-3230). */
  public_suffix_warning_messages?: string[];
  /** Whether the saved list reached the ingest workers. */
  distribution: InternalDomainsDistribution;
  distribution_error?: string | null;
}

/** NAN-3230: why a suffix was refused (422 `error.details.refused[]`). */
export type SuffixRefusal = 'high_volume_tld' | 'country_code_tld' | 'public_registry_suffix';

export interface RefusedSuffix {
  suffix: string;
  reason: SuffixRefusal;
  message: string;
}

/** `error.code` of the 422 that refuses high-volume public suffixes. */
export const INTERNAL_DOMAINS_REFUSED = 'INTERNAL_DOMAINS_REFUSED';

/** The per-entry refusals carried by an `INTERNAL_DOMAINS_REFUSED` error, else []. */
export function refusedSuffixesFromError(err: unknown): RefusedSuffix[] {
  if (typeof err !== 'object' || err == null) return [];
  const { code, details } = err as { code?: unknown; details?: unknown };
  if (code !== INTERNAL_DOMAINS_REFUSED || typeof details !== 'object' || details == null) return [];
  const refused = (details as { refused?: unknown }).refused;
  if (!Array.isArray(refused)) return [];
  return refused.filter(
    (r): r is RefusedSuffix =>
      typeof r === 'object' && r != null && typeof (r as RefusedSuffix).suffix === 'string' && typeof (r as RefusedSuffix).message === 'string',
  );
}

export class InternalDomainsApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}

  async get(): Promise<InternalDomainsSettings> {
    return this.request('/api/settings/internal-domains');
  }

  async update(suffixes: string[]): Promise<InternalDomainsSettings> {
    return this.request('/api/settings/internal-domains', {
      method: 'PUT',
      body: JSON.stringify({ suffixes }),
    });
  }
}
