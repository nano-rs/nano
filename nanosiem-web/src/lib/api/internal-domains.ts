// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Internal domains (NAN-3226) — `/api/settings/internal-domains`.
 *
 * DNS suffixes whose names are internal hosts, never internet domains. The
 * saved list is unioned with the built-in suffixes (`local`, `corp`, ...).
 * Readable by any analyst (`search:execute`); writes need `settings:system`.
 * Enterprise builds only: the open edition answers 404 and callers fall back
 * to the built-ins.
 */

export type InternalDomainsDistribution = 'published' | 'not_applicable' | 'failed';

export interface InternalDomainsSettings {
  /** Added suffixes, normalized lowercase, sorted. */
  suffixes: string[];
  /** Built-in suffixes that always apply. */
  builtin: string[];
  /** Entries of `suffixes` that are public TLDs / public suffixes. */
  public_suffix_warnings: string[];
  /** One explanation per `public_suffix_warnings` entry, same order (NAN-3230). */
  public_suffix_warning_messages?: string[];
  /** Whether the saved list reached every reader (always `published` here). */
  distribution: InternalDomainsDistribution;
  distribution_error?: string | null;
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
