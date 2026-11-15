// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Lookup URL allowlist (NAN-5443) — `/api/settings/inputlookup-allowed-domains`.
 *
 * The hosts `inputlookup url=...` may fetch from. The admin list is merged
 * with the deployment list (`INPUTLOOKUP_ALLOWED_DOMAINS`), unless the
 * deployment locks it (`INPUTLOOKUP_ALLOWED_DOMAINS_LOCKED=true`), in which
 * case the deployment list alone applies and the admin list is read-only.
 * Read needs `settings:view`; writes need `settings:system`.
 */

/** Route of the Settings page that edits the list. */
export const LOOKUP_URLS_SETTINGS_PATH = '/settings/lookup-urls';

export type LookupAllowlistMode = 'any_public_host' | 'allowlist';

export interface LookupAllowlistSettings {
  /** Hosts added in Settings (normalized, sorted). Ignored while `locked`. */
  domains: string[];
  /** Hosts from INPUTLOOKUP_ALLOWED_DOMAINS (not removable here). */
  deployment_domains: string[];
  /** The deployment list overrides the admin list; the list is read-only. */
  locked: boolean;
  /** What applies now. */
  effective: string[];
  mode: LookupAllowlistMode;
  max_domains: number;
  /** Other processes pick up a change within this many seconds. */
  refresh_interval_secs: number;
}

/**
 * Whether a search error is the lookup allowlist refusal, so the Search page
 * can link to the Settings page. Matches the server's `DomainNotAllowed` text.
 */
export function isLookupAllowlistRefusal(message: string | null | undefined): boolean {
  return !!message && message.includes('not in the lookup URL allowlist');
}

export class LookupUrlAllowlistApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}

  async get(): Promise<LookupAllowlistSettings> {
    return this.request('/api/settings/inputlookup-allowed-domains');
  }

  async update(domains: string[]): Promise<LookupAllowlistSettings> {
    return this.request('/api/settings/inputlookup-allowed-domains', {
      method: 'PUT',
      body: JSON.stringify({ domains }),
    });
  }
}
