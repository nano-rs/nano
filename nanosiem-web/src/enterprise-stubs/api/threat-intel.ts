// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for ThreatIntelApi. Threat-intel lookups and the Enrich
// flyout are enterprise-only (NAN-4931); `/api/threat-intel/*` does not exist
// on open builds and every affordance is hidden by the `threatIntel`
// capability.

export type ThreatIntelArtifactType = 'hash' | 'domain' | 'ip' | 'url';

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('Threat-intel lookups are enterprise-only'));

export class ThreatIntelApi {
  constructor(_request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {
    void _request;
  }

  listProviders(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  configureProvider(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  uninstallProvider(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  lookup(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  lookupIndicators(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
}
