// SPDX-License-Identifier: AGPL-3.0-or-later
// Threat-intel lookups (hosted-shared): the tenant's own indicator sets (IOC
// feeds and lists), plus per-tenant providers and on-demand artifact
// enrichment through VirusTotal, AbuseIPDB, GreyNoise, URLhaus, ThreatFox,
// MalwareBazaar and Shodan.

export type ThreatIntelArtifactType = 'hash' | 'domain' | 'ip' | 'url';
export type ThreatIntelVerdict = 'malicious' | 'suspicious' | 'benign' | 'unknown' | 'not_found';
export type ThreatIntelOrigin = 'analyst' | 'pivt' | 'auto_investigation';
export type ThreatIntelProviderStatus =
  | 'ok'
  | 'cached'
  | 'quota_exhausted'
  | 'budget_exhausted'
  | 'auth_failed'
  | 'not_configured'
  | 'error';

export interface ThreatIntelLimits {
  per_minute: number;
  per_day: number;
  cache_ttl_secs: number;
}

export interface ThreatIntelProvider {
  provider: string;
  name: string;
  description: string;
  homepage: string | null;
  artifact_types: ThreatIntelArtifactType[];
  credential_fields: { name: string; label: string; required: boolean; set: boolean }[];
  installed: boolean;
  enabled: boolean;
  ready: boolean;
  defaults: ThreatIntelLimits;
  effective: ThreatIntelLimits;
  usage: { this_minute: number; today: number };
  updated_at: string | null;
}

export interface ConfigureThreatIntelProvider {
  enabled?: boolean;
  /** Field name -> value. Empty string removes the stored value. */
  credentials?: Record<string, string>;
  /** 0 resets to the provider default. */
  per_minute?: number;
  per_day?: number;
  cache_ttl_secs?: number;
}

export interface ThreatIntelProviderResult {
  provider: string;
  provider_name: string;
  status: ThreatIntelProviderStatus;
  verdict: ThreatIntelVerdict | null;
  score: number | null;
  link: string | null;
  tags: string[];
  summary: Record<string, unknown>;
  fetched_at: string | null;
  cached_at: string | null;
  expires_at: string | null;
  quota_reason: string | null;
  retry_after_secs: number | null;
  message: string | null;
}

export interface ThreatIntelLookupResponse {
  artifact: string;
  artifact_type: ThreatIntelArtifactType;
  origin: ThreatIntelOrigin;
  availability: 'available' | 'no_provider_configured';
  verdict: ThreatIntelVerdict | null;
  score: number | null;
  results: ThreatIntelProviderResult[];
}

export interface ThreatIntelLookupRequest {
  artifact: string;
  artifact_type?: ThreatIntelArtifactType;
  providers?: string[];
  force_refresh?: boolean;
  origin?: 'analyst' | 'pivt';
}

/** NAN-3881: one match in the tenant's own indicator sets. */
export interface IndicatorMatch {
  ioc_type: string | null;
  threat_type: string | null;
  malware: string | null;
  confidence: number | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  tags: string[];
}

export interface IndicatorSourceMatches {
  /** Feed or IOC-list display name. */
  source: string;
  matches: IndicatorMatch[];
}

export interface IndicatorLookupResponse {
  artifact: string;
  artifact_type: ThreatIntelArtifactType | null;
  /** Indicator sources searched; null when the tenant worker does not report them. */
  source_count: number | null;
  source_names: string[] | null;
  /** Matches grouped by source, strongest first. */
  sources: IndicatorSourceMatches[];
}

export interface IndicatorLookupRequest {
  artifact: string;
  artifact_type?: ThreatIntelArtifactType;
}

export class ThreatIntelApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}

  listProviders(): Promise<{ providers: ThreatIntelProvider[] }> {
    return this.request('/api/threat-intel/providers');
  }

  configureProvider(provider: string, body: ConfigureThreatIntelProvider): Promise<ThreatIntelProvider> {
    return this.request(`/api/threat-intel/providers/${encodeURIComponent(provider)}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    });
  }

  uninstallProvider(provider: string): Promise<{ provider: string; deleted: boolean }> {
    return this.request(`/api/threat-intel/providers/${encodeURIComponent(provider)}`, { method: 'DELETE' });
  }

  lookup(body: ThreatIntelLookupRequest): Promise<ThreatIntelLookupResponse> {
    return this.request('/api/threat-intel/lookup', { method: 'POST', body: JSON.stringify(body) });
  }

  /** Search the tenant's own IOC feeds and lists (no external request). */
  lookupIndicators(body: IndicatorLookupRequest): Promise<IndicatorLookupResponse> {
    return this.request('/api/threat-intel/indicator-lookup', { method: 'POST', body: JSON.stringify(body) });
  }
}
