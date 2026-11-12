// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  EnrichmentSource,
  IpLookupResult,
  AgentEnrichmentProvider,
  ListAgentEnrichmentProvidersResponse,
  CreateAgentEnrichmentProviderRequest,
  UpdateAgentEnrichmentProviderRequest,
} from './types';
import { authenticatedFetch } from '../authenticated-fetch';
import { getServiceUrl } from './utils';

/** NAN-4759 / NAN-4948: freshness of one installed platform feed (GET /api/enrichment/platform-feeds). */
export type PlatformFeedState = 'fresh' | 'stale' | 'expired';
export interface PlatformFeedStatus {
  feed_id: string;
  name: string;
  revision: number;
  produced_at: string | null;
  hard_expiry: string;
  age_seconds: number | null;
  state: PlatformFeedState;
  license_id: string | null;
  terms_revision: string | null;
  /** Records the signed descriptor states for the feed. */
  records: number | null;
  /** NAN-4948: the feed stamps new events from the bundle now. */
  active?: boolean;
  /** NAN-4948: rows loaded into ClickHouse. */
  loaded?: number | null;
  /** NAN-4948: why the feed is not active, when it is not. */
  detail?: string | null;
}
export interface PlatformFeedsStatus {
  /** This deployment consumes the signed platform feed bundle. */
  available: boolean;
  /** A verified bundle is installed. */
  installed: boolean;
  bundle_sha256: string | null;
  /** `online` or `offline`. */
  source: string | null;
  installed_at: string | null;
  stale_after_days: number;
  feeds: PlatformFeedStatus[];
  /** Attribution shown with the data (IPinfo CC BY-SA 4.0). */
  notice: string | null;
  /** NAN-4948 (additive): installed descriptor sequence. */
  sequence?: number | null;
  /** NAN-4948: `open`, `sovereign`, `mirror` or `file`. */
  channel?: string | null;
  /** NAN-4948: the scheduled online check runs (false in air-gap mode). */
  auto_update?: boolean;
  last_check_at?: string | null;
  /** NAN-4948: `installed`, `current`, `checking`, `busy`, `refused` or `failed`. */
  last_check_status?: string | null;
  /** NAN-4948: why the latest check did not install (the installed bundle is kept). */
  last_error?: string | null;
  last_error_at?: string | null;
  /** NAN-4959: when the scheduled online check is next due (null in air-gap or before the first check). */
  next_check_at?: string | null;
}
/** NAN-4948: result of a platform feed import. */
export interface PlatformFeedInstallResponse {
  result: { outcome: 'installed'; sequence: number; loaded: Record<string, number> } | { outcome: 'current'; sequence: number };
  status: PlatformFeedsStatus;
}

/**
 * NAN-4948: import nano's signed platform feed bundle (`.nanfeed`), for
 * air-gapped installs. Multipart, so it bypasses the JSON `request` helper.
 * Verified server-side before anything is written; a refused file keeps the
 * installed bundle.
 */
export async function importPlatformFeedBundle(file: File): Promise<PlatformFeedInstallResponse> {
  const formData = new FormData();
  formData.append('file', file);
  const endpoint = '/api/enrichment/platform-feeds/import';
  const response = await authenticatedFetch(endpoint, `${getServiceUrl(endpoint)}${endpoint}`, {
    method: 'POST',
    body: formData,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: { message: response.statusText } }));
    const error = body.error || body;
    throw new Error(error.message || 'Feed bundle import failed');
  }
  return response.json();
}

export class EnrichmentApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  // Basic Enrichment Sources

  /** NAN-4948: installed platform feed bundle and per-feed freshness. */
  async getPlatformFeeds(): Promise<PlatformFeedsStatus> {
    return this.request<PlatformFeedsStatus>('/api/enrichment/platform-feeds');
  }

  /** NAN-4948: check nano's feed endpoint now (runs in the background; poll getPlatformFeeds). */
  async checkPlatformFeeds(): Promise<{ accepted: boolean }> {
    return this.request<{ accepted: boolean }>('/api/enrichment/platform-feeds/check', { method: 'POST' });
  }

  async listEnrichmentSources(): Promise<EnrichmentSource[]> {
    const response = await this.request<{ sources: EnrichmentSource[] }>('/api/enrichment/sources');
    return response.sources;
  }

  async enableEnrichmentSource(sourceId: string): Promise<{ success: boolean; message: string }> {
    return this.request(`/api/enrichment/sources/${sourceId}/enable`, {
      method: 'POST',
    });
  }

  async disableEnrichmentSource(sourceId: string): Promise<{ success: boolean; message: string }> {
    return this.request(`/api/enrichment/sources/${sourceId}/disable`, {
      method: 'POST',
    });
  }

  async getEnrichmentStats(): Promise<Record<string, { total: number; last_updated?: string }>> {
    return this.request('/api/enrichment/stats');
  }

  async lookupIp(ip: string): Promise<IpLookupResult> {
    return this.request(`/api/enrichment/lookup/ip/${encodeURIComponent(ip)}`);
  }

  // NAN-1111: ThreatFox and TOR Exit Nodes configure / sync methods,
  // plus the shared `/api/enrichment/ioc/{lookup,stats}` endpoints,
  // lived here. Both providers moved to the marketplace + sandboxed code
  // (nano-rs/nano-enrichments); the IOC lookup endpoints had no
  // remaining UI callers. IPinfo Lite comes from nano's signed platform
  // feed bundle (NAN-4959 removed its configure / sync / auto-sync calls).

  // Agent Enrichment Providers (AI-powered)

  async listAgentEnrichmentProviders(): Promise<ListAgentEnrichmentProvidersResponse> {
    return this.request('/api/settings/agent-enrichments');
  }

  async getAgentEnrichmentProvider(providerId: string): Promise<AgentEnrichmentProvider> {
    return this.request(`/api/settings/agent-enrichments/${providerId}`);
  }

  async createAgentEnrichmentProvider(request: CreateAgentEnrichmentProviderRequest): Promise<AgentEnrichmentProvider> {
    return this.request('/api/settings/agent-enrichments', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async updateAgentEnrichmentProvider(providerId: string, request: UpdateAgentEnrichmentProviderRequest): Promise<AgentEnrichmentProvider> {
    return this.request(`/api/settings/agent-enrichments/${providerId}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async deleteAgentEnrichmentProvider(providerId: string): Promise<{ success: boolean; message: string; cache_entries_cleared: number }> {
    return this.request(`/api/settings/agent-enrichments/${providerId}`, {
      method: 'DELETE',
    });
  }

  async updateAgentEnrichmentCredentials(providerId: string, credentials: Record<string, string>): Promise<{ success: boolean; message: string }> {
    return this.request(`/api/settings/agent-enrichments/${providerId}/credentials`, {
      method: 'PUT',
      body: JSON.stringify({ credentials }),
    });
  }

  async testAgentEnrichmentConnection(providerId: string): Promise<{ success: boolean; message: string; response_time_ms?: number; error?: string }> {
    return this.request(`/api/settings/agent-enrichments/${providerId}/test`, {
      method: 'POST',
    });
  }

  async getAgentEnrichmentUsage(): Promise<Record<string, { requests_today: number; requests_this_month: number }>> {
    return this.request('/api/settings/agent-enrichments/usage');
  }
}
