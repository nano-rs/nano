// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  PrevalenceResponse,
  BulkPrevalenceRequest,
  BulkPrevalenceResponse,
  RareArtifactsQuery,
  NewArtifactsQuery,
  ArtifactListResponse,
  ArtifactExplorerQuery,
  ArtifactExplorerResponse,
  ArtifactDetailResponse,
  ScatterPlotRequest,
  PrevalenceScatterDataResponse,
  PrevalenceSettingsResponse,
  UpdatePrevalenceSettingsRequest,
} from './types';
import { browserTenantRuntime } from '../tenant-runtime';

/** NAN-3088: a lean (enterprise-shared) tenant's rare list and export are
 * durable jobs on its own Search view. The API's `/api/prevalence/*` answer
 * a 307 there too; calling Search directly avoids the hop. */
export function leanPrevalencePath(route: 'rare' | 'export'): string {
  return browserTenantRuntime.current().scope.kind === 'enterprise_shared'
    ? `/api/search/prevalence/${route}`
    : `/api/prevalence/${route}`;
}

export class PrevalenceApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async getHashPrevalence(hash: string): Promise<PrevalenceResponse> {
    return this.request(`/api/prevalence/hash/${encodeURIComponent(hash)}`);
  }

  async getDomainPrevalence(domain: string): Promise<PrevalenceResponse> {
    return this.request(`/api/prevalence/domain/${encodeURIComponent(domain)}`);
  }

  async getBulkPrevalence(request: BulkPrevalenceRequest): Promise<BulkPrevalenceResponse> {
    return this.request('/api/prevalence/bulk', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async getRareArtifacts(params?: RareArtifactsQuery): Promise<ArtifactListResponse> {
    const searchParams = new URLSearchParams();
    if (params?.window) searchParams.set('window', params.window);
    if (params?.type) searchParams.set('type', params.type);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));
    if (params?.job_id) searchParams.set('job_id', params.job_id);
    if (params?.refresh) searchParams.set('refresh', 'true');
    const query = searchParams.toString();
    return this.request(`${leanPrevalencePath('rare')}${query ? `?${query}` : ''}`);
  }

  async getNewArtifacts(params?: NewArtifactsQuery): Promise<ArtifactListResponse> {
    const searchParams = new URLSearchParams();
    if (params?.since) searchParams.set('since', params.since);
    if (params?.type) searchParams.set('type', params.type);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));
    const query = searchParams.toString();
    return this.request(`/api/prevalence/new${query ? `?${query}` : ''}`);
  }

  async getArtifactExplorer(params?: ArtifactExplorerQuery): Promise<ArtifactExplorerResponse> {
    const searchParams = new URLSearchParams();
    if (params?.window) searchParams.set('window', params.window);
    if (params?.type) searchParams.set('type', params.type);
    if (params?.risk_level) searchParams.set('risk_level', params.risk_level);
    if (params?.search) searchParams.set('search', params.search);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset != null) searchParams.set('offset', String(params.offset));
    if (params?.cursor_last_seen) searchParams.set('cursor_last_seen', params.cursor_last_seen);
    if (params?.cursor_kind) searchParams.set('cursor_kind', params.cursor_kind);
    if (params?.cursor_artifact) searchParams.set('cursor_artifact', params.cursor_artifact);
    const query = searchParams.toString();
    return this.request(`/api/prevalence/explorer${query ? `?${query}` : ''}`);
  }

  async getArtifactDetail(artifact: string, window?: string, signal?: AbortSignal): Promise<ArtifactDetailResponse> {
    const searchParams = new URLSearchParams();
    searchParams.set('artifact', artifact);
    if (window) searchParams.set('window', window);
    return this.request(`/api/prevalence/explorer/detail?${searchParams.toString()}`, {
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(15_000)]) : AbortSignal.timeout(15_000),
    });
  }

  async getPrevalenceScatterData(request: ScatterPlotRequest): Promise<PrevalenceScatterDataResponse> {
    return this.request('/api/prevalence/scatter', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async getPrevalenceSettings(): Promise<PrevalenceSettingsResponse> {
    return this.request('/api/settings/prevalence');
  }

  async updatePrevalenceSettings(request: UpdatePrevalenceSettingsRequest): Promise<PrevalenceSettingsResponse> {
    return this.request('/api/settings/prevalence', {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async getPrevalenceArtifactsForQuery(request: { query: string; time_range: string | { start: string; end: string } }): Promise<{
    hash_points: Array<{
      artifact: string;
      host_count: number;
      first_seen: string;
      last_seen: string;
      total_occurrences: number;
      is_rare: boolean;
      prevalence_score: number;
    }>;
    domain_points: Array<{
      artifact: string;
      host_count: number;
      first_seen: string;
      last_seen: string;
      total_occurrences: number;
      is_rare: boolean;
      prevalence_score: number;
    }>;
    rarity_threshold: number;
    artifacts_truncated: boolean;
  }> {
    return this.request('/api/prevalence/query-artifacts', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }
}
