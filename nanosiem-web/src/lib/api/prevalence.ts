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
    const query = searchParams.toString();
    return this.request(`/api/prevalence/rare${query ? `?${query}` : ''}`);
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
    const query = searchParams.toString();
    return this.request(`/api/prevalence/explorer${query ? `?${query}` : ''}`);
  }

  async getArtifactDetail(artifact: string, window?: string): Promise<ArtifactDetailResponse> {
    const searchParams = new URLSearchParams();
    searchParams.set('artifact', artifact);
    if (window) searchParams.set('window', window);
    return this.request(`/api/prevalence/explorer/detail?${searchParams.toString()}`);
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
  }> {
    return this.request('/api/prevalence/query-artifacts', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }
}
