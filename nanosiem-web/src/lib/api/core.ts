// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Core API routes
 * Handles health checks, fields, source types, ingestion, system metrics, and developer settings
 */

import type {
  SchemaFieldsResponse,
  SystemOverview,
  SystemConfig,
  DeveloperSettings,
  UpdateDeveloperSettingsRequest,
} from './types';

export class CoreApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  // Health check
  async healthCheck(): Promise<{ status: string }> {
    return this.request('/health');
  }

  // Version info (from authenticated detailed health endpoint)
  async getVersion(): Promise<{ version: string; status: string }> {
    return this.request('/health/detailed');
  }

  // Fields
  // NAN-1505/1510: pass the active search query + window so the picker enumerates
  // ext keys scoped to THIS search (matching the per-field value fetch) — without
  // the query, a filtered search listed keys from other source types that then
  // expanded empty. Omit all params for the syntax-highlighter path → backend
  // uses a recent default window.
  // NAN-4928: POST with the query in the body, so the hunt never lands in a
  // GET URL (server and proxy logs). The GET form is deprecated.
  async getExtFieldNames(query?: string, start?: string, end?: string, signal?: AbortSignal): Promise<string[]> {
    const body: { query?: string; start?: string; end?: string } = {};
    if (query) body.query = query;
    if (start && end) {
      body.start = start;
      body.end = end;
    }
    return this.request('/api/fields/ext', { method: 'POST', body: JSON.stringify(body), ...(signal ? { signal } : {}) });
  }

  async getFieldValues(name: string, limit: number = 10): Promise<[string, number][]> {
    return this.request(`/api/fields/${encodeURIComponent(name)}/values?limit=${limit}`);
  }

  async getSourceTypes(timeRange?: { start: string; end: string }): Promise<[string, number][]> {
    const params = timeRange ? `?start=${encodeURIComponent(timeRange.start)}&end=${encodeURIComponent(timeRange.end)}` : '';
    return this.request(`/api/source-types${params}`);
  }

  /**
   * Active schema profile's field universe (UDM or OCSF), from the profile-aware
   * `/api/schema/fields` endpoint. The frontend uses this to categorize fields
   * for the active deployment instead of assuming UDM (OCSF Phase 7, NAN-1241):
   * under OCSF, promoted fields like `src_endpoint.ip` / `class_uid` are "known"
   * and must not fall into the "Extended" (ext spill) bucket.
   */
  async getSchemaFields(): Promise<SchemaFieldsResponse> {
    return this.request('/api/schema/fields');
  }

  // Ingestion
  async ingestEvent(event: Record<string, unknown>): Promise<{ success: boolean; count: number; alerts_generated?: number }> {
    return this.request('/api/ingest', {
      method: 'POST',
      body: JSON.stringify(event),
    });
  }

  // System metrics
  async getSystemOverview(hours?: number): Promise<SystemOverview> {
    const params = hours ? `?hours=${hours}` : '';
    return this.request(`/api/system/overview${params}`);
  }

  async getSystemConfig(): Promise<SystemConfig> {
    return this.request('/api/system/config');
  }

  // Developer Settings (Scheduler Control)
  async getDeveloperSettings(): Promise<DeveloperSettings> {
    return this.request('/api/settings/developer');
  }

  async updateDeveloperSettings(request: UpdateDeveloperSettingsRequest): Promise<DeveloperSettings> {
    return this.request('/api/settings/developer', {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }
}
