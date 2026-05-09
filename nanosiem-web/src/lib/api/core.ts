// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Core API routes
 * Handles health checks, fields, source types, ingestion, system metrics, and developer settings
 */

import type {
  FieldInfo,
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
  async listFields(): Promise<FieldInfo[]> {
    return this.request('/api/fields');
  }

  async getExtFieldNames(): Promise<string[]> {
    return this.request('/api/fields/ext');
  }

  async getFieldValues(name: string, limit: number = 10): Promise<[string, number][]> {
    return this.request(`/api/fields/${encodeURIComponent(name)}/values?limit=${limit}`);
  }

  async getSourceTypes(timeRange?: { start: string; end: string }): Promise<[string, number][]> {
    const params = timeRange ? `?start=${encodeURIComponent(timeRange.start)}&end=${encodeURIComponent(timeRange.end)}` : '';
    return this.request(`/api/source-types${params}`);
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
