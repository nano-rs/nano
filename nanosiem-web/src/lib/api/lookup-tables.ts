// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  LookupTable,
  LookupUsage,
  LookupHistoryEntry,
  CreateLookupTableConfig,
  CreateLookupTableResponse,
  CreateLookupTableFromSchemaRequest,
  LookupQueryRequest,
  LookupResult,
  BatchLookupResult,
  LookupRowsPage,
  AddRowsResponse,
  ScheduledJob,
  UpsertLookupIngestionRequest,
  ValidateCronResponse,
  JobExecution,
} from './types';
import { getServiceUrl } from './utils';

export class LookupTablesApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
    private getAccessToken?: () => string | null
  ) {}

  async listLookupTables(): Promise<LookupTable[]> {
    return this.request('/api/lookup-tables');
  }

  async getLookupTable(id: string): Promise<LookupTable> {
    return this.request(`/api/lookup-tables/${id}`);
  }

  async createLookupTable(config: CreateLookupTableConfig, file: File): Promise<CreateLookupTableResponse> {
    // Use FormData for multipart upload - must bypass the standard request function
    // which sets Content-Type to application/json
    const formData = new FormData();
    formData.append('file', file);
    formData.append('config', JSON.stringify(config));

    const endpoint = '/api/lookup-tables';
    const serviceUrl = getServiceUrl(endpoint);
    const url = `${serviceUrl}${endpoint}`;

    const headers: HeadersInit = {};
    // Add Authorization header if we have a token
    if (this.getAccessToken) {
      const token = this.getAccessToken();
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
    }

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: formData,
    });

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({
        error: { code: 'UNKNOWN_ERROR', message: response.statusText }
      }));
      const error = errorBody.error || errorBody;
      throw new Error(error.message || 'Request failed');
    }

    return response.json();
  }

  async deleteLookupTable(id: string): Promise<{ success: boolean }> {
    return this.request(`/api/lookup-tables/${id}`, {
      method: 'DELETE',
    });
  }

  async lookupQuery(request: LookupQueryRequest): Promise<LookupResult | BatchLookupResult> {
    return this.request('/api/lookup-tables/query', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async sampleRows(name: string, limit?: number): Promise<{ rows: Record<string, unknown>[] }> {
    const params = new URLSearchParams();
    if (limit) params.set('limit', String(limit));
    const query = params.toString();
    return this.request(`/api/lookup-tables/${encodeURIComponent(name)}/sample${query ? `?${query}` : ''}`);
  }

  /**
   * Detection rules that reference this lookup table via `@<name>` in their nPL query.
   *
   * Powers the Usage section of the LookupTableView Details inspector.
   * 404s if the lookup table does not exist; returns `[]` when no rules
   * reference the table.
   */
  async usage(name: string): Promise<LookupUsage[]> {
    return this.request(`/api/lookup-tables/${encodeURIComponent(name)}/usage`);
  }

  /**
   * Recent activity (refresh + edit + upload events) on this lookup table.
   *
   * Powers the History tab on the redesigned LookupTableView (NAN-510 slice 3
   * PR 3 / NAN-512). 404s if the lookup table does not exist; returns `[]`
   * when there is no recorded activity.
   */
  async ingestionHistory(name: string, limit?: number): Promise<LookupHistoryEntry[]> {
    const params = new URLSearchParams();
    if (limit) params.set('limit', String(limit));
    const query = params.toString();
    return this.request(
      `/api/lookup-tables/${encodeURIComponent(name)}/ingestion-history${query ? `?${query}` : ''}`,
    );
  }

  async createLookupTableFromSchema(req: CreateLookupTableFromSchemaRequest): Promise<LookupTable> {
    return this.request('/api/lookup-tables/schema', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async listRows(name: string, page?: number, pageSize?: number): Promise<LookupRowsPage> {
    const params = new URLSearchParams();
    if (page) params.set('page', String(page));
    if (pageSize) params.set('page_size', String(pageSize));
    const query = params.toString();
    return this.request(`/api/lookup-tables/${encodeURIComponent(name)}/rows${query ? `?${query}` : ''}`);
  }

  async addRows(name: string, rows: Record<string, unknown>[]): Promise<AddRowsResponse> {
    return this.request(`/api/lookup-tables/${encodeURIComponent(name)}/rows`, {
      method: 'POST',
      body: JSON.stringify({ rows }),
    });
  }

  async updateRow(name: string, rowId: number, fields: Record<string, unknown>): Promise<{ success: boolean }> {
    return this.request(`/api/lookup-tables/${encodeURIComponent(name)}/rows/${rowId}`, {
      method: 'PUT',
      body: JSON.stringify({ fields }),
    });
  }

  async deleteRow(name: string, rowId: number): Promise<{ success: boolean }> {
    return this.request(`/api/lookup-tables/${encodeURIComponent(name)}/rows/${rowId}`, {
      method: 'DELETE',
    });
  }

  async deleteRows(name: string, rowIds: number[]): Promise<{ deleted: number }> {
    return this.request(`/api/lookup-tables/${encodeURIComponent(name)}/rows`, {
      method: 'DELETE',
      body: JSON.stringify({ row_ids: rowIds }),
    });
  }

  // ==================== Ingestion (scheduled jobs) ====================

  async getIngestion(name: string): Promise<ScheduledJob | null> {
    return this.request(`/api/lookup-tables/${encodeURIComponent(name)}/ingestion`);
  }

  async upsertIngestion(name: string, request: UpsertLookupIngestionRequest): Promise<ScheduledJob> {
    return this.request(`/api/lookup-tables/${encodeURIComponent(name)}/ingestion`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async deleteIngestion(name: string): Promise<{ success: boolean }> {
    return this.request(`/api/lookup-tables/${encodeURIComponent(name)}/ingestion`, {
      method: 'DELETE',
    });
  }

  async triggerIngestion(name: string): Promise<JobExecution> {
    return this.request(`/api/lookup-tables/${encodeURIComponent(name)}/ingestion/trigger`, {
      method: 'POST',
    });
  }

  async enableIngestion(name: string): Promise<ScheduledJob> {
    return this.request(`/api/lookup-tables/${encodeURIComponent(name)}/ingestion/enable`, {
      method: 'POST',
    });
  }

  async disableIngestion(name: string): Promise<ScheduledJob> {
    return this.request(`/api/lookup-tables/${encodeURIComponent(name)}/ingestion/disable`, {
      method: 'POST',
    });
  }

  async validateCron(expression: string, previewCount?: number): Promise<ValidateCronResponse> {
    return this.request('/api/lookup-tables/validate-cron', {
      method: 'POST',
      body: JSON.stringify({ expression, preview_count: previewCount }),
    });
  }
}
