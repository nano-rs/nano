// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  AuditExportQuery,
  AuditLogQuery,
  AuditLogResponse,
} from './types';

function filenameFromDisposition(response: Response, fallback: string): string {
  const disposition = response.headers.get('content-disposition');
  const encoded = disposition?.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  if (encoded) {
    try {
      return decodeURIComponent(encoded);
    } catch {
      return fallback;
    }
  }
  return disposition?.match(/filename="([^"]+)"/i)?.[1] ?? fallback;
}

export class AuditApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
    private requestRaw: (endpoint: string, options?: RequestInit) => Promise<Response>,
  ) {}

  async queryAuditLogs(query: AuditLogQuery): Promise<AuditLogResponse> {
    const params = new URLSearchParams();
    if (query.user_id) params.append('user_id', query.user_id);
    if (query.action) params.append('action', query.action);
    if (query.resource_type) params.append('resource_type', query.resource_type);
    if (query.source) params.append('source', query.source);
    if (query.start_time) params.append('start_time', query.start_time);
    if (query.end_time) params.append('end_time', query.end_time);
    if (query.success !== undefined) params.append('success', String(query.success));
    if (query.limit !== undefined) params.append('limit', String(query.limit));
    if (query.offset !== undefined) params.append('offset', String(query.offset));

    const queryString = params.toString();
    return this.request(`/api/audit${queryString ? `?${queryString}` : ''}`);
  }

  /** Download every matching audit row, bounded by the server at 100,000. */
  async exportAuditLogs(query: AuditExportQuery): Promise<{ blob: Blob; filename: string }> {
    const params = new URLSearchParams();
    if (query.user_id) params.append('user_id', query.user_id);
    if (query.action) params.append('action', query.action);
    if (query.resource_type) params.append('resource_type', query.resource_type);
    if (query.source) params.append('source', query.source);
    if (query.start_time) params.append('start_time', query.start_time);
    if (query.end_time) params.append('end_time', query.end_time);
    if (query.success !== undefined) params.append('success', String(query.success));
    params.append('format', query.format ?? 'csv');
    params.append('limit', String(Math.min(query.limit ?? 100_000, 100_000)));

    const response = await this.requestRaw(`/api/audit/export?${params.toString()}`, { method: 'POST' });
    return {
      blob: await response.blob(),
      filename: filenameFromDisposition(response, `audit_logs.${query.format ?? 'csv'}`),
    };
  }
}
