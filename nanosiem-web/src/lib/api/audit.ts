// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  AuditLogQuery,
  AuditLogResponse,
} from './types';

export class AuditApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
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
}
