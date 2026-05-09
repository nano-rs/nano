// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  FileFormat,
  PreviewResult,
  UploadRecord,
  UploadHistoryFilter,
} from './types';
import { getServiceUrl } from './utils';

export class UploadApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
    private getAccessToken?: () => string | null
  ) {}

  async previewUpload(file: File, format?: FileFormat, delimiter?: string): Promise<PreviewResult> {
    // Use FormData for multipart upload - must bypass the standard request function
    const formData = new FormData();
    formData.append('file', file);

    if (format || delimiter) {
      const config: Record<string, unknown> = {
        destination_type: 'lookup',
        destination_name: 'preview',
      };
      if (format) config.format = format;
      if (delimiter) config.csv_delimiter = delimiter;
      formData.append('config', JSON.stringify(config));
    }

    const endpoint = '/api/upload/preview';
    const serviceUrl = getServiceUrl(endpoint);
    const url = `${serviceUrl}${endpoint}`;

    const headers: HeadersInit = {};
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
      throw new Error(error.message || 'Preview failed');
    }

    return response.json();
  }

  async getUploadHistory(filter?: UploadHistoryFilter): Promise<UploadRecord[]> {
    const params = new URLSearchParams();
    if (filter?.destination_type) params.set('destination_type', filter.destination_type);
    if (filter?.destination_name) params.set('destination_name', filter.destination_name);
    if (filter?.status) params.set('status', filter.status);
    if (filter?.start_date) params.set('start_date', filter.start_date);
    if (filter?.end_date) params.set('end_date', filter.end_date);
    if (filter?.limit) params.set('limit', String(filter.limit));
    if (filter?.offset) params.set('offset', String(filter.offset));
    const query = params.toString();
    return this.request(`/api/upload/history${query ? `?${query}` : ''}`);
  }
}
