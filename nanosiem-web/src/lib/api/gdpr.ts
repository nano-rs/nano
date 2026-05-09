// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * GDPR Anonymization API routes
 * Handles data subject anonymization requests (right to erasure)
 */

import type {
  GdprSubmitRequest,
  GdprAnonymizationPreview,
  GdprAnonymizationRequest,
  GdprAnonymizationListResponse,
} from './types';

export class GdprApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async submitRequest(req: GdprSubmitRequest): Promise<GdprAnonymizationPreview> {
    return this.request('/api/gdpr/anonymize', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async listRequests(params?: { limit?: number; offset?: number }): Promise<GdprAnonymizationListResponse> {
    const searchParams = new URLSearchParams();
    if (params?.limit != null) searchParams.set('limit', String(params.limit));
    if (params?.offset != null) searchParams.set('offset', String(params.offset));
    const query = searchParams.toString();
    return this.request(`/api/gdpr/anonymize${query ? `?${query}` : ''}`);
  }

  async getRequest(id: string): Promise<GdprAnonymizationRequest> {
    return this.request(`/api/gdpr/anonymize/${id}`);
  }

  async executeRequest(id: string): Promise<GdprAnonymizationRequest> {
    return this.request(`/api/gdpr/anonymize/${id}/execute`, {
      method: 'POST',
    });
  }
}
