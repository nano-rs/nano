// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  WebhookConfig,
  CreateWebhookRequest,
  UpdateWebhookRequest,
  WebhookDeliveryLog,
  WebhookTestResult,
} from './types';

export class WebhooksApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async listWebhooks(): Promise<WebhookConfig[]> {
    return this.request('/api/settings/webhooks');
  }

  async createWebhook(request: CreateWebhookRequest): Promise<WebhookConfig> {
    return this.request('/api/settings/webhooks', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async getWebhook(id: string): Promise<WebhookConfig> {
    return this.request(`/api/settings/webhooks/${id}`);
  }

  async updateWebhook(id: string, request: UpdateWebhookRequest): Promise<WebhookConfig> {
    return this.request(`/api/settings/webhooks/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async deleteWebhook(id: string): Promise<{ deleted: boolean }> {
    return this.request(`/api/settings/webhooks/${id}`, {
      method: 'DELETE',
    });
  }

  async testWebhook(id: string): Promise<WebhookTestResult> {
    return this.request(`/api/settings/webhooks/${id}/test`, {
      method: 'POST',
    });
  }

  async listDeliveries(id: string, limit?: number): Promise<WebhookDeliveryLog[]> {
    const params = new URLSearchParams();
    if (limit) params.set('limit', String(limit));
    const query = params.toString();
    return this.request(`/api/settings/webhooks/${id}/deliveries${query ? `?${query}` : ''}`);
  }
}
