// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Identity Provider API client
 *
 * Manages identity provider sync (Entra ID, Google Workspace, AD)
 * and the unified user directory.
 */

import type {
  IdentityProviderSummary,
  CreateIdentityProviderRequest,
  UpdateIdentityProviderRequest,
  IdentityConnectionTestResponse,
  IdentityUser,
  IdentityUserListResponse,
  IdentityStats,
  IdentitySyncTriggerResponse,
  ListIdentityProvidersResponse,
  IdentityResolveResponse,
} from './types';

export class IdentityApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
  ) {}

  // ========================================================================
  // Provider Management
  // ========================================================================

  async listProviders(): Promise<ListIdentityProvidersResponse> {
    return this.request('/api/settings/identity-providers');
  }

  async getProvider(id: string): Promise<IdentityProviderSummary> {
    return this.request(`/api/settings/identity-providers/${id}`);
  }

  async createProvider(
    request: CreateIdentityProviderRequest,
  ): Promise<IdentityProviderSummary> {
    return this.request('/api/settings/identity-providers', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async updateProvider(
    id: string,
    request: UpdateIdentityProviderRequest,
  ): Promise<IdentityProviderSummary> {
    return this.request(`/api/settings/identity-providers/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async deleteProvider(
    id: string,
  ): Promise<{ success: boolean; message: string }> {
    return this.request(`/api/settings/identity-providers/${id}`, {
      method: 'DELETE',
    });
  }

  async updateCredentials(
    id: string,
    credentials: Record<string, unknown>,
  ): Promise<{ success: boolean; message: string }> {
    return this.request(`/api/settings/identity-providers/${id}/credentials`, {
      method: 'POST',
      body: JSON.stringify({ credentials }),
    });
  }

  async testConnection(id: string): Promise<IdentityConnectionTestResponse> {
    return this.request(
      `/api/settings/identity-providers/${id}/test`,
      { method: 'POST' },
    );
  }

  async triggerSync(id: string): Promise<IdentitySyncTriggerResponse> {
    return this.request(
      `/api/settings/identity-providers/${id}/sync`,
      { method: 'POST' },
    );
  }

  // ========================================================================
  // User Directory
  // ========================================================================

  async listUsers(params?: {
    provider_id?: string;
    search?: string;
    account_status?: string;
    page?: number;
    page_size?: number;
  }): Promise<IdentityUserListResponse> {
    const searchParams = new URLSearchParams();
    if (params?.provider_id) searchParams.set('provider_id', params.provider_id);
    if (params?.search) searchParams.set('search', params.search);
    if (params?.account_status) searchParams.set('account_status', params.account_status);
    if (params?.page) searchParams.set('page', String(params.page));
    if (params?.page_size) searchParams.set('page_size', String(params.page_size));

    const qs = searchParams.toString();
    return this.request(`/api/identity/users${qs ? `?${qs}` : ''}`);
  }

  // NAN-1117: id is now the composite "provider_id|external_id" string.
  async getUser(id: string): Promise<IdentityUser> {
    return this.request(`/api/identity/users/${encodeURIComponent(id)}`);
  }

  async lookupUser(identifier: string): Promise<IdentityUser | null> {
    try {
      return await this.request(`/api/identity/users/lookup?q=${encodeURIComponent(identifier)}`);
    } catch {
      return null;
    }
  }

  async getStats(): Promise<IdentityStats> {
    return this.request('/api/identity/stats');
  }

  // ========================================================================
  // IP Identity Resolution
  // ========================================================================

  async resolveIdentity(ip: string, timestamp?: string): Promise<IdentityResolveResponse> {
    const params = new URLSearchParams({ ip });
    if (timestamp) params.set('timestamp', timestamp);
    return this.request(`/api/identity/resolve?${params.toString()}`);
  }
}
