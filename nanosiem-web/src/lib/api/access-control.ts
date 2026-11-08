// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  UserDetail,
  UserListResponse,
  CreateUserRequest,
  UpdateUserRequest,
  GroupDetail,
  GroupListResponse,
  CreateGroupRequest,
  UpdateGroupRequest,
  RoleDetail,
  RoleListResponse,
  CreateRoleRequest,
  UpdateRoleRequest,
  PermissionInfo,
  ApiKeySummary,
  ApiKeyListResponse,
  CreateApiKeyRequest,
  UpdateApiKeyRequest,
  ApiKeyCreatedResponse,
  ApiKeyUsageResponse,
  SessionListResponse,
  OidcProviderSummary,
  OidcProviderListResponse,
  CreateOidcProviderRequest,
  UpdateOidcProviderRequest,
  OidcGroupMappingsResponse,
  UpdateOidcGroupMappingsRequest,
  OidcTokenGroupsResponse,
  AuthMethodsSettings,
} from './types';

export class AccessControlApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  // User management
  async listUsers(): Promise<UserListResponse> {
    return this.request('/api/users');
  }

  async getUser(id: string): Promise<UserDetail> {
    return this.request(`/api/users/${id}`);
  }

  async createUser(request: CreateUserRequest): Promise<UserDetail> {
    return this.request('/api/users', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async updateUser(id: string, request: UpdateUserRequest): Promise<UserDetail> {
    return this.request(`/api/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async deleteUser(id: string): Promise<void> {
    return this.request(`/api/users/${id}`, {
      method: 'DELETE',
    });
  }

  async unlockUser(id: string): Promise<UserDetail> {
    return this.request(`/api/users/${id}/unlock`, {
      method: 'POST',
    });
  }

  async disableUser(id: string): Promise<UserDetail> {
    return this.request(`/api/users/${id}/disable`, {
      method: 'POST',
    });
  }

  async enableUser(id: string): Promise<UserDetail> {
    return this.request(`/api/users/${id}/enable`, {
      method: 'POST',
    });
  }

  // Group management
  async listGroups(): Promise<GroupListResponse> {
    return this.request('/api/groups');
  }

  async getGroup(id: string): Promise<GroupDetail> {
    return this.request(`/api/groups/${id}`);
  }

  async createGroup(request: CreateGroupRequest): Promise<GroupDetail> {
    return this.request('/api/groups', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async updateGroup(id: string, request: UpdateGroupRequest): Promise<GroupDetail> {
    return this.request(`/api/groups/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async deleteGroup(id: string): Promise<void> {
    return this.request(`/api/groups/${id}`, {
      method: 'DELETE',
    });
  }

  // Role management
  async listRoles(): Promise<RoleListResponse> {
    return this.request('/api/roles');
  }

  async getRole(id: string): Promise<RoleDetail> {
    return this.request(`/api/roles/${id}`);
  }

  async createRole(request: CreateRoleRequest): Promise<RoleDetail> {
    return this.request('/api/roles', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async updateRole(id: string, request: UpdateRoleRequest): Promise<RoleDetail> {
    return this.request(`/api/roles/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async deleteRole(id: string): Promise<void> {
    return this.request(`/api/roles/${id}`, {
      method: 'DELETE',
    });
  }

  async listPermissions(): Promise<PermissionInfo[]> {
    const response = await this.request<{ permissions: PermissionInfo[] }>('/api/permissions');
    return response.permissions;
  }

  // API Key management
  async listApiKeys(): Promise<ApiKeyListResponse> {
    return this.request('/api/api-keys');
  }

  async createApiKey(request: CreateApiKeyRequest): Promise<ApiKeyCreatedResponse> {
    return this.request('/api/api-keys', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async getApiKey(id: string): Promise<ApiKeySummary> {
    return this.request(`/api/api-keys/${id}`);
  }

  async getApiKeyUsage(id: string, days = 14): Promise<ApiKeyUsageResponse> {
    return this.request(`/api/api-keys/${id}/usage?days=${days}`);
  }

  async updateApiKey(id: string, request: UpdateApiKeyRequest): Promise<ApiKeySummary> {
    return this.request(`/api/api-keys/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async resetApiKey(id: string): Promise<ApiKeyCreatedResponse> {
    return this.request(`/api/api-keys/${id}/reset`, {
      method: 'POST',
    });
  }

  async deleteApiKey(id: string): Promise<void> {
    return this.request(`/api/api-keys/${id}`, {
      method: 'DELETE',
    });
  }

  async enableApiKey(id: string): Promise<ApiKeySummary> {
    return this.request(`/api/api-keys/${id}/enable`, {
      method: 'POST',
    });
  }

  async disableApiKey(id: string): Promise<ApiKeySummary> {
    return this.request(`/api/api-keys/${id}/disable`, {
      method: 'POST',
    });
  }

  // Session management
  async listAllSessions(): Promise<SessionListResponse> {
    return this.request('/api/sessions');
  }

  async listMySessions(): Promise<SessionListResponse> {
    return this.request('/api/sessions/me');
  }

  async terminateSession(id: string): Promise<void> {
    return this.request(`/api/sessions/${id}`, {
      method: 'DELETE',
    });
  }

  // OIDC Provider Management
  async listOidcProviders(): Promise<OidcProviderListResponse> {
    return this.request('/api/settings/oidc');
  }

  /** NAN-2181: tenant authentication-method configuration (admin view). */
  async getAuthMethodsSettings(): Promise<AuthMethodsSettings> {
    return this.request('/api/settings/auth-methods');
  }

  /**
   * NAN-2181: turn local password sign-in on or off.
   *
   * Rejected with 409 when disabling without an enabled OIDC provider — the
   * server owns that guard; the UI disabling the control is a convenience.
   */
  async updateAuthMethodsSettings(localPasswordEnabled: boolean): Promise<AuthMethodsSettings> {
    return this.request('/api/settings/auth-methods', {
      method: 'PUT',
      body: JSON.stringify({ localPasswordEnabled }),
    });
  }

  async getOidcProvider(id: string): Promise<OidcProviderSummary> {
    return this.request(`/api/settings/oidc/${id}`);
  }

  async createOidcProvider(request: CreateOidcProviderRequest): Promise<OidcProviderSummary> {
    return this.request('/api/settings/oidc', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async updateOidcProvider(id: string, request: UpdateOidcProviderRequest): Promise<OidcProviderSummary> {
    return this.request(`/api/settings/oidc/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async deleteOidcProvider(id: string): Promise<void> {
    return this.request(`/api/settings/oidc/${id}`, {
      method: 'DELETE',
    });
  }

  async enableOidcProvider(id: string): Promise<OidcProviderSummary> {
    return this.request(`/api/settings/oidc/${id}/enable`, {
      method: 'POST',
    });
  }

  async disableOidcProvider(id: string): Promise<OidcProviderSummary> {
    return this.request(`/api/settings/oidc/${id}/disable`, {
      method: 'POST',
    });
  }

  async getOidcGroupMappings(providerId: string): Promise<OidcGroupMappingsResponse> {
    return this.request(`/api/settings/oidc/${providerId}/mappings`);
  }

  async updateOidcGroupMappings(providerId: string, request: UpdateOidcGroupMappingsRequest): Promise<OidcGroupMappingsResponse> {
    return this.request(`/api/settings/oidc/${providerId}/mappings`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async getOidcTokenGroups(providerId: string): Promise<OidcTokenGroupsResponse> {
    return this.request(`/api/settings/oidc/${providerId}/token-groups`);
  }
}
