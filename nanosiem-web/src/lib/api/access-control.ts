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
  SharedTenantInviteRequest,
  SharedTenantInviteResponse,
  SharedTenantMember,
  SharedTenantUpdateMemberRequest,
  SharedTenantMembershipInvitationListResponse,
  MySharedTenantInvitationListResponse,
  AcceptMySharedTenantInvitationResponse,
  SharedOidcAdminProviderList,
  SharedOidcAdminMutationResponse,
  SharedOidcAdminCreateRequest,
  SharedOidcAdminUpdateRequest,
} from './types';
import { browserTenantRuntime } from '@/lib/tenant-runtime';
import {
  apiKeyCreatedFromShared,
  apiKeyListFromShared,
  apiKeySummaryFromShared,
  sharedCreateRequest,
  sharedUpdateRequest,
  SharedApiKeyUnsupportedError,
  type CreatedSharedAutomationKey,
  type SharedAutomationKeyList,
  type SharedAutomationKeySummary,
} from '@/lib/shared-automation-keys';

/**
 * NAN-2361: a hosted-shared tenant's `/api/api-keys` is the tenant
 * automation-key registry, whose wire shape differs from the dedicated one
 * (camelCase, `status` instead of `enabled`, rotate instead of reset, no
 * enable / disable, no per-key GET). The mapping lives in
 * `lib/shared-automation-keys.ts`; this is the one place the client branches.
 */
function sharedTenantRuntime(): boolean {
  return browserTenantRuntime.current().scope.kind === 'enterprise_shared';
}

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

  /**
   * Hosted-shared tenant: invite a member (no password; the one-time
   * activation link is returned exactly once).
   */
  async inviteSharedTenantMember(request: SharedTenantInviteRequest): Promise<SharedTenantInviteResponse> {
    return this.request('/api/users', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  /** Hosted-shared tenant: replace a member's roles / groups and/or suspend / re-activate. */
  async updateSharedTenantMember(id: string, request: SharedTenantUpdateMemberRequest): Promise<SharedTenantMember> {
    return this.request(`/api/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  /** Hosted-shared tenant: existing-identity invitations of this tenant (NAN-2361 wave 5). */
  async listSharedTenantMembershipInvitations(): Promise<SharedTenantMembershipInvitationListResponse> {
    return this.request('/api/users/invitations');
  }

  async revokeSharedTenantMembershipInvitation(id: string): Promise<void> {
    return this.request(`/api/users/invitations/${id}`, { method: 'DELETE' });
  }

  /** The signed-in identity's pending invitations from other tenants. */
  async listMySharedTenantInvitations(): Promise<MySharedTenantInvitationListResponse> {
    return this.request('/api/users/me/invitations');
  }

  /** Accept one of the signed-in identity's invitations from the console (fresh session, exact origin). */
  async acceptMySharedTenantInvitation(id: string, idempotencyKey: string): Promise<AcceptMySharedTenantInvitationResponse> {
    return this.request(`/api/users/me/invitations/${id}/accept`, {
      method: 'POST',
      body: JSON.stringify({ idempotency_key: idempotencyKey }),
    });
  }

  // Hosted-shared OIDC provider administration (step-up admin API, NAN-2361 wave 5)
  async listSharedOidcAdminProviders(): Promise<SharedOidcAdminProviderList> {
    return this.request('/api/auth/shared/oidc/admin/providers');
  }

  async createSharedOidcAdminProvider(request: SharedOidcAdminCreateRequest): Promise<SharedOidcAdminMutationResponse> {
    return this.request('/api/auth/shared/oidc/admin/providers', { method: 'POST', body: JSON.stringify(request) });
  }

  async updateSharedOidcAdminProvider(id: string, request: SharedOidcAdminUpdateRequest): Promise<SharedOidcAdminMutationResponse> {
    return this.request(`/api/auth/shared/oidc/admin/providers/${id}`, { method: 'PUT', body: JSON.stringify(request) });
  }

  async rotateSharedOidcAdminProviderSecret(id: string, idempotencyKey: string, clientSecret: string): Promise<SharedOidcAdminMutationResponse> {
    return this.request(`/api/auth/shared/oidc/admin/providers/${id}/rotate-secret`, {
      method: 'POST', body: JSON.stringify({ idempotency_key: idempotencyKey, client_secret: clientSecret }),
    });
  }

  async setSharedOidcAdminProviderEnabled(id: string, idempotencyKey: string, enabled: boolean): Promise<SharedOidcAdminMutationResponse> {
    return this.request(`/api/auth/shared/oidc/admin/providers/${id}/${enabled ? 'enable' : 'disable'}`, {
      method: 'POST', body: JSON.stringify({ idempotency_key: idempotencyKey }),
    });
  }

  /** "Delete": retires the provider (disabled, hidden, slug released; identities and revisions kept). */
  async deleteSharedOidcAdminProvider(id: string, idempotencyKey: string): Promise<SharedOidcAdminMutationResponse> {
    return this.request(`/api/auth/shared/oidc/admin/providers/${id}`, {
      method: 'DELETE', body: JSON.stringify({ idempotency_key: idempotencyKey }),
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
    if (sharedTenantRuntime()) {
      return apiKeyListFromShared(await this.request<SharedAutomationKeyList>('/api/api-keys'));
    }
    return this.request('/api/api-keys');
  }

  async createApiKey(request: CreateApiKeyRequest): Promise<ApiKeyCreatedResponse> {
    if (sharedTenantRuntime()) {
      const created = await this.request<CreatedSharedAutomationKey>('/api/api-keys', {
        method: 'POST',
        body: JSON.stringify(sharedCreateRequest(request)),
      });
      return apiKeyCreatedFromShared(created);
    }
    return this.request('/api/api-keys', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async getApiKey(id: string): Promise<ApiKeySummary> {
    if (sharedTenantRuntime()) {
      // The shared registry has no per-key GET; the owner-scoped list is small
      // (plan-capped) and already the page's source of truth.
      const list = await this.listApiKeys();
      const key = list.api_keys.find(candidate => candidate.id === id);
      if (!key) throw new Error('API key not found');
      return key;
    }
    return this.request(`/api/api-keys/${id}`);
  }

  /**
   * Same path and response shape on both editions. On a hosted-shared tenant
   * the series counts authenticated requests from the key-authority ledger
   * (real request volume); on a dedicated deployment it counts audited actions.
   */
  async getApiKeyUsage(id: string, days = 14): Promise<ApiKeyUsageResponse> {
    return this.request(`/api/api-keys/${id}/usage?days=${days}`);
  }

  async updateApiKey(id: string, request: UpdateApiKeyRequest): Promise<ApiKeySummary> {
    if (sharedTenantRuntime()) {
      const updated = await this.request<SharedAutomationKeySummary>(`/api/api-keys/${id}`, {
        method: 'PUT',
        body: JSON.stringify(sharedUpdateRequest(request)),
      });
      return apiKeySummaryFromShared(updated);
    }
    return this.request(`/api/api-keys/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  /** Issue a new secret (shown once). Shared tenants call it "rotate". */
  async resetApiKey(id: string): Promise<ApiKeyCreatedResponse> {
    if (sharedTenantRuntime()) {
      const rotated = await this.request<CreatedSharedAutomationKey>(`/api/api-keys/${id}/rotate`, {
        method: 'POST',
      });
      return apiKeyCreatedFromShared(rotated);
    }
    return this.request(`/api/api-keys/${id}/reset`, {
      method: 'POST',
    });
  }

  /** Dedicated: permanent delete. Shared: terminal revoke (row stays listed as `revoked`). */
  async deleteApiKey(id: string): Promise<void> {
    return this.request(`/api/api-keys/${id}`, {
      method: 'DELETE',
    });
  }

  async enableApiKey(id: string): Promise<ApiKeySummary> {
    if (sharedTenantRuntime()) throw new SharedApiKeyUnsupportedError('enable');
    return this.request(`/api/api-keys/${id}/enable`, {
      method: 'POST',
    });
  }

  async disableApiKey(id: string): Promise<ApiKeySummary> {
    if (sharedTenantRuntime()) throw new SharedApiKeyUnsupportedError('disable');
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
