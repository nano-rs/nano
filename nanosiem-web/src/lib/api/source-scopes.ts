// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  RestrictedSource,
  RestrictedSourcesResponse,
  CreateRestrictedSourceRequest,
  SourceScopeGrant,
  SourceScopeGrantsResponse,
  CreateSourceScopeGrantRequest,
} from './types';

/**
 * Per-source RBAC scoping (NAN-1789 / NAN-1802).
 *
 * Controls which analyst groups can SEE events from a given `source_type`. The
 * enforceable unit is the event-borne `source_type` STRING (not a log_source
 * UUID).
 *
 * Model: an EMPTY restricted registry = allow-all (the default — every source
 * is visible to everyone). Listing a `source_type` makes it invisible-by-
 * default; it is then visible only to groups granted it. Granting the
 * "Everyone" system group (`EVERYONE_GROUP_ID`) re-opens it for all users
 * without removing it from the registry.
 *
 * Endpoints are permission-gated: reads require `source_scopes:view`, writes
 * require `source_scopes:manage`.
 */
export class SourceScopesApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  /** List every `source_type` in the restricted registry. */
  async listRestricted(): Promise<RestrictedSourcesResponse> {
    return this.request('/api/source-scopes/restricted');
  }

  /** Add a `source_type` to the restricted registry (makes it invisible-by-default). */
  async addRestricted(req: CreateRestrictedSourceRequest): Promise<RestrictedSource> {
    return this.request('/api/source-scopes/restricted', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  /** Remove a `source_type` from the restricted registry (re-opens it to everyone). */
  async removeRestricted(sourceType: string): Promise<void> {
    return this.request(`/api/source-scopes/restricted/${encodeURIComponent(sourceType)}`, {
      method: 'DELETE',
    });
  }

  /** List the group grants for a restricted `source_type`. */
  async listGrants(sourceType: string): Promise<SourceScopeGrant[]> {
    const res = await this.request<SourceScopeGrantsResponse>(
      `/api/source-scopes/restricted/${encodeURIComponent(sourceType)}/grants`,
    );
    return res.grants;
  }

  /** Grant a group visibility of a restricted `source_type`. */
  async addGrant(req: CreateSourceScopeGrantRequest): Promise<SourceScopeGrant> {
    return this.request('/api/source-scopes/grants', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  /** Revoke a group's grant for a restricted `source_type`. */
  async removeGrant(sourceType: string, groupId: string): Promise<void> {
    return this.request(
      `/api/source-scopes/grants/${encodeURIComponent(sourceType)}/${encodeURIComponent(groupId)}`,
      { method: 'DELETE' },
    );
  }
}
