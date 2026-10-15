// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  SourceVisibilityModel,
  SetGroupRestrictionsRequest,
  GroupRestrictionsResponse,
  SetMemberExceptionsRequest,
  MemberExceptionsResponse,
  EffectiveSourceVisibility,
} from './types';

/**
 * Source visibility on the hosted-shared lake (NAN-2361 wave 8).
 *
 * The restriction key is the source slug every lake event carries in
 * `metadata.log_source`. A restriction is (group, slug): members of that
 * tenant group cannot see events from the source. Per-member exceptions
 * (`restrict` / `allow`) handle one-offs. Everything is visible by default.
 * Effective deny set = groups' restrictions ∪ restrict exceptions − allow
 * exceptions; `source_scopes:view_all` bypasses.
 *
 * Reads need `source_scopes:view`, writes `source_scopes:manage`.
 */
export class SourceVisibilityApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  /** The whole page state: sources, groups, members, restrictions, exceptions. */
  async get(): Promise<SourceVisibilityModel> {
    return this.request('/api/source-visibility');
  }

  /** Replace the set of sources a group cannot see. */
  async setGroupRestrictions(groupId: string, req: SetGroupRestrictionsRequest): Promise<GroupRestrictionsResponse> {
    return this.request(`/api/source-visibility/groups/${encodeURIComponent(groupId)}`, {
      method: 'PUT',
      body: JSON.stringify(req),
    });
  }

  /** Replace a member's one-off exceptions. */
  async setMemberExceptions(userId: string, req: SetMemberExceptionsRequest): Promise<MemberExceptionsResponse> {
    return this.request(`/api/source-visibility/members/${encodeURIComponent(userId)}`, {
      method: 'PUT',
      body: JSON.stringify(req),
    });
  }

  /** A member's effective deny set as the model computes it. */
  async effective(userId: string): Promise<EffectiveSourceVisibility> {
    return this.request(`/api/source-visibility/effective/${encodeURIComponent(userId)}`);
  }
}
