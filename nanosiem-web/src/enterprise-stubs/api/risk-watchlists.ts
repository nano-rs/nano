// SPDX-License-Identifier: AGPL-3.0-or-later
/* eslint-disable @typescript-eslint/no-unused-vars -- open-edition stub keeps the enterprise signatures */

// Open-edition stub for RiskWatchlistsApi. Risk watchlists are enterprise-only.

import type {
  RiskWatchlist,
  RiskWatchlistMemberInput,
  RiskWatchlistsResponse,
  RiskWatchlistDetailResponse,
  CreateRiskWatchlistRequest,
  UpdateRiskWatchlistRequest,
  AddRiskWatchlistMembersResponse,
  RemoveRiskWatchlistMembersResponse,
  DeleteRiskWatchlistResponse,
  RiskWatchlistLookupResponse,
  RiskWatchlistMembershipsResponse,
  RiskWatchlistSuggestResponse,
} from '@/lib/api/types';

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('RiskWatchlistsApi is enterprise-only'));

export class RiskWatchlistsApi {
  constructor(_request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {
    void _request;
  }

  list(): Promise<RiskWatchlistsResponse> {
    return ENTERPRISE_ONLY();
  }
  get(_id: string): Promise<RiskWatchlistDetailResponse> {
    return ENTERPRISE_ONLY();
  }
  create(_request: CreateRiskWatchlistRequest): Promise<RiskWatchlist> {
    return ENTERPRISE_ONLY();
  }
  update(_id: string, _request: UpdateRiskWatchlistRequest): Promise<RiskWatchlist> {
    return ENTERPRISE_ONLY();
  }
  delete(_id: string): Promise<DeleteRiskWatchlistResponse> {
    return ENTERPRISE_ONLY();
  }
  addMembers(
    _id: string,
    _members: RiskWatchlistMemberInput[],
    _note?: string,
  ): Promise<AddRiskWatchlistMembersResponse> {
    return ENTERPRISE_ONLY();
  }
  removeMembers(_id: string, _values: string[]): Promise<RemoveRiskWatchlistMembersResponse> {
    return ENTERPRISE_ONLY();
  }
  lookup(_entity: string): Promise<RiskWatchlistLookupResponse> {
    return ENTERPRISE_ONLY();
  }
  memberships(): Promise<RiskWatchlistMembershipsResponse> {
    return ENTERPRISE_ONLY();
  }
  suggest(_values: RiskWatchlistMemberInput[]): Promise<RiskWatchlistSuggestResponse> {
    return ENTERPRISE_ONLY();
  }
}
