// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for CasesApi. Cases (investigation management) is enterprise-only.

import type {
  Case,
  CaseListResponse,
  CaseSummary,
  CaseStats,
  CaseFullResponse,
  CaseFilter,
  CreateCaseRequest,
  UpdateCaseRequest,
  AddAlertToCaseRequest,
  CaseWallEntry,
  AddWallEntryRequest,
  ChangeCaseStatusRequest,
  EscalateCaseRequest,
  BulkChangeCaseStatusRequest,
  BulkChangeCaseStatusResponse,
  BulkAssignRequest,
  BulkAssignResponse,
  DuplicateCandidate,
  MergeCasesResponse,
  RelatedCaseSummary,
  CaseGroupingRule,
  CreateGroupingRuleRequest,
  UpdateGroupingRuleRequest,
  CaseSettings,
  UpdateCaseSettingsRequest,
  ShareCaseRequest,
  CaseShareResult,
  CreateHandoffRequest,
  CaseHandoff,
  BounceHandoffRequest,
  PresenceHeartbeatResponse,
} from '@/lib/api/types';

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('CasesApi is enterprise-only'));

export class CasesApi {
  constructor(
    _request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
  ) {
    void _request;
  }

  listCases(_params?: CaseFilter): Promise<CaseListResponse> {
    return ENTERPRISE_ONLY();
  }
  getMyCases(_limit?: number): Promise<CaseSummary[]> {
    return ENTERPRISE_ONLY();
  }
  getCaseStats(): Promise<CaseStats> {
    return ENTERPRISE_ONLY();
  }
  createCase(_request: CreateCaseRequest): Promise<{ case: Case; message: string }> {
    return ENTERPRISE_ONLY();
  }
  getCase(_id: string): Promise<CaseFullResponse> {
    return ENTERPRISE_ONLY();
  }
  updateCase(_id: string, _request: UpdateCaseRequest): Promise<Case> {
    return ENTERPRISE_ONLY();
  }
  deleteCase(_id: string): Promise<{ message: string }> {
    return ENTERPRISE_ONLY();
  }
  addAlertToCase(
    _caseId: string,
    _request: AddAlertToCaseRequest,
  ): Promise<{ message: string }> {
    return ENTERPRISE_ONLY();
  }
  removeAlertFromCase(_caseId: string, _alertId: string): Promise<{ message: string }> {
    return ENTERPRISE_ONLY();
  }
  getCaseWall(
    _caseId: string,
    _limit?: number,
    _offset?: number,
  ): Promise<CaseWallEntry[]> {
    return ENTERPRISE_ONLY();
  }
  addCaseWallEntry(
    _caseId: string,
    _request: AddWallEntryRequest,
  ): Promise<CaseWallEntry> {
    return ENTERPRISE_ONLY();
  }
  assignCase(
    _caseId: string,
    _assignedTo: string | null,
    _assignedGroup?: string | null,
  ): Promise<Case> {
    return ENTERPRISE_ONLY();
  }
  changeCaseStatus(_caseId: string, _request: ChangeCaseStatusRequest): Promise<Case> {
    return ENTERPRISE_ONLY();
  }
  escalateCase(_caseId: string, _request: EscalateCaseRequest): Promise<Case> {
    return ENTERPRISE_ONLY();
  }
  createHandoff(_caseId: string, _request: CreateHandoffRequest): Promise<CaseHandoff> {
    return ENTERPRISE_ONLY();
  }
  acceptHandoff(_caseId: string, _handoffId: string): Promise<CaseHandoff> {
    return ENTERPRISE_ONLY();
  }
  bounceHandoff(
    _caseId: string,
    _handoffId: string,
    _request: BounceHandoffRequest,
  ): Promise<CaseHandoff> {
    return ENTERPRISE_ONLY();
  }
  cancelHandoff(_caseId: string, _handoffId: string): Promise<CaseHandoff> {
    return ENTERPRISE_ONLY();
  }
  postCasePresenceHeartbeat(_caseId: string): Promise<PresenceHeartbeatResponse> {
    return ENTERPRISE_ONLY();
  }
  bulkChangeCaseStatus(
    _request: BulkChangeCaseStatusRequest,
  ): Promise<BulkChangeCaseStatusResponse> {
    return ENTERPRISE_ONLY();
  }
  bulkAssignCases(_request: BulkAssignRequest): Promise<BulkAssignResponse> {
    return ENTERPRISE_ONLY();
  }
  getRelatedCases(_caseId: string): Promise<RelatedCaseSummary[]> {
    return ENTERPRISE_ONLY();
  }
  linkRelatedCase(
    _caseId: string,
    _target: { targetCaseId?: string; targetCaseNumber?: number },
    _reason?: string,
  ): Promise<void> {
    return ENTERPRISE_ONLY();
  }
  unlinkRelatedCase(_caseId: string, _targetCaseId: string): Promise<void> {
    return ENTERPRISE_ONLY();
  }
  getDuplicateCandidates(_caseId: string): Promise<DuplicateCandidate[]> {
    return ENTERPRISE_ONLY();
  }
  shareCase(_caseId: string, _request: ShareCaseRequest): Promise<CaseShareResult> {
    return ENTERPRISE_ONLY();
  }
  mergeCases(
    _targetCaseId: string,
    _sourceCaseIds: string[],
  ): Promise<MergeCasesResponse> {
    return ENTERPRISE_ONLY();
  }
  listGroupingRules(): Promise<CaseGroupingRule[]> {
    return ENTERPRISE_ONLY();
  }
  createGroupingRule(
    _request: CreateGroupingRuleRequest,
  ): Promise<CaseGroupingRule> {
    return ENTERPRISE_ONLY();
  }
  updateGroupingRule(
    _id: string,
    _request: UpdateGroupingRuleRequest,
  ): Promise<CaseGroupingRule> {
    return ENTERPRISE_ONLY();
  }
  deleteGroupingRule(_id: string): Promise<{ message: string }> {
    return ENTERPRISE_ONLY();
  }
  getCaseSettings(): Promise<CaseSettings> {
    return ENTERPRISE_ONLY();
  }
  updateCaseSettings(_request: UpdateCaseSettingsRequest): Promise<CaseSettings> {
    return ENTERPRISE_ONLY();
  }
}
