// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for PlaybooksApi. Playbook authoring + library are enterprise-only.

import type {
  ApprovalResponseRequest,
  AttachToCaseRequest,
  CreatePlaybookRequest,
  DryResolveRequest,
  DryResolveResponse,
  FinishRunRequest,
  ForkPlaybookRequest,
  ListPlaybooksQuery,
  Playbook,
  PlaybookAnalytics,
  PlaybookApproval,
  PlaybookListResponse,
  PlaybookPermission,
  PlaybookRun,
  PlaybookSuggestion,
  PlaybookVersion,
  ResolvedRunResponse,
  SetPermissionRequest,
  SubmitForReviewRequest,
  UpdatePlaybookRequest,
  UpdateStepCompletionRequest,
} from '@/lib/api/types';

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('PlaybooksApi is enterprise-only'));

// Re-declared types from the enterprise playbooks module — same shape so callers compile.
export interface PlaybookRepository {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  url: string;
  branch: string;
  playbooks_path: string | null;
  auto_sync_enabled: boolean;
  sync_interval_hours: number;
  last_synced_at: string | null;
  last_sync_commit: string | null;
  last_sync_status: 'success' | 'failed' | 'syncing' | null;
  last_sync_error: string | null;
  playbook_count: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreatePlaybookRepositoryRequest {
  name: string;
  url: string;
  description?: string;
  branch?: string;
  playbooks_path?: string;
  auto_sync_enabled?: boolean;
  sync_interval_hours?: number;
}

export interface UpdatePlaybookRepositoryRequest {
  name?: string;
  description?: string;
  branch?: string;
  playbooks_path?: string;
  auto_sync_enabled?: boolean;
  sync_interval_hours?: number;
  enabled?: boolean;
}

export interface PlaybookSyncStartResponse {
  repository_id: string;
  status: string;
  message: string;
}

export interface PlaybookRepositorySyncStatus {
  status: 'success' | 'failed' | 'syncing' | 'idle' | null;
  last_synced_at: string | null;
  last_sync_commit: string | null;
  last_sync_error: string | null;
  playbook_count: number;
}

export interface RepositoryPlaybook {
  id: string;
  repository_id: string;
  file_path: string;
  file_sha: string | null;
  title: string | null;
  subtitle: string | null;
  category: string | null;
}

export interface ImportAllPlaybooksResponse {
  imported: number;
  skipped: number;
  unparseable: number;
  failed: { path: string; error: string }[];
}

export interface SyncAndImportResponse {
  playbooks_total: number;
  playbooks_added: number;
  imported: number;
  skipped: number;
  unparseable: number;
  failed: { path: string; error: string }[];
}

export class PlaybooksApi {
  constructor(
    _request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
  ) {
    void _request;
  }

  list(_query?: ListPlaybooksQuery): Promise<PlaybookListResponse> {
    return ENTERPRISE_ONLY();
  }
  get(_id: string): Promise<Playbook> {
    return ENTERPRISE_ONLY();
  }
  listVersions(_id: string): Promise<PlaybookVersion[]> {
    return ENTERPRISE_ONLY();
  }
  listRuns(_id: string): Promise<PlaybookRun[]> {
    return ENTERPRISE_ONLY();
  }
  listPermissions(_id: string): Promise<PlaybookPermission[]> {
    return ENTERPRISE_ONLY();
  }
  listApprovals(_id: string): Promise<PlaybookApproval[]> {
    return ENTERPRISE_ONLY();
  }
  create(_req: CreatePlaybookRequest): Promise<Playbook> {
    return ENTERPRISE_ONLY();
  }
  update(_id: string, _req: UpdatePlaybookRequest): Promise<Playbook> {
    return ENTERPRISE_ONLY();
  }
  fork(_id: string, _req?: ForkPlaybookRequest): Promise<Playbook> {
    return ENTERPRISE_ONLY();
  }
  archive(_id: string): Promise<void> {
    return ENTERPRISE_ONLY();
  }
  deletePermanent(_id: string): Promise<void> {
    return ENTERPRISE_ONLY();
  }
  suggestForRule(_ruleId: string): Promise<PlaybookSuggestion[]> {
    return ENTERPRISE_ONLY();
  }
  dryResolve(_req: DryResolveRequest): Promise<DryResolveResponse> {
    return ENTERPRISE_ONLY();
  }
  attachToCase(_id: string, _req: AttachToCaseRequest): Promise<PlaybookRun> {
    return ENTERPRISE_ONLY();
  }
  finishRun(_runId: string, _req?: FinishRunRequest): Promise<PlaybookRun> {
    return ENTERPRISE_ONLY();
  }
  listRunsForCase(_caseId: string): Promise<PlaybookRun[]> {
    return ENTERPRISE_ONLY();
  }
  getResolvedRun(_runId: string): Promise<ResolvedRunResponse> {
    return ENTERPRISE_ONLY();
  }
  updateStepCompletion(
    _runId: string,
    _stepId: string,
    _req: UpdateStepCompletionRequest,
  ): Promise<PlaybookRun> {
    return ENTERPRISE_ONLY();
  }
  promote(_id: string): Promise<Playbook> {
    return ENTERPRISE_ONLY();
  }
  composeAdaptiveFromCase(_caseId: string): Promise<Playbook> {
    return ENTERPRISE_ONLY();
  }
  submitForReview(
    _id: string,
    _req?: SubmitForReviewRequest,
  ): Promise<PlaybookApproval> {
    return ENTERPRISE_ONLY();
  }
  approve(
    _approvalId: string,
    _req?: ApprovalResponseRequest,
  ): Promise<PlaybookApproval> {
    return ENTERPRISE_ONLY();
  }
  reject(
    _approvalId: string,
    _req?: ApprovalResponseRequest,
  ): Promise<PlaybookApproval> {
    return ENTERPRISE_ONLY();
  }
  setPermission(
    _id: string,
    _role: string,
    _req: SetPermissionRequest,
  ): Promise<PlaybookPermission> {
    return ENTERPRISE_ONLY();
  }
  deletePermission(_id: string, _role: string): Promise<void> {
    return ENTERPRISE_ONLY();
  }
  getAnalytics(_id: string): Promise<PlaybookAnalytics> {
    return ENTERPRISE_ONLY();
  }
  listRepositories(): Promise<PlaybookRepository[]> {
    return ENTERPRISE_ONLY();
  }
  getRepository(_id: string): Promise<PlaybookRepository> {
    return ENTERPRISE_ONLY();
  }
  createRepository(_req: CreatePlaybookRepositoryRequest): Promise<PlaybookRepository> {
    return ENTERPRISE_ONLY();
  }
  updateRepository(
    _id: string,
    _req: UpdatePlaybookRepositoryRequest,
  ): Promise<PlaybookRepository> {
    return ENTERPRISE_ONLY();
  }
  deleteRepository(_id: string): Promise<void> {
    return ENTERPRISE_ONLY();
  }
  syncRepository(_id: string): Promise<PlaybookSyncStartResponse> {
    return ENTERPRISE_ONLY();
  }
  getSyncStatus(_id: string): Promise<PlaybookRepositorySyncStatus> {
    return ENTERPRISE_ONLY();
  }
  listRepositoryPlaybooks(_id: string): Promise<RepositoryPlaybook[]> {
    return ENTERPRISE_ONLY();
  }
  importRepositoryPlaybook(
    _repoId: string,
    _path: string,
    _importType?: 'linked' | 'forked',
  ): Promise<unknown> {
    return ENTERPRISE_ONLY();
  }
  importAllRepositoryPlaybooks(
    _repoId: string,
    _importType?: 'linked' | 'forked',
  ): Promise<ImportAllPlaybooksResponse> {
    return ENTERPRISE_ONLY();
  }
  syncAndImportRepository(
    _repoId: string,
    _importType?: 'linked' | 'forked',
  ): Promise<SyncAndImportResponse> {
    return ENTERPRISE_ONLY();
  }
}
