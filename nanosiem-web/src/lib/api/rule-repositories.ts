// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Rule Repository API routes
 * Handles external rule repository sync, Sigma rule browsing, and imports
 */

// =============================================================================
// Types
// =============================================================================

export interface RuleRepository {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  url: string;
  branch: string;
  rules_path: string | null;
  rule_format: 'sigma' | 'nanosiem';
  auto_sync_enabled: boolean;
  sync_interval_hours: number;
  last_synced_at: string | null;
  last_sync_commit: string | null;
  last_sync_status: 'success' | 'failed' | 'syncing' | null;
  last_sync_error: string | null;
  rule_count: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  created_by: string | null;
  /** Selected paths for sync. Null means sync all, empty array means sync nothing. */
  selected_paths: string[] | null;
}

export interface CreateRepositoryRequest {
  name: string;
  url: string;
  description?: string;
  branch?: string;
  rules_path?: string;
  rule_format?: 'sigma' | 'nanosiem';
  auto_sync_enabled?: boolean;
  sync_interval_hours?: number;
}

export interface UpdateRepositoryRequest {
  name?: string;
  description?: string;
  branch?: string;
  rules_path?: string;
  auto_sync_enabled?: boolean;
  sync_interval_hours?: number;
  enabled?: boolean;
  /** Selected paths to sync. Send empty array to clear, omit to leave unchanged. */
  selected_paths?: string[];
}

export interface FolderInfo {
  name: string;
  path: string;
  file_count: number;
  rule_count: number;
}

export interface RepositoryRule {
  id: string;
  repository_id: string;
  file_path: string;
  file_sha: string | null;
  raw_content: string;
  // Import status (from API enrichment)
  is_imported?: boolean;
  linked_detection_rule_id?: string | null;
  title: string | null;
  description: string | null;
  severity: string | null;
  mitre_tactics: string[] | null;
  mitre_techniques: string[] | null;
  tags: string[] | null;
  requires_fields: string[] | null;
  requires_source_types: string[] | null;
  conversion_status: 'pending' | 'success' | 'failed' | 'manual' | 'untranslated';
  converted_npl: string | null;
  conversion_confidence: number | null;
  conversion_warnings: string[] | null;
  conversion_field_mappings: Record<string, string> | null;
  coverage_status: 'full' | 'partial' | 'none' | null;
  coverage_missing_fields: string[] | null;
  created_at: string;
  updated_at: string;
}

export interface RepositoryRuleFilter {
  path_prefix?: string;
  severity?: string;
  conversion_status?: string;
  coverage_status?: string;
  search?: string;
  has_npl?: boolean;
  limit?: number;
  offset?: number;
}

export interface SyncResult {
  repository_id: string;
  status: 'success' | 'failed' | 'syncing';
  commit: string | null;
  rules_added: number;
  rules_updated: number;
  rules_removed: number;
  rules_total: number;
  conversion_succeeded: number;
  conversion_failed: number;
  duration_ms: number;
  error: string | null;
}

/** Response when starting a sync (async operation) */
export interface SyncStartResponse {
  repository_id: string;
  status: string;
  message: string;
}

export interface SyncStatus {
  status: string | null;
  last_synced_at: string | null;
  last_sync_commit: string | null;
  last_sync_error: string | null;
  rule_count: number;
}

export interface ImportRequest {
  import_type?: 'linked' | 'forked';
  folder?: string;
  name?: string;
  severity?: string;
  mode?: string;
  custom_npl?: string;
  /** Source type mappings: { original_type: replacement_type } */
  source_type_mappings?: Record<string, string>;
  /** Merge all source types to a single type */
  merge_to_single_source_type?: string;
}

export interface SourceTypeSuggestion {
  missing_type: string;
  suggested_type: string;
  reason: string;
}

export interface ImportPreview {
  repository_rule: RepositoryRule;
  proposed_name: string;
  proposed_description: string | null;
  proposed_severity: string;
  proposed_query: string | null;
  proposed_mitre_tactics: string[];
  proposed_mitre_techniques: string[];
  conversion_status: string;
  conversion_confidence: number | null;
  conversion_warnings: string[];
  field_mappings: Record<string, string> | null;
  coverage_status: string | null;
  missing_fields: string[];
  available_source_types: string[];
  /** Source types required by the rule */
  required_source_types: string[];
  /** Source types that are missing in your environment */
  missing_source_types: string[];
  /** Suggestions for alternative source types */
  source_type_suggestions: SourceTypeSuggestion[];
  already_imported: boolean;
  existing_import_type: string | null;
  existing_detection_rule_id: string | null;
}

export interface ImportResult {
  detection_rule_id: string;
  import_type: string;
}

// Upstream change tracking

export interface UpdatedRule {
  repository_rule_id: string;
  detection_rule_id: string;
  file_path: string;
  title: string | null;
  change_type: 'modified' | 'deleted';
  old_sha: string | null;
  new_sha: string | null;
}

export interface UpstreamUpdatesResponse {
  updates: UpdatedRule[];
  total_count: number;
}

export interface UpstreamDiff {
  detection_rule_id: string;
  repository_rule_id: string;
  file_path: string;
  upstream_title: string | null;
  upstream_description: string | null;
  upstream_severity: string | null;
  upstream_query: string;
  upstream_raw_content: string;
  current_query: string;
  current_title: string;
  current_description: string | null;
  has_changes: boolean;
  /** Whether stored customizations (source_type mappings) were applied to upstream_query */
  customizations_applied?: boolean;
}

export interface CoverageAnalysis {
  total_rules: number;
  full_coverage: number;
  partial_coverage: number;
  no_coverage: number;
  coverage_by_severity: CoverageBySeverity;
  coverage_by_tactic: TacticCoverage[];
  most_missing_fields: MissingFieldCount[];
  suggested_source_types: string[];
}

export interface CoverageBySeverity {
  critical: CoverageCount;
  high: CoverageCount;
  medium: CoverageCount;
  low: CoverageCount;
  informational: CoverageCount;
}

export interface CoverageCount {
  total: number;
  full: number;
  partial: number;
  none: number;
}

export interface TacticCoverage {
  tactic: string;
  tactic_name: string;
  total: number;
  full: number;
  partial: number;
  none: number;
}

export interface MissingFieldCount {
  field: string;
  count: number;
  source_types_with_field: string[];
}

export interface CoverageFilter {
  repository_id?: string;
  severity?: string;
  mitre_tactic?: string;
  mitre_technique?: string;
}

export interface ConvertSigmaRequest {
  sigma_yaml: string;
}

export interface ConvertSigmaResponse {
  npl_query: string;
  confidence: number;
  field_mappings: FieldMapping[];
  unmapped_fields: string[];
  requires_fields: string[];
  warnings: string[];
  needs_review: boolean;
}

export interface FieldMapping {
  sigma_field: string;
  udm_field: string;
  confidence: number;
  notes: string | null;
}

// Batch operations

export interface BatchImportItem {
  path: string;
  severity?: string;
  mode?: string;
  source_type_mappings?: Record<string, string>;
  merge_to_single_source_type?: string;
}

export interface BatchImportResponse {
  imported: number;
  /** Existing imports re-imported against newer upstream content (NAN-673). */
  updated: number;
  skipped: number;
  failed: { path: string; error: string }[];
}

export interface BatchRemoveResponse {
  removed: number;
  failed: { detection_rule_id: string; error: string }[];
}

// =============================================================================
// API Client
// =============================================================================

export class RuleRepositoriesApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  // Repository CRUD

  async listRepositories(): Promise<{ repositories: RuleRepository[] }> {
    return this.request('/api/rule-repositories');
  }

  async getRepository(id: string): Promise<RuleRepository> {
    return this.request(`/api/rule-repositories/${id}`);
  }

  async createRepository(req: CreateRepositoryRequest): Promise<RuleRepository> {
    return this.request('/api/rule-repositories', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async updateRepository(id: string, req: UpdateRepositoryRequest): Promise<RuleRepository> {
    return this.request(`/api/rule-repositories/${id}`, {
      method: 'PUT',
      body: JSON.stringify(req),
    });
  }

  async deleteRepository(id: string): Promise<void> {
    return this.request(`/api/rule-repositories/${id}`, {
      method: 'DELETE',
    });
  }

  // Sync operations

  /** Start syncing a repository (async - returns immediately, sync runs in background) */
  async syncRepository(id: string): Promise<SyncStartResponse> {
    return this.request(`/api/rule-repositories/${id}/sync`, {
      method: 'POST',
    });
  }

  async getSyncStatus(id: string): Promise<SyncStatus> {
    return this.request(`/api/rule-repositories/${id}/sync/status`);
  }

  // Folder selection (before sync)

  async listFolders(repositoryId: string): Promise<{ folders: FolderInfo[] }> {
    return this.request(`/api/rule-repositories/${repositoryId}/folders`);
  }

  // Browse rules

  async listRules(repositoryId: string, filter?: RepositoryRuleFilter): Promise<RepositoryRule[]> {
    const params = new URLSearchParams();
    if (filter?.path_prefix) params.set('path_prefix', filter.path_prefix);
    if (filter?.severity) params.set('severity', filter.severity);
    if (filter?.conversion_status) params.set('conversion_status', filter.conversion_status);
    if (filter?.coverage_status) params.set('coverage_status', filter.coverage_status);
    if (filter?.search) params.set('search', filter.search);
    if (filter?.has_npl !== undefined) params.set('has_npl', String(filter.has_npl));
    if (filter?.limit) params.set('limit', String(filter.limit));
    if (filter?.offset) params.set('offset', String(filter.offset));

    const query = params.toString();
    return this.request(`/api/rule-repositories/${repositoryId}/rules${query ? `?${query}` : ''}`);
  }

  async getRule(repositoryId: string, path: string): Promise<RepositoryRule> {
    return this.request(`/api/rule-repositories/${repositoryId}/rules/by-path/${encodeURIComponent(path)}`);
  }

  // Import

  async previewImport(repositoryId: string, path: string): Promise<ImportPreview> {
    return this.request(`/api/rule-repositories/${repositoryId}/rules/preview/${encodeURIComponent(path)}`);
  }

  async importRule(repositoryId: string, path: string, req?: ImportRequest): Promise<ImportResult> {
    return this.request(`/api/rule-repositories/${repositoryId}/rules/import/${encodeURIComponent(path)}`, {
      method: 'POST',
      body: JSON.stringify(req ?? {}),
    });
  }

  // Batch operations

  async batchImport(repositoryId: string, items: BatchImportItem[]): Promise<BatchImportResponse> {
    return this.request(`/api/rule-repositories/${repositoryId}/rules/import-batch`, {
      method: 'POST',
      body: JSON.stringify({ items }),
    });
  }

  async removeAllImported(repositoryId: string): Promise<BatchRemoveResponse> {
    return this.request(`/api/rule-repositories/${repositoryId}/rules/remove-all-imported`, {
      method: 'POST',
    });
  }

  // Coverage

  async getCoverage(filter?: CoverageFilter): Promise<CoverageAnalysis> {
    const params = new URLSearchParams();
    if (filter?.repository_id) params.set('repository_id', filter.repository_id);
    if (filter?.severity) params.set('severity', filter.severity);
    if (filter?.mitre_tactic) params.set('mitre_tactic', filter.mitre_tactic);
    if (filter?.mitre_technique) params.set('mitre_technique', filter.mitre_technique);

    const query = params.toString();
    return this.request(`/api/rule-repositories/coverage${query ? `?${query}` : ''}`);
  }

  async refreshCoverage(): Promise<void> {
    return this.request('/api/rule-repositories/coverage/refresh', {
      method: 'POST',
    });
  }

  // Sigma conversion (standalone)

  async convertSigma(req: ConvertSigmaRequest): Promise<ConvertSigmaResponse> {
    return this.request('/api/sigma/convert', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  // Upstream change tracking

  async getUpstreamUpdates(repositoryId: string): Promise<UpstreamUpdatesResponse> {
    return this.request(`/api/rule-repositories/${repositoryId}/upstream-updates`);
  }

  async getUpstreamDiff(detectionRuleId: string): Promise<UpstreamDiff> {
    return this.request(`/api/detection-rules/${detectionRuleId}/upstream-diff`);
  }

  async dismissUpstreamChanges(detectionRuleId: string): Promise<void> {
    return this.request(`/api/detection-rules/${detectionRuleId}/upstream-diff/dismiss`, {
      method: 'POST',
    });
  }
}
