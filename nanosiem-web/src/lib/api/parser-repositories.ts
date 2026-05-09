// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Parser Repository API routes
 * Handles external parser repository sync, parser browsing, and imports
 */

// =============================================================================
// Types
// =============================================================================

export interface ParserRepository {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  url: string;
  branch: string;
  parsers_path: string | null;
  auto_sync_enabled: boolean;
  sync_interval_hours: number;
  last_synced_at: string | null;
  last_sync_commit: string | null;
  last_sync_status: 'success' | 'failed' | 'syncing' | null;
  last_sync_error: string | null;
  parser_count: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  created_by: string | null;
}

export interface CreateParserRepositoryRequest {
  name: string;
  url: string;
  description?: string;
  branch?: string;
  parsers_path?: string;
  auto_sync_enabled?: boolean;
  sync_interval_hours?: number;
}

export interface UpdateParserRepositoryRequest {
  name?: string;
  description?: string;
  branch?: string;
  parsers_path?: string;
  auto_sync_enabled?: boolean;
  sync_interval_hours?: number;
  enabled?: boolean;
}

export interface RepositoryParser {
  id: string;
  repository_id: string;
  file_path: string;
  file_sha: string | null;
  raw_content: string;
  name: string | null;
  display_name: string | null;
  description: string | null;
  version: string | null;
  category: string | null;
  vendor: string | null;
  product: string | null;
  parser_vrl: string | null;
  // Import status (from API enrichment)
  is_imported?: boolean;
  linked_log_source_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface RepositoryParserFilter {
  category?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface ParserSyncStartResponse {
  repository_id: string;
  status: string;
  message: string;
}

export interface ParserSyncStatus {
  status: string | null;
  last_synced_at: string | null;
  last_sync_commit: string | null;
  last_sync_error: string | null;
  parser_count: number;
}

export interface ParserImportRequest {
  import_type?: 'linked' | 'forked';
  /** The match value that activates this parser via routing rules (e.g., "apache") */
  source_type?: string;
  /** Ingestion method: routed, kafka, aws_s3, gcp_pubsub, splunk_hec, vector */
  ingestion_method?: string;
}

export interface ParserImportPreview {
  repository_parser: RepositoryParser;
  proposed_name: string;
  proposed_description: string | null;
  proposed_category: string | null;
  proposed_vendor: string | null;
  proposed_product: string | null;
  already_imported: boolean;
  existing_import_type: string | null;
  existing_log_source_id: string | null;
}

export interface ParserImportResult {
  log_source_id: string;
  import_type: string;
}

export interface BatchImportParserItem {
  path: string;
  import_type?: 'linked' | 'forked';
  source_type?: string;
  ingestion_method?: string;
}

export interface ParserBatchImportResponse {
  imported: number;
  skipped: number;
  failed: { path: string; error: string }[];
}

export interface ParserBatchRemoveResponse {
  removed: number;
  failed: number;
}

// Upstream change tracking

export interface ParserImport {
  id: string;
  repository_parser_id: string;
  log_source_id: string;
  import_type: string;
  imported_at: string;
  imported_by: string | null;
  imported_commit: string | null;
  last_sync_commit: string | null;
  upstream_changed: boolean;
}

export interface ParserUpstreamUpdate {
  log_source_id: string;
  repository_parser_id: string;
  file_path: string;
  display_name: string | null;
  version: string | null;
  import_type: string;
}

export interface ApplyUpstreamUpdateResult {
  log_source_id: string;
  updated: boolean;
  needs_deploy: boolean;
  message: string;
}

export interface BulkApplyUpstreamResult {
  updated: number;
  failed: number;
  results: ApplyUpstreamUpdateResult[];
}

export interface UpstreamParserDiff {
  log_source_id: string;
  repository_parser_id: string;
  file_path: string;
  upstream_display_name: string | null;
  upstream_description: string | null;
  upstream_version: string | null;
  upstream_vrl: string;
  current_vrl: string;
  has_changes: boolean;
}

// =============================================================================
// API Client
// =============================================================================

export class ParserRepositoriesApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  // Repository CRUD

  async listRepositories(): Promise<{ repositories: ParserRepository[] }> {
    return this.request('/api/parser-repositories');
  }

  async getRepository(id: string): Promise<ParserRepository> {
    return this.request(`/api/parser-repositories/${id}`);
  }

  async createRepository(req: CreateParserRepositoryRequest): Promise<ParserRepository> {
    return this.request('/api/parser-repositories', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async updateRepository(id: string, req: UpdateParserRepositoryRequest): Promise<ParserRepository> {
    return this.request(`/api/parser-repositories/${id}`, {
      method: 'PUT',
      body: JSON.stringify(req),
    });
  }

  async deleteRepository(id: string): Promise<void> {
    return this.request(`/api/parser-repositories/${id}`, {
      method: 'DELETE',
    });
  }

  // Sync operations

  /** Start syncing a repository (async - returns immediately, sync runs in background) */
  async syncRepository(id: string): Promise<ParserSyncStartResponse> {
    return this.request(`/api/parser-repositories/${id}/sync`, {
      method: 'POST',
    });
  }

  async getSyncStatus(id: string): Promise<ParserSyncStatus> {
    return this.request(`/api/parser-repositories/${id}/sync/status`);
  }

  // Browse parsers

  async listParsers(repositoryId: string, filter?: RepositoryParserFilter): Promise<RepositoryParser[]> {
    const params = new URLSearchParams();
    if (filter?.category) params.set('category', filter.category);
    if (filter?.search) params.set('search', filter.search);
    if (filter?.limit) params.set('limit', String(filter.limit));
    if (filter?.offset) params.set('offset', String(filter.offset));

    const query = params.toString();
    return this.request(`/api/parser-repositories/${repositoryId}/parsers${query ? `?${query}` : ''}`);
  }

  async getParser(repositoryId: string, path: string): Promise<RepositoryParser> {
    return this.request(`/api/parser-repositories/${repositoryId}/parsers/by-path/${encodeURIComponent(path)}`);
  }

  // Import

  async previewImport(repositoryId: string, path: string): Promise<ParserImportPreview> {
    return this.request(`/api/parser-repositories/${repositoryId}/parsers/preview/${encodeURIComponent(path)}`);
  }

  async importParser(repositoryId: string, path: string, req?: ParserImportRequest): Promise<ParserImportResult> {
    return this.request(`/api/parser-repositories/${repositoryId}/parsers/import/${encodeURIComponent(path)}`, {
      method: 'POST',
      body: JSON.stringify(req ?? {}),
    });
  }

  // Batch operations

  async batchImport(repositoryId: string, items: BatchImportParserItem[]): Promise<ParserBatchImportResponse> {
    return this.request(`/api/parser-repositories/${repositoryId}/parsers/import-batch`, {
      method: 'POST',
      body: JSON.stringify({ items }),
    });
  }

  async removeAllImported(repositoryId: string): Promise<ParserBatchRemoveResponse> {
    return this.request(`/api/parser-repositories/${repositoryId}/parsers/remove-all-imported`, {
      method: 'POST',
    });
  }

  // Upstream change tracking

  async getUpstreamUpdates(repositoryId: string): Promise<{ updates: ParserUpstreamUpdate[] }> {
    return this.request(`/api/parser-repositories/${repositoryId}/upstream-updates`);
  }

  async getUpstreamDiff(logSourceId: string): Promise<UpstreamParserDiff> {
    return this.request(`/api/log-sources/${logSourceId}/upstream-diff`);
  }

  async dismissUpstreamChanges(logSourceId: string): Promise<void> {
    return this.request(`/api/log-sources/${logSourceId}/upstream-diff/dismiss`, {
      method: 'POST',
    });
  }

  async applyUpstreamUpdate(logSourceId: string): Promise<ApplyUpstreamUpdateResult> {
    return this.request(`/api/log-sources/${logSourceId}/apply-upstream-update`, {
      method: 'POST',
    });
  }

  async applyAllUpstreamUpdates(repositoryId: string): Promise<BulkApplyUpstreamResult> {
    return this.request(`/api/parser-repositories/${repositoryId}/apply-all-upstream-updates`, {
      method: 'POST',
    });
  }
}
