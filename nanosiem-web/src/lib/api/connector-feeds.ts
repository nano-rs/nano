// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Connector pull feeds (NAN-4914): bundled connector specs run on a schedule
 * by the nano-connector-runner service, delivering into the local Vector.
 */

/** `collector`: events into a parser lane. `identity` (G22): users and group
 * memberships into the user directory (`user_registry`); no lane. */
export type ConnectorKind = 'collector' | 'identity';

export interface ConnectorSpecInfo {
  name: string;
  display_name: string;
  kind: ConnectorKind;
  credential_provider: string;
  source_type: string;
  schedule: string | null;
  config_fields: string[];
  optional_config_fields: string[];
  credential_fields: string[];
}

export interface ConnectorFeed {
  id: string;
  name: string;
  connector: string;
  kind: ConnectorKind;
  source_type: string;
  enabled: boolean;
  running: boolean;
  schedule: string | null;
  effective_schedule: string;
  config: Record<string, unknown>;
  credential_id: string | null;
  max_run_secs: number | null;
  next_run_at: string;
  consecutive_failures: number;
  last_run_at: string | null;
  last_status: string | null;
  last_error: string | null;
  last_success_at: string | null;
  created_at: string;
  /** This build bundles a newer spec; adopt it explicitly (resets cursors). */
  spec_update_available?: boolean;
}

export interface ConnectorFeedRun {
  id: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  events: number;
  pages: number;
  error: string | null;
}

export interface ConnectorFeedCheckpoint {
  stream_id: string;
  kind: string;
  commits: number;
  updated_at: string;
}

export interface ConnectorFeedDetail {
  feed: ConnectorFeed;
  runs: ConnectorFeedRun[];
  checkpoints: ConnectorFeedCheckpoint[];
}

export interface CreateConnectorFeedRequest {
  name: string;
  connector: string;
  /** Text config values; engine flags such as `identity_allow_shrink` are booleans. */
  config: Record<string, string | boolean>;
  /** Bind an existing credential (`cred_...`). */
  credential_id?: string;
  /** Or enter a new credential (stored in the credentials store). */
  credentials?: Record<string, string>;
  schedule?: string;
  max_run_secs?: number;
}

export class ConnectorFeedsApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}

  listSpecs(): Promise<ConnectorSpecInfo[]> {
    return this.request('/api/connector-specs');
  }

  list(): Promise<ConnectorFeed[]> {
    return this.request('/api/connector-feeds');
  }

  get(id: string): Promise<ConnectorFeedDetail> {
    return this.request(`/api/connector-feeds/${encodeURIComponent(id)}`);
  }

  create(request: CreateConnectorFeedRequest): Promise<{ id: string; credential_id: string | null }> {
    return this.request('/api/connector-feeds', { method: 'POST', body: JSON.stringify(request) });
  }

  setEnabled(id: string, enabled: boolean): Promise<ConnectorFeed> {
    return this.request(`/api/connector-feeds/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    });
  }

  remove(id: string): Promise<void> {
    return this.request(`/api/connector-feeds/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  /** Adopt this build's bundled spec for the feed (resets its checkpoints). */
  adoptSpec(id: string): Promise<{ adopted: boolean; checkpoints_reset: number }> {
    return this.request(`/api/connector-feeds/${encodeURIComponent(id)}/adopt-spec`, { method: 'POST' });
  }

  resetStream(id: string, stream: string): Promise<{ stream: string; anchor: string; next_run_at: string }> {
    return this.request(`/api/connector-feeds/${encodeURIComponent(id)}/reset`, {
      method: 'POST',
      body: JSON.stringify({ stream }),
    });
  }
}
