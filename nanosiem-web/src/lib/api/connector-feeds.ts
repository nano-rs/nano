// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Connector pull feeds (NAN-4914): bundled connector specs run on a schedule
 * by the nano-connector-runner service, delivering into the local Vector.
 */

import { DEPLOY_REQUEST_TIMEOUT_MS, type LongRequest } from './log-sources';

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
  /** NAN-5903: plain-English label, help and known values per config key. */
  config_field_info?: ConnectorFieldInfo[];
  /** NAN-5903: plain-English label and help per credential field. */
  credential_field_info?: ConnectorFieldInfo[];
  /** NAN-5903: catalog parsers a missing lane's log source is set up from. */
  parsers?: string[];
}

/** How a form shows one config or credential key (NAN-5903). */
export interface ConnectorFieldInfo {
  key: string;
  label: string;
  /** Tooltip text. */
  help: string;
  placeholder: string | null;
  /** Known values of a comma-separated list field (a multi-select). */
  choices: ConnectorFieldChoice[];
}

export interface ConnectorFieldChoice {
  value: string;
  label: string;
  /** Ticked on a new feed. */
  default: boolean;
}

export type LaneSourceAction = 'reuse' | 'create' | 'extend' | 'turn_on';

/** One log source a feed's lanes use, and what setup does to it. */
export interface LaneSourceStep {
  action: LaneSourceAction;
  log_source_id: string | null;
  log_source_name: string;
  lanes: string[];
  added_lanes: string[];
  parser: string | null;
  /** For a source setup creates or changes: a catalog import, or a connector-owned pull source. */
  origin?: 'catalog_import' | 'pull_source' | null;
}

/** `POST /api/connector-feeds/plan`: what a create would set up. */
export interface ConnectorFeedSetupPlan {
  lanes: string[];
  log_sources: LaneSourceStep[];
  creates: number;
  changes_log_sources: boolean;
  required_permissions: string[];
  missing_permissions: string[];
}

export interface ConnectorFeedCreated {
  id: string;
  credential_id: string | null;
  log_sources?: LaneSourceStep[];
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
  /** NAN-5903: set up the log sources of lanes that have none first. */
  set_up_log_sources?: boolean;
}

export class ConnectorFeedsApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
    /** NAN-5903: a start that sets up log sources deploys them first, which
     * outlasts the default 60 s client timeout (the edges allow 300 s). */
    private longRequest?: LongRequest,
  ) {}

  /** A start with consent to set up log sources runs under the deploy budget. */
  private startRequest<T>(endpoint: string, options: RequestInit, setsUp: boolean): Promise<T> {
    return setsUp && this.longRequest
      ? this.longRequest<T>(endpoint, options, DEPLOY_REQUEST_TIMEOUT_MS)
      : this.request<T>(endpoint, options);
  }

  listSpecs(): Promise<ConnectorSpecInfo[]> {
    return this.request('/api/connector-specs');
  }

  list(): Promise<ConnectorFeed[]> {
    return this.request('/api/connector-feeds');
  }

  get(id: string): Promise<ConnectorFeedDetail> {
    return this.request(`/api/connector-feeds/${encodeURIComponent(id)}`);
  }

  create(request: CreateConnectorFeedRequest): Promise<ConnectorFeedCreated> {
    return this.startRequest(
      '/api/connector-feeds',
      { method: 'POST', body: JSON.stringify(request) },
      !!request.set_up_log_sources,
    );
  }

  /** What a create with this config would do to the lanes' log sources. */
  plan(connector: string, config: CreateConnectorFeedRequest['config']): Promise<ConnectorFeedSetupPlan> {
    return this.request('/api/connector-feeds/plan', { method: 'POST', body: JSON.stringify({ connector, config }) });
  }

  /** `setUpLogSources` (NAN-5903): on resume, set up lanes that lost their log source. */
  setEnabled(id: string, enabled: boolean, setUpLogSources = false): Promise<ConnectorFeed> {
    return this.startRequest(
      `/api/connector-feeds/${encodeURIComponent(id)}`,
      { method: 'PATCH', body: JSON.stringify(setUpLogSources ? { enabled, set_up_log_sources: true } : { enabled }) },
      setUpLogSources,
    );
  }

  remove(id: string): Promise<void> {
    return this.request(`/api/connector-feeds/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  /** Adopt this build's bundled spec for the feed (resets its checkpoints). */
  adoptSpec(id: string, setUpLogSources = false): Promise<{ adopted: boolean; checkpoints_reset: number }> {
    return this.startRequest(
      `/api/connector-feeds/${encodeURIComponent(id)}/adopt-spec`,
      { method: 'POST', ...(setUpLogSources ? { body: JSON.stringify({ set_up_log_sources: true }) } : {}) },
      setUpLogSources,
    );
  }

  resetStream(id: string, stream: string): Promise<{ stream: string; anchor: string; next_run_at: string }> {
    return this.request(`/api/connector-feeds/${encodeURIComponent(id)}/reset`, {
      method: 'POST',
      body: JSON.stringify({ stream }),
    });
  }
}
