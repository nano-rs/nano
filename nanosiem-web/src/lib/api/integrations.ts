// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Integration collectors API client (NAN-2189).
 *
 * A collector-category marketplace entry is the *integration*; an instance is
 * one configured connection to a vendor tenant. The catalog itself is served by
 * the marketplace API — this client only manages instances.
 */

// =============================================================================
// Types
// =============================================================================

/** One independently toggleable feed declared by a collector's manifest. */
export interface StreamStatus {
  stream_id: string;
  label?: string;
  /** Routes this stream's events to a parser. */
  source_type?: string;
  enabled: boolean;
  /** False on an enabled stream means it has never successfully run. */
  has_cursor: boolean;
  last_success_at?: string;
  last_error?: string;
  events_fetched: number;
  /**
   * Seconds since this stream last delivered. The number that matters for
   * iterator-style APIs: vendors drop undelivered events after a retention
   * window, so a stalled stream is data loss rather than a backlog.
   */
  staleness_secs?: number;
}

/**
 * What happened when an enabled stream was given a log source (NAN-2192).
 *
 * Only present on create/update responses. Anything other than `linked` means
 * that stream is collecting into nothing the operator can see — which is the
 * whole reason this is surfaced rather than logged.
 */
export type StreamProvisionReport = {
  stream_id: string;
  source_type: string;
} & (
  | { status: 'linked'; log_source_id: string; created: boolean }
  // `declared_parser` is present when the collector manifest named the parser
  // it needs (NAN-2248) and no synced repository provides it. The remedy is to
  // sync that repository — not to look for a parser claiming `source_type`,
  // which by design nothing may claim.
  | { status: 'no_parser'; source_type: string; declared_parser?: string }
  | { status: 'not_permitted'; missing: string }
  | { status: 'failed'; error: string }
);

export interface IntegrationInstance {
  id: string;
  catalog_id: string;
  name: string;
  enabled: boolean;
  config: Record<string, unknown>;
  /** Credentials are never returned — only whether they are set. */
  has_credentials: boolean;
  enabled_streams: string[];
  schedule?: string;
  backfill_from?: string;
  last_run_at?: string;
  last_run_status?: 'success' | 'partial' | 'failed' | 'running' | 'cancelled';
  last_run_duration_ms?: number;
  last_error?: string;
  events_fetched: number;
  /** True while a run holds this instance's lease. */
  running: boolean;
  streams: StreamStatus[];
  /** Populated on create/update only; the read paths do not re-provision. */
  provisioning?: StreamProvisionReport[];
}

export interface CreateInstanceRequest {
  slug: string;
  name: string;
  config?: Record<string, unknown>;
  credentials?: Record<string, string>;
  /** Omit to take the manifest's `default: true` streams. */
  enabled_streams?: string[];
  schedule?: string;
  backfill_from?: string;
  enabled?: boolean;
}

export interface UpdateInstanceRequest {
  name?: string;
  enabled?: boolean;
  config?: Record<string, unknown>;
  /** Omit to keep the stored secret — the API never returns it to send back. */
  credentials?: Record<string, string>;
  enabled_streams?: string[];
  /** `null` clears the override and falls back to the manifest schedule. */
  schedule?: string | null;
  backfill_from?: string | null;
}

export interface ListInstancesResponse {
  instances: IntegrationInstance[];
}

export interface TriggerRunResponse {
  triggered: boolean;
  message: string;
}

/** Collector-specific manifest fields, carried inside a catalog entry's config. */
export interface CollectorStreamDef {
  id: string;
  label: string;
  source_type: string;
  default?: boolean;
  description?: string;
}

export interface CollectorConfigFieldDef {
  name: string;
  label: string;
  field_type: string;
  required: boolean;
  help?: string;
  placeholder?: string;
}

/**
 * Read the collector fields out of a catalog entry's `config`.
 *
 * Repo sync flattens them into that blob rather than adding catalog columns,
 * so every consumer has to unpack them the same way.
 */
export function collectorManifest(config: Record<string, unknown> | undefined): {
  streams: CollectorStreamDef[];
  configFields: CollectorConfigFieldDef[];
  pollSchedule?: string;
} {
  const cfg = config ?? {};
  return {
    streams: Array.isArray(cfg.streams) ? (cfg.streams as CollectorStreamDef[]) : [],
    configFields: Array.isArray(cfg.config_fields)
      ? (cfg.config_fields as CollectorConfigFieldDef[])
      : [],
    pollSchedule: typeof cfg.poll_schedule === 'string' ? cfg.poll_schedule : undefined,
  };
}

// =============================================================================
// Client
// =============================================================================

export class IntegrationsApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
  ) {}

  async listInstances(slug?: string): Promise<ListInstancesResponse> {
    const qs = slug ? `?slug=${encodeURIComponent(slug)}` : '';
    return this.request<ListInstancesResponse>(`/api/integrations/instances${qs}`);
  }

  async getInstance(id: string): Promise<IntegrationInstance> {
    return this.request<IntegrationInstance>(
      `/api/integrations/instances/${encodeURIComponent(id)}`,
    );
  }

  async createInstance(request: CreateInstanceRequest): Promise<IntegrationInstance> {
    return this.request<IntegrationInstance>('/api/integrations/instances', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
  }

  async updateInstance(
    id: string,
    request: UpdateInstanceRequest,
  ): Promise<IntegrationInstance> {
    return this.request<IntegrationInstance>(
      `/api/integrations/instances/${encodeURIComponent(id)}`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      },
    );
  }

  async deleteInstance(id: string): Promise<void> {
    return this.request<void>(`/api/integrations/instances/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  /**
   * Queue a run. Deliberately not synchronous: a collector run is long-lived
   * and must go through the scheduler's single-flight lease, or two consumers
   * end up on the same cursor.
   */
  async triggerRun(id: string): Promise<TriggerRunResponse> {
    return this.request<TriggerRunResponse>(
      `/api/integrations/instances/${encodeURIComponent(id)}/run`,
      { method: 'POST' },
    );
  }
}
