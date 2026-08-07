// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Integration collectors API client (NAN-2189).
 *
 * A collector-category marketplace entry is the *integration*; an instance is
 * one configured connection to a vendor tenant. The catalog itself is served by
 * the marketplace API — this client only manages instances.
*/

import type { CredentialFieldDef } from './marketplace';

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
 * Only present on create/update responses. Anything `streamNeedsAttention`
 * flags means that stream is collecting into nothing the operator can see —
 * which is the whole reason this is surfaced rather than logged.
 */
export type StreamProvisionReport = {
  stream_id: string;
  source_type: string;
} & (
  | {
      status: 'linked';
      log_source_id: string;
      created: boolean;
      /**
       * Whether the log source is actually DEPLOYED to Vector (NAN-2202).
       *
       * `false` means the stream collects into nothing: the collector runs,
       * authenticates, fetches events and POSTs them successfully, and they hit
       * no route, because Vector never learned to handle this `source_type`.
       * Zero data AND zero errors on every surface.
       *
       * Optional on the wire: a response from a pre-NAN-2202 API omits it, and
       * `streamNeedsAttention` treats absent as not-deployed. That direction is
       * deliberate — it surfaces the ambiguity rather than rendering an unknown
       * state as healthy, which is the bug this field exists to end.
       */
      deployed?: boolean;
    }
  // `declared_parser` is present when the collector manifest named the parser
  // it needs (NAN-2248) and no synced repository provides it. The remedy is to
  // sync that repository — not to look for a parser claiming `source_type`,
  // which by design nothing may claim.
  | { status: 'no_parser'; source_type: string; declared_parser?: string }
  | { status: 'not_permitted'; missing: string }
  // NAN-2202: creating this stream's log source would exceed the data-source
  // tier cap. Not a malfunction — the operator's next step is a plan change.
  | { status: 'limit_exceeded'; message: string }
  | { status: 'failed'; error: string }
);

/**
 * Whether a provisioning outcome is worth putting in front of an operator.
 *
 * The TypeScript half of `StreamProvisionReport::needs_attention()` in
 * `nanosiem-enterprise/src/integrations/provisioning.rs` — keep the two in step.
 *
 * NAN-2202: `linked` alone is NOT success. A linked-but-undeployed stream looks
 * healthy on every surface and collects into nothing, so it has to count here;
 * treating any `linked` as fine is precisely how a dead feed stayed invisible.
 */
export function streamNeedsAttention(report: StreamProvisionReport): boolean {
  return report.status !== 'linked' || report.deployed !== true;
}

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
  parser?: string;
  default?: boolean;
  description?: string;
}

export interface CollectorManifestAuth {
  header_name?: string;
  credential_field?: string;
  username_field?: string;
  password_field?: string;
  token_url?: string;
  client_id_field?: string;
  client_secret_field?: string;
  scope?: string;
}

export type CollectorAuthType =
  | 'none'
  | 'bearer'
  | 'api_key_header'
  | 'basic_auth'
  | 'oauth2_client_credentials';

export interface CustomCollectorDefinitionRequest {
  name: string;
  description?: string;
  code: string;
  allowed_domains: string[];
  allowed_domain_suffixes: string[];
  credential_fields: CredentialFieldDef[];
  config_fields: CollectorConfigFieldDef[];
  auth_type: CollectorAuthType;
  auth?: CollectorManifestAuth;
  streams: CollectorStreamDef[];
  poll_schedule: string;
}

export interface CustomCollectorDefinition extends CustomCollectorDefinitionRequest {
  id: string;
  slug: string;
  max_run_secs: number;
  max_events_per_emit: number;
  max_events_per_run: number;
  max_bytes_per_run: number;
  created_at: string;
  updated_at: string;
}

export interface CustomCollectorValidationResponse {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export interface CustomCollectorPreviewRequest {
  definition: CustomCollectorDefinitionRequest;
  config: Record<string, unknown>;
  credentials: Record<string, string>;
  enabled_streams: string[];
}

export interface CustomCollectorPreviewEvent {
  stream: string;
  source_type: string;
  event: unknown;
}

export interface CustomCollectorPreviewResponse {
  status: 'success' | 'partial' | 'failed' | 'cancelled';
  events: CustomCollectorPreviewEvent[];
  events_emitted: number;
  bytes_emitted: number;
  checkpoints: number;
  duration_ms: number;
  budget_exhausted: boolean;
  error?: string;
}

export interface GenerateCustomCollectorCodeRequest {
  definition_name: string;
  /** Natural-language instructions for the code builder, not the catalog description. */
  description: string;
  curl_example?: string;
  api_docs?: string;
  sample_response?: string;
  allowed_domains: string[];
  allowed_domain_suffixes: string[];
  credential_fields: CredentialFieldDef[];
  config_fields: CollectorConfigFieldDef[];
  auth_type: CollectorAuthType;
  auth?: CollectorManifestAuth;
  streams: CollectorStreamDef[];
  poll_schedule: string;
}

export interface GenerateCustomCollectorCodeResponse {
  /** Candidate code; the wizard does not apply it until the operator confirms. */
  code: string;
  explanation: string;
  warnings: string[];
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
  maxRunSecs?: number;
  maxEventsPerRun?: number;
  maxBytesPerRun?: number;
} {
  const cfg = config ?? {};
  return {
    streams: Array.isArray(cfg.streams) ? (cfg.streams as CollectorStreamDef[]) : [],
    configFields: Array.isArray(cfg.config_fields)
      ? (cfg.config_fields as CollectorConfigFieldDef[])
      : [],
    pollSchedule: typeof cfg.poll_schedule === 'string' ? cfg.poll_schedule : undefined,
    maxRunSecs: typeof cfg.max_run_secs === 'number' ? cfg.max_run_secs : undefined,
    maxEventsPerRun:
      typeof cfg.max_events_per_run === 'number' ? cfg.max_events_per_run : undefined,
    maxBytesPerRun:
      typeof cfg.max_bytes_per_run === 'number' ? cfg.max_bytes_per_run : undefined,
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

  async validateCustomCollector(
    request: CustomCollectorDefinitionRequest,
  ): Promise<CustomCollectorValidationResponse> {
    return this.request<CustomCollectorValidationResponse>(
      '/api/integrations/custom/validate',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      },
    );
  }

  async generateCustomCollectorCode(
    request: GenerateCustomCollectorCodeRequest,
  ): Promise<GenerateCustomCollectorCodeResponse> {
    return this.request<GenerateCustomCollectorCodeResponse>(
      '/api/integrations/custom/generate-code',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      },
    );
  }

  async previewCustomCollector(
    request: CustomCollectorPreviewRequest,
  ): Promise<CustomCollectorPreviewResponse> {
    return this.request<CustomCollectorPreviewResponse>(
      '/api/integrations/custom/preview',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      },
    );
  }

  async createCustomCollector(
    request: CustomCollectorDefinitionRequest,
  ): Promise<CustomCollectorDefinition> {
    return this.request<CustomCollectorDefinition>('/api/integrations/custom', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
  }

  async getCustomCollector(id: string): Promise<CustomCollectorDefinition> {
    return this.request<CustomCollectorDefinition>(
      `/api/integrations/custom/${encodeURIComponent(id)}`,
    );
  }

  async updateCustomCollector(
    id: string,
    request: CustomCollectorDefinitionRequest,
  ): Promise<CustomCollectorDefinition> {
    return this.request<CustomCollectorDefinition>(
      `/api/integrations/custom/${encodeURIComponent(id)}`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      },
    );
  }

  async deleteCustomCollector(id: string): Promise<void> {
    return this.request<void>(`/api/integrations/custom/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
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
