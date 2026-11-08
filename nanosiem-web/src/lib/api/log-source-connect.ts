// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Connect-first onboarding (NAN-4912 phase 2, ported from main's NAN-4847 onto
 * the single-tenant APIs). A source is connected before it is parsed: a token
 * bound to a draft source lands events in `logs` as `source_type=<route key>`
 * through the router's catch-all, so "receiving, not parsed" is a real state.
 */

import type { IngestToken, InstallTokenMode } from './ingest-tokens';
import type { LogSource } from './types';

export type ConnectState =
  | 'disabled'
  | 'awaiting_data'
  | 'receiving_unparsed'
  | 'receiving'
  | 'no_recent_data';

export interface LogSourceConnectStatus {
  /** Log source TypeID (same as `LogSource.id`). */
  source_id: string;
  /** The `source_type` this source's events carry. */
  route_key: string;
  state: ConnectState;
  deployed: boolean;
  lifecycle_status: string;
  /** Whether a token can be bound (push transports: HTTP, HEC, OTLP). */
  push_capable: boolean;
  events_24h: number;
  first_seen?: string | null;
  last_seen?: string | null;
  active_tokens: number;
  token_last_used_at?: string | null;
}

export interface LogSourceConnectDetail extends LogSourceConnectStatus {
  /** Tokens bound to this source that are not revoked. */
  tokens: IngestToken[];
}

export interface UnassignedSource {
  route_key: string;
  events_24h: number;
  first_seen?: string | null;
  last_seen?: string | null;
  /** False when the key has characters a source key cannot carry (fix it at the sender). */
  convertible: boolean;
}

export interface UnassignedSourcesResponse {
  window_hours: number;
  sources: UnassignedSource[];
  /** Tokens whose source was deleted; Vector refuses them until bound. */
  unbound_tokens: IngestToken[];
  install_token_mode: InstallTokenMode;
}

export interface ConvertUnassignedRequest {
  route_key: string;
  name?: string;
  /** An unbound token to bind (same value; the sender keeps its config). */
  credential_id?: string;
  category?: string;
  vendor?: string;
  product?: string;
}

export interface ConvertUnassignedResponse {
  log_source: LogSource;
  bound_token?: IngestToken | null;
  /** Bound, but Vector's tokens file is retried in the background. */
  publication_pending: boolean;
}

export const CONNECT_STATUS_QUERY_KEY = ['log-sources', 'connect-status'] as const;
export const UNASSIGNED_SOURCES_QUERY_KEY = ['log-sources', 'unassigned'] as const;
export const connectDetailQueryKey = (id: string) => ['log-sources', 'connect-status', id] as const;

/** Human label for a connect state (UI copy, kept in one place). */
export const CONNECT_STATE_LABEL: Record<ConnectState, string> = {
  disabled: 'disabled',
  awaiting_data: 'awaiting data',
  receiving_unparsed: 'receiving · not parsed',
  receiving: 'receiving',
  no_recent_data: 'no data 24h',
};

export class LogSourceConnectApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}

  listStatus(): Promise<LogSourceConnectStatus[]> {
    return this.request<LogSourceConnectStatus[]>('/api/log-sources/connect-status');
  }

  getStatus(id: string): Promise<LogSourceConnectDetail> {
    return this.request<LogSourceConnectDetail>(`/api/log-sources/${encodeURIComponent(id)}/connect-status`);
  }

  listUnassigned(): Promise<UnassignedSourcesResponse> {
    return this.request<UnassignedSourcesResponse>('/api/log-sources/unassigned');
  }

  convert(request: ConvertUnassignedRequest): Promise<ConvertUnassignedResponse> {
    return this.request<ConvertUnassignedResponse>('/api/log-sources/unassigned/convert', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }
}
