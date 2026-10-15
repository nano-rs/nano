// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Named, revocable ingest tokens (dedicated / open core, NAN-3770). Each token
 * is bound to exactly one log source and decides it: every event sent with it
 * lands in that source whatever sourcetype it declares (NAN-3806). Hosted
 * tenants use `/api/log-sources/ingest-credentials` instead.
 */

/** A log source a token can be bound to (push-capable: HTTP, HEC, Vector). */
export interface BindableSource {
  source_id: string;
  name: string;
  source_type: string;
  /** The `source_type` every event of a bound token is routed on. */
  route_key: string;
  enabled: boolean;
}

export interface IngestToken {
  credential_id: string;
  name: string;
  /** `nit_` + 8 characters; the only part of the value ever shown again. */
  token_prefix: string;
  /** `unbound`: no source yet, so Vector refuses it until an admin binds it. */
  state: 'active' | 'unbound' | 'revoked';
  source_id?: string | null;
  source_name?: string | null;
  route_key?: string | null;
  source_bound_at?: string | null;
  /** Requests Vector accepted with this token (sampled, approximate). */
  request_count?: number;
  created_at: string;
  created_by?: string | null;
  last_used_at?: string | null;
  revoked_at?: string | null;
  revoked_by?: string | null;
  revocable: boolean;
}

export interface InstallTokenState {
  name: string;
  enabled: boolean;
  /** `active` = enabled and bound; `unbound` = enabled but refused until bound. */
  state: 'active' | 'unbound' | 'disabled' | 'not_configured';
  source_id?: string | null;
  source_name?: string | null;
  route_key?: string | null;
  source_bound_at?: string | null;
  updated_at?: string | null;
  updated_by?: string | null;
}

export interface IngestTokenList {
  tokens: IngestToken[];
  install_token: InstallTokenState;
  sources: BindableSource[];
}

export interface IssuedIngestToken {
  credential: IngestToken;
  /** The token value. Returned once, never stored or readable again. */
  token: string;
}

export const INGEST_TOKENS_QUERY_KEY = ['ingest-tokens'] as const;

export class IngestTokensApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}

  list(): Promise<IngestTokenList> {
    return this.request<IngestTokenList>('/api/ingest-tokens');
  }

  /** Issues a token bound to `sourceId` (required; a binding never changes). */
  create(name: string, sourceId: string): Promise<IssuedIngestToken> {
    return this.request<IssuedIngestToken>('/api/ingest-tokens', {
      method: 'POST',
      body: JSON.stringify({ name, source_id: sourceId }),
      cache: 'no-store',
    });
  }

  /** Binds an unbound token to a source. */
  bind(credentialId: string, sourceId: string): Promise<IngestToken> {
    return this.request<IngestToken>(`/api/ingest-tokens/${encodeURIComponent(credentialId)}/bind`, {
      method: 'POST',
      body: JSON.stringify({ source_id: sourceId }),
    });
  }

  revoke(credentialId: string): Promise<IngestToken> {
    return this.request<IngestToken>(`/api/ingest-tokens/${encodeURIComponent(credentialId)}/revoke`, {
      method: 'POST',
    });
  }

  setInstallTokenEnabled(enabled: boolean): Promise<InstallTokenState> {
    return this.request<InstallTokenState>('/api/ingest-tokens/install-token', {
      method: 'PUT',
      body: JSON.stringify({ enabled }),
    });
  }

  /** Binds the install token (`VECTOR_AUTH_TOKEN`) to a source, while it is unbound. */
  bindInstallToken(sourceId: string): Promise<InstallTokenState> {
    return this.request<InstallTokenState>('/api/ingest-tokens/install-token', {
      method: 'PUT',
      body: JSON.stringify({ source_id: sourceId }),
    });
  }
}
