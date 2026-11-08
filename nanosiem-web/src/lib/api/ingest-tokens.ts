// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Named, revocable per-source ingest tokens (NAN-4907, ported from NAN-3770 /
 * NAN-3806). Each token is bound to exactly one log source and decides it:
 * every event sent with it lands in that source whatever sourcetype it
 * declares. The install token (`VECTOR_AUTH_TOKEN`) is either strict (bound to
 * one source, or refused) or in the deprecated legacy multiplex mode (routed by
 * the sender's X-Source-Type, as before per-source tokens).
 */

/** A log source a token can be bound to (token-authenticated push lanes: HTTP, HEC, OTLP). */
export interface BindableSource {
  source_id: string;
  name: string;
  source_type: string;
  /** The `source_type` every event of a bound token is routed on. */
  route_key: string;
  enabled: boolean;
  /** Undeployed sources still receive events (unparsed, as `source_type=<route_key>`). */
  deployed?: boolean;
}

export interface IngestToken {
  credential_id: string;
  name: string;
  /** `nit_` + 8 characters; the only part of the value ever shown again. */
  token_prefix: string;
  /** `unbound`: no source (it was deleted), so Vector refuses it until an admin binds it. */
  state: 'active' | 'unbound' | 'revoked';
  source_id?: string | null;
  source_name?: string | null;
  route_key?: string | null;
  source_bound_at?: string | null;
  /** The token this one replaced, when it was issued by a rotation. */
  rotated_from?: string | null;
  /** Requests Vector accepted with this token (sampled, approximate). */
  request_count?: number;
  created_at: string;
  created_by?: string | null;
  last_used_at?: string | null;
  revoked_at?: string | null;
  revoked_by?: string | null;
  revocable: boolean;
}

export type InstallTokenMode = 'strict' | 'legacy_multiplex';

export interface InstallTokenState {
  name: string;
  enabled: boolean;
  mode: InstallTokenMode;
  /**
   * `legacy_multiplex` = accepted, routed by what the sender declares
   * (deprecated); `active` = strict and bound; `unbound` = strict, refused
   * until bound.
   */
  state: 'legacy_multiplex' | 'active' | 'unbound' | 'disabled' | 'not_configured';
  deprecated: boolean;
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
  /** How the tokens file reaches Vector. `none`: issuing is refused on this deployment. */
  delivery?: 'shared_volume' | 'http' | 'none';
}

export interface IssuedIngestToken {
  credential: IngestToken;
  /** The token value. Returned once, never stored or readable again. */
  token: string;
  /** On a rotation: the replaced token, now revoked. */
  replaced?: IngestToken | null;
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

  /** New value, same name and source; the old value is revoked. */
  rotate(credentialId: string): Promise<IssuedIngestToken> {
    return this.request<IssuedIngestToken>(`/api/ingest-tokens/${encodeURIComponent(credentialId)}/rotate`, {
      method: 'POST',
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

  /** Binds the install token to a source (leaves legacy multiplex mode). */
  bindInstallToken(sourceId: string): Promise<InstallTokenState> {
    return this.request<InstallTokenState>('/api/ingest-tokens/install-token', {
      method: 'PUT',
      body: JSON.stringify({ source_id: sourceId }),
    });
  }

  /** Leaves legacy multiplex mode without binding: the install token is refused. */
  setInstallTokenStrict(): Promise<InstallTokenState> {
    return this.request<InstallTokenState>('/api/ingest-tokens/install-token', {
      method: 'PUT',
      body: JSON.stringify({ mode: 'strict' }),
    });
  }
}
