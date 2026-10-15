// SPDX-License-Identifier: AGPL-3.0-or-later
/** `identity` feeds sync a directory into the identity directory: no ingest token, no parser. */
export type ConnectorKind = 'collector' | 'identity';
export interface ConnectorSpec {
  name: string;
  kind: ConnectorKind;
  source_slug: string;
  config_fields: string[];
  credential_fields: string[];
}
export interface ConnectorFeed {
  id: string;
  name: string;
  connector: string;
  kind: ConnectorKind;
  enabled: boolean;
  last_status: string | null;
  last_error: string | null;
  last_success_at: string | null;
}
export interface CreateConnectorFeed {
  name: string;
  connector: string;
  config: Record<string, string>;
  vendor_credentials: Record<string, string>;
  /** Collector feeds only; omitted for identity feeds. */
  ingest_token?: string;
}
export class ConnectorFeedsApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}
  specs(): Promise<ConnectorSpec[]> { return this.request('/api/connector-specs'); }
  list(): Promise<ConnectorFeed[]> { return this.request('/api/connector-feeds'); }
  create(input: CreateConnectorFeed): Promise<{ id: string }> {
    return this.request('/api/connector-feeds', { method: 'POST', body: JSON.stringify(input) });
  }
  setEnabled(id: string, enabled: boolean): Promise<{ ok: boolean }> {
    return this.request(`/api/connector-feeds/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify({ enabled }) });
  }
  delete(id: string): Promise<{ ok: boolean }> {
    return this.request(`/api/connector-feeds/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }
}
