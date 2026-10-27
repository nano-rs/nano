// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * OCSF bucket drop sources (open core / dedicated, NAN-3807): read-only status.
 * Sources are created by the `lean-landing-admin` CLI, never through the API.
 */

export type LandingFileState = 'listed' | 'claimed' | 'accepted' | 'refused';

export interface LandingSourceStatus {
  /** Log source id; also the `source=<id>` folder senders write under. */
  source_id: string;
  name: string;
  route_key: string;
  credential_id: string;
  state: 'active' | 'revoked';
  created_at: string;
  revoked_at?: string | null;
  files_accepted: number;
  files_refused: number;
  files_in_progress: number;
  rows_accepted: number;
  rows_refused: number;
  redeliveries: number;
  last_seen_at?: string | null;
  last_finished_at?: string | null;
  /** Value-free reason code of the newest refused file. */
  last_refusal_reason?: string | null;
  last_refusal_at?: string | null;
}

export interface LandingFile {
  id: number;
  object_key: string;
  etag: string;
  source_id?: string | null;
  size_bytes: number;
  state: LandingFileState;
  rows_accepted: number;
  rows_refused: number;
  reason?: string | null;
  content_sha256?: string | null;
  bronze_key?: string | null;
  attempts: number;
  redeliveries: number;
  lease_until?: string | null;
  first_seen_at: string;
  finished_at?: string | null;
}

export interface LandingSourceList {
  sources: LandingSourceStatus[];
}

export interface LandingFileList {
  files: LandingFile[];
}

export const LANDING_SOURCES_QUERY_KEY = ['landing-sources'] as const;

export class LandingSourcesApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}

  list(): Promise<LandingSourceList> {
    return this.request<LandingSourceList>('/api/landing-sources');
  }

  files(sourceId: string, options: { limit?: number; state?: LandingFileState } = {}): Promise<LandingFileList> {
    const params = new URLSearchParams();
    if (options.limit !== undefined) params.set('limit', String(options.limit));
    if (options.state) params.set('state', options.state);
    const qs = params.toString();
    return this.request<LandingFileList>(
      `/api/landing-sources/${encodeURIComponent(sourceId)}/files${qs ? `?${qs}` : ''}`,
    );
  }
}
