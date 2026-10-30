// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  LogSource,
  NewLogSource,
  UpdateLogSource,
  LogSourceVrlValidationResult,
  LogSourceTestResult,
  LiveTestResult,
  LogSourceDeployment,
  LogSourceHealth,
  LogSourceVersion,
  LogSourceWithDraftStatus,
  IngestionHistoryPoint,
  LogSourceHealthSeries,
  EnhancedDeploymentResponse,
  NamespaceValidationResult,
  TenantIngestEndpoint,
  TenantIngestCredentialRequest,
  TenantIngestCredentialList,
  IngestCredentialRequestInput,
  IngestCredentialPrecheckInput,
  IngestCredentialPrecheck,
  IngestCredentialReveal,
  IngestCredentialRevocation,
  SenderTemplateCatalog,
  TenantSourceWriters,
  IngestCredentialActivity,
  IngestSourceActivity,
  TenantIngestObservation,
  TenantLogSourceStats,
  TenantParserRollout,
  TenantParserBaseOffer,
  TenantParserSamples,
  SharedDeploymentResponse,
  SharedRevertResponse,
} from './types';

/** Deploy/publish body: dedicated `ocsf_sample_logs`; hosted-shared `samples` (stored with the version for the build's `vector test`). */
function deployBody(ocsfSampleLogs?: string[], samples?: string[]): RequestInit {
  const body: Record<string, string[]> = {};
  if (ocsfSampleLogs) body.ocsf_sample_logs = ocsfSampleLogs;
  if (samples) body.samples = samples;
  return Object.keys(body).length ? { body: JSON.stringify(body) } : {};
}

export class LogSourcesApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async listLogSources(): Promise<LogSource[]> {
    return this.request('/api/log-sources');
  }

  async getLogSource(id: string): Promise<LogSource> {
    return this.request(`/api/log-sources/${id}`);
  }

  async createLogSource(request: NewLogSource): Promise<LogSource> {
    return this.request('/api/log-sources', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async updateLogSource(id: string, request: UpdateLogSource): Promise<LogSource> {
    return this.request(`/api/log-sources/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async deleteLogSource(id: string): Promise<{ deleted: boolean }> {
    return this.request(`/api/log-sources/${id}`, {
      method: 'DELETE',
    });
  }

  async toggleLogSource(id: string, enabled: boolean): Promise<LogSource> {
    return this.request(`/api/log-sources/${id}/toggle`, {
      method: 'POST',
      body: JSON.stringify({ enabled }),
    });
  }

  async validateLogSource(id: string): Promise<LogSourceVrlValidationResult> {
    return this.request(`/api/log-sources/${id}/validate`, {
      method: 'POST',
    });
  }

  async validateLogSourceVrl(vrlCode: string): Promise<LogSourceVrlValidationResult> {
    return this.request('/api/log-sources/validate-vrl', {
      method: 'POST',
      body: JSON.stringify({ vrl_code: vrlCode }),
    });
  }

  async testLogSourceVrl(
    vrlCode: string,
    sampleLog: string,
    extensionVrl?: string,
    validateOcsf: boolean = false,
    logSourceId?: string,
  ): Promise<LogSourceTestResult> {
    return this.request('/api/log-sources/test-vrl', {
      method: 'POST',
      body: JSON.stringify({
        vrl_code: vrlCode,
        sample_log: sampleLog,
        ...(extensionVrl && extensionVrl.trim() !== ''
          ? { extension_vrl: extensionVrl }
          : {}),
        validate_ocsf: validateOcsf,
        ...(logSourceId ? { log_source_id: logSourceId } : {}),
      }),
    });
  }

  async testLogSourceVrlLive(vrlCode: string, sourceType: string, currentVrl?: string, limit: number = 10): Promise<LiveTestResult[]> {
    return this.request('/api/log-sources/test-live', {
      method: 'POST',
      body: JSON.stringify({ vrl_code: vrlCode, source_type: sourceType, current_vrl: currentVrl, limit }),
    });
  }

  async deployLogSource(id: string, ocsfSampleLogs?: string[], samples?: string[]): Promise<SharedDeploymentResponse> {
    return this.request(`/api/log-sources/${id}/deploy`, {
      method: 'POST',
      ...deployBody(ocsfSampleLogs, samples),
    });
  }

  async undeployLogSource(id: string): Promise<EnhancedDeploymentResponse> {
    return this.request(`/api/log-sources/${id}/undeploy`, {
      method: 'POST',
    });
  }

  async deployAllLogSources(): Promise<{ deployed: boolean }> {
    return this.request('/api/log-sources/deploy-all', {
      method: 'POST',
    });
  }

  async getLogSourceDeployments(id: string): Promise<LogSourceDeployment[]> {
    return this.request(`/api/log-sources/${id}/deployments`);
  }

  async getLogSourceHealth(id: string): Promise<LogSourceHealth> {
    return this.request(`/api/log-sources/${id}/health`);
  }

  /**
   * NAN-2361 hosted-shared tenants: per-source hourly ingestion series from
   * the lake's per-source counters. Only under the hosted-shared profile.
   */
  async getLogSourceStats(id: string, hours?: number): Promise<TenantLogSourceStats> {
    const params = hours ? `?hours=${hours}` : '';
    return this.request(`/api/log-sources/${id}/stats${params}`);
  }

  async getIngestionHistory(hours?: number): Promise<IngestionHistoryPoint[]> {
    const params = hours ? `?hours=${hours}` : '';
    return this.request(`/api/log-sources/ingestion-history${params}`);
  }

  /** NAN-3207: health series (volume vs expected band + segments) for every visible source. `hours` is clamped 1..72 server-side. */
  async getHealthSeries(hours?: number): Promise<LogSourceHealthSeries[]> {
    const params = hours ? `?hours=${hours}` : '';
    return this.request(`/api/log-sources/health-series${params}`);
  }

  /** NAN-3207: health series for one source (exactly one element; 404 when not visible). */
  async getLogSourceHealthSeries(id: string, hours?: number): Promise<LogSourceHealthSeries[]> {
    const params = hours ? `?hours=${hours}` : '';
    return this.request(`/api/log-sources/${encodeURIComponent(id)}/health-series${params}`);
  }

  // NAN-2361 hosted-shared tenants: the tenant's own ingest endpoint, its
  // credential issuance requests and the lake-observed ingestion series.
  // These routes exist only under the hosted-shared profile.

  async getIngestEndpoint(): Promise<TenantIngestEndpoint> {
    return this.request('/api/log-sources/ingest-endpoint');
  }

  async listIngestCredentials(): Promise<TenantIngestCredentialList> {
    return this.request('/api/log-sources/ingest-credentials');
  }

  async requestIngestCredential(input: IngestCredentialRequestInput): Promise<TenantIngestCredentialRequest> {
    return this.request('/api/log-sources/ingest-credentials', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  /** The issuance guard's verdict for these sources, without issuing (NAN-2617). */
  async precheckIngestCredential(input: IngestCredentialPrecheckInput): Promise<IngestCredentialPrecheck> {
    return this.request('/api/log-sources/ingest-credentials/precheck', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  /** Poll a request's state; never returns a token. */
  async getIngestCredentialRequest(requestId: string): Promise<IngestCredentialReveal> {
    return this.request(`/api/log-sources/ingest-credentials/requests/${encodeURIComponent(requestId)}`, {
      cache: 'no-store',
    });
  }

  /** Reveal once (requester only): returns the sealed token; 410 afterwards. */
  async revealIngestCredential(requestId: string): Promise<IngestCredentialReveal> {
    return this.request(`/api/log-sources/ingest-credentials/requests/${encodeURIComponent(requestId)}/reveal`, {
      method: 'POST',
      cache: 'no-store',
    });
  }

  async assignIngestSource(credentialId: string, source_slug: string, label: string): Promise<{ credential_id: string; source_slug: string; label: string }> {
    return this.request(`/api/log-sources/ingest-credentials/${encodeURIComponent(credentialId)}/assign-source`, {
      method: 'POST', body: JSON.stringify({ source_slug, label }),
    });
  }

  async revokeIngestCredential(credentialId: string, reason: string): Promise<IngestCredentialRevocation> {
    return this.request(`/api/log-sources/ingest-credentials/${encodeURIComponent(credentialId)}/revoke`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  }

  async getSenderTemplates(): Promise<SenderTemplateCatalog> {
    return this.request('/api/log-sources/sender-templates');
  }

  /** Credentials that can write a registry entry's sources (NAN-2597). */
  async getLogSourceCredentials(id: string): Promise<TenantSourceWriters> {
    return this.request(`/api/log-sources/${encodeURIComponent(id)}/credentials`);
  }

  /** Credentials that can write one lake source label (NAN-2597, Source Visibility). */
  async getSourceWriters(sourceSlug: string): Promise<TenantSourceWriters> {
    return this.request(`/api/log-sources/ingest-credentials/writers/${encodeURIComponent(sourceSlug)}`);
  }

  /** Edge + lake activity and first-event state for one credential (NAN-2598). */
  async getIngestCredentialActivity(credentialId: string, hours?: number): Promise<IngestCredentialActivity> {
    const params = hours ? `?hours=${hours}` : '';
    return this.request(`/api/log-sources/ingest-credentials/${encodeURIComponent(credentialId)}/activity${params}`);
  }

  /** Per-credential breakdown of one lake source label (NAN-2598). */
  async getIngestSourceActivity(sourceSlug: string, hours?: number): Promise<IngestSourceActivity> {
    const params = hours ? `?hours=${hours}` : '';
    return this.request(`/api/log-sources/ingest-sources/${encodeURIComponent(sourceSlug)}/activity${params}`);
  }

  async getIngestionObserved(hours?: number): Promise<TenantIngestObservation> {
    const params = hours ? `?hours=${hours}` : '';
    return this.request(`/api/log-sources/ingestion-observed${params}`);
  }

  // Version management

  async getLogSourceVersions(id: string): Promise<LogSourceVersion[]> {
    return this.request(`/api/log-sources/${id}/versions`);
  }

  async publishLogSource(id: string, samples?: string[]): Promise<SharedDeploymentResponse> {
    return this.request(`/api/log-sources/${id}/publish`, {
      method: 'POST',
      ...deployBody(undefined, samples),
    });
  }

  async revertLogSourceVersion(id: string, versionId: number): Promise<SharedRevertResponse> {
    return this.request(`/api/log-sources/${id}/versions/${versionId}/revert`, {
      method: 'POST',
    });
  }

  // Parser-bundle rollouts (hosted-shared, NAN-2607)

  /** Re-roll the active published version (the "Retry rollout" action). */
  async requestParserRollout(id: string, input: { samples?: string[]; reason?: string } = {}): Promise<TenantParserRollout> {
    return this.request(`/api/log-sources/${id}/rollout`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async listLogSourceRollouts(id: string, limit?: number): Promise<TenantParserRollout[]> {
    return this.request(`/api/log-sources/${id}/rollouts${limit ? `?limit=${limit}` : ''}`);
  }

  async listParserRollouts(filter: { states?: string[]; limit?: number } = {}): Promise<TenantParserRollout[]> {
    const params = new URLSearchParams();
    if (filter.states?.length) params.set('state', filter.states.join(','));
    if (filter.limit) params.set('limit', String(filter.limit));
    const qs = params.toString();
    return this.request(`/api/log-sources/rollouts${qs ? `?${qs}` : ''}`);
  }

  async getParserRollout(rolloutId: string): Promise<TenantParserRollout> {
    return this.request(`/api/log-sources/rollouts/${encodeURIComponent(rolloutId)}`);
  }

  async listParserBaseOffers(): Promise<TenantParserBaseOffer[]> {
    return this.request('/api/log-sources/parser-base-offers');
  }

  async mergeParserBaseOffer(offerId: string, reason?: string): Promise<TenantParserRollout> {
    return this.request(`/api/log-sources/parser-base-offers/${encodeURIComponent(offerId)}/merge`, {
      method: 'POST',
      body: JSON.stringify(reason ? { reason } : {}),
    });
  }

  async getLogSourceSamples(id: string): Promise<TenantParserSamples> {
    return this.request(`/api/log-sources/${id}/samples`);
  }

  async putLogSourceSamples(id: string, samples: string[]): Promise<TenantParserSamples> {
    return this.request(`/api/log-sources/${id}/samples`, {
      method: 'PUT',
      body: JSON.stringify({ samples }),
    });
  }

  /** With `expectedUpdatedAt`, the server refuses (409) to discard a newer draft another editor saved. */
  async discardLogSourceDraft(id: string, expectedUpdatedAt?: string): Promise<LogSource> {
    return this.request(`/api/log-sources/${id}/discard-draft`, {
      method: 'POST',
      ...(expectedUpdatedAt ? { body: JSON.stringify({ expected_updated_at: expectedUpdatedAt }) } : {}),
    });
  }

  async getLogSourceDraftStatus(id: string): Promise<LogSourceWithDraftStatus> {
    return this.request(`/api/log-sources/${id}/draft-status`);
  }

  /**
   * NAN-522: validate a feed namespace string against the platform's
   * namespace rules (prefix grammar + length + character set).
   */
  async validateNamespace(namespace: string): Promise<NamespaceValidationResult> {
    return this.request('/api/log-sources/validate-namespace', {
      method: 'POST',
      body: JSON.stringify({ namespace }),
    });
  }
}
