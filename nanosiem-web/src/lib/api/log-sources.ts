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
  EnhancedDeploymentResponse,
  GenerationDeliveryStatus,
  NamespaceValidationResult,
} from './types';

/**
 * NAN-5131: deploy/undeploy/publish render the Vector config synchronously and
 * take 90 s+ on a small host. The edge gives these routes 300 s; the client
 * waits a little longer so the edge's answer (not a client abort) is shown.
 */
export const DEPLOY_REQUEST_TIMEOUT_MS = 310_000;
/** A request with an explicit client timeout. */
export type LongRequest = <T>(endpoint: string, options: RequestInit, timeoutMs: number) => Promise<T>;

export class LogSourcesApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
    private longRequest?: LongRequest,
  ) {}

  private deployRequest<T>(endpoint: string, options: RequestInit): Promise<T> {
    return this.longRequest
      ? this.longRequest<T>(endpoint, options, DEPLOY_REQUEST_TIMEOUT_MS)
      : this.request<T>(endpoint, options);
  }

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
  ): Promise<LogSourceTestResult> {
    return this.request('/api/log-sources/test-vrl', {
      method: 'POST',
      body: JSON.stringify({
        vrl_code: vrlCode,
        sample_log: sampleLog,
        ...(extensionVrl && extensionVrl.trim() !== ''
          ? { extension_vrl: extensionVrl }
          : {}),
      }),
    });
  }

  async testLogSourceVrlLive(vrlCode: string, sourceType: string, currentVrl?: string, limit: number = 10): Promise<LiveTestResult[]> {
    return this.request('/api/log-sources/test-live', {
      method: 'POST',
      body: JSON.stringify({ vrl_code: vrlCode, source_type: sourceType, current_vrl: currentVrl, limit }),
    });
  }

  async deployLogSource(id: string): Promise<EnhancedDeploymentResponse> {
    return this.deployRequest(`/api/log-sources/${id}/deploy`, {
      method: 'POST',
    });
  }

  async undeployLogSource(id: string): Promise<EnhancedDeploymentResponse> {
    return this.deployRequest(`/api/log-sources/${id}/undeploy`, {
      method: 'POST',
    });
  }

  async deployAllLogSources(): Promise<{ deployed: boolean }> {
    return this.deployRequest('/api/log-sources/deploy-all', {
      method: 'POST',
    });
  }

  /** NAN-5279: re-check a deploy's generation on the ingest hosts (one poll, no wait). */
  async getDeliveryStatus(generation: number): Promise<GenerationDeliveryStatus> {
    return this.request(`/api/log-sources/delivery-status?generation=${encodeURIComponent(String(generation))}`);
  }

  async getLogSourceDeployments(id: string): Promise<LogSourceDeployment[]> {
    return this.request(`/api/log-sources/${id}/deployments`);
  }

  async getLogSourceHealth(id: string): Promise<LogSourceHealth> {
    return this.request(`/api/log-sources/${id}/health`);
  }

  /** NAN-4922: where senders reach this deployment's Vector listeners. */
  async getIngestEndpoint(): Promise<import('./types').IngestEndpoint> {
    return this.request('/api/log-sources/ingest-endpoint');
  }

  /** NAN-3207/NAN-4922: hourly volume vs the expected band, every visible source. */
  async getHealthSeries(hours = 24): Promise<import('./types').LogSourceHealthSeries[]> {
    return this.request(`/api/log-sources/health-series?hours=${hours}`);
  }

  /** One source (a one-element array; 404 when missing or not visible). */
  async getLogSourceHealthSeries(id: string, hours = 24): Promise<import('./types').LogSourceHealthSeries[]> {
    return this.request(`/api/log-sources/${encodeURIComponent(id)}/health-series?hours=${hours}`);
  }

  async getIngestionHistory(hours?: number): Promise<IngestionHistoryPoint[]> {
    const params = hours ? `?hours=${hours}` : '';
    return this.request(`/api/log-sources/ingestion-history${params}`);
  }

  // Version management

  async getLogSourceVersions(id: string): Promise<LogSourceVersion[]> {
    return this.request(`/api/log-sources/${id}/versions`);
  }

  /**
   * Publish the working copy. `expectedUpdatedAt` (NAN-4919) makes the server
   * refuse with 409 unless the working copy is still the reviewed revision.
   */
  async publishLogSource(id: string, expectedUpdatedAt?: string): Promise<EnhancedDeploymentResponse> {
    return this.deployRequest(`/api/log-sources/${id}/publish`, {
      method: 'POST',
      ...(expectedUpdatedAt
        ? { body: JSON.stringify({ expected_updated_at: expectedUpdatedAt }) }
        : {}),
    });
  }

  async revertLogSourceVersion(id: string, versionId: number): Promise<LogSourceVersion> {
    return this.request(`/api/log-sources/${id}/versions/${versionId}/revert`, {
      method: 'POST',
    });
  }

  async discardLogSourceDraft(id: string, expectedUpdatedAt?: string): Promise<LogSource> {
    return this.request(`/api/log-sources/${id}/discard-draft`, {
      method: 'POST',
      ...(expectedUpdatedAt
        ? { body: JSON.stringify({ expected_updated_at: expectedUpdatedAt }) }
        : {}),
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
