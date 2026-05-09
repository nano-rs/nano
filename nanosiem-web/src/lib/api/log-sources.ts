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
  NamespaceValidationResult,
} from './types';

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

  async testLogSourceVrl(vrlCode: string, sampleLog: string): Promise<LogSourceTestResult> {
    return this.request('/api/log-sources/test-vrl', {
      method: 'POST',
      body: JSON.stringify({ vrl_code: vrlCode, sample_log: sampleLog }),
    });
  }

  async testLogSourceVrlLive(vrlCode: string, sourceType: string, currentVrl?: string, limit: number = 10): Promise<LiveTestResult[]> {
    return this.request('/api/log-sources/test-live', {
      method: 'POST',
      body: JSON.stringify({ vrl_code: vrlCode, source_type: sourceType, current_vrl: currentVrl, limit }),
    });
  }

  async deployLogSource(id: string): Promise<EnhancedDeploymentResponse> {
    return this.request(`/api/log-sources/${id}/deploy`, {
      method: 'POST',
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

  async getIngestionHistory(hours?: number): Promise<IngestionHistoryPoint[]> {
    const params = hours ? `?hours=${hours}` : '';
    return this.request(`/api/log-sources/ingestion-history${params}`);
  }

  // Version management

  async getLogSourceVersions(id: string): Promise<LogSourceVersion[]> {
    return this.request(`/api/log-sources/${id}/versions`);
  }

  async publishLogSource(id: string): Promise<EnhancedDeploymentResponse> {
    return this.request(`/api/log-sources/${id}/publish`, {
      method: 'POST',
    });
  }

  async revertLogSourceVersion(id: string, versionId: number): Promise<LogSourceVersion> {
    return this.request(`/api/log-sources/${id}/versions/${versionId}/revert`, {
      method: 'POST',
    });
  }

  async discardLogSourceDraft(id: string): Promise<LogSource> {
    return this.request(`/api/log-sources/${id}/discard-draft`, {
      method: 'POST',
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
