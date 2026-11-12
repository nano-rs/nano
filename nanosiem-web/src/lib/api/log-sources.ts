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
  DeployJob,
  NamespaceValidationResult,
  OcsfGateRequest,
} from './types';
import { followDeployJob, type PollOptions } from '../deploy-job';

/** NAN-5079: the OCSF gate fields of a publish / deploy body. */
export function ocsfGateBody(ocsf?: OcsfGateRequest): Record<string, unknown> {
  const samples = (ocsf?.ocsfSampleLogs ?? []).filter((s) => s.trim() !== '');
  return {
    ...(samples.length > 0 ? { ocsf_sample_logs: samples } : {}),
    ...(ocsf?.acknowledgeUnattested ? { acknowledge_unattested: true } : {}),
    ...(ocsf?.unattestedSystemInstall ? { unattested_system_install: true } : {}),
  };
}

/**
 * NAN-5131: deploy/undeploy/publish rendered the Vector config synchronously
 * and could take 90 s+ on a small host, so these routes got a 300 s edge
 * budget and the client waited a little longer.
 *
 * NAN-5132: they now start a background job (`?wait=false` → 202) and the
 * client polls it, so the request returns at once. The long timeout stays on
 * the start request only for a server that predates deploy jobs and answers
 * synchronously.
 */
export const DEPLOY_REQUEST_TIMEOUT_MS = 310_000;
/** A request with an explicit client timeout. */
export type LongRequest = <T>(endpoint: string, options: RequestInit, timeoutMs: number) => Promise<T>;
/** Builds the error a failed job throws (an ApiClientError in the app). */
export type DeployErrorFactory = (message: string, code: string, status?: number) => Error;

/** Options for a deploy call: progress callback and polling overrides. */
/**
 * Poll options for a deploy job, plus (NAN-5079) the OCSF gate fields sent in
 * the start request's body. The server checks the gate BEFORE creating the
 * job, so a refusal is a 422 on the start request itself.
 */
export type DeployCallOptions = PollOptions & { ocsf?: OcsfGateRequest };

/** JSON `init` fields for a deploy-route body; omitted when empty. */
function jsonBody(body: Record<string, unknown>): { body?: string } {
  return Object.keys(body).length > 0 ? { body: JSON.stringify(body) } : {};
}

function isDeployJob(value: unknown): value is DeployJob {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as DeployJob).id === 'string' &&
    typeof (value as DeployJob).state === 'string' &&
    typeof (value as DeployJob).status_path === 'string'
  );
}

const defaultErrorFactory: DeployErrorFactory = (message, code, status) =>
  Object.assign(new Error(message), { code, status });

function errorCode(status: number | null | undefined): string {
  switch (status) {
    case 400:
      return 'BAD_REQUEST';
    case 403:
      return 'FORBIDDEN';
    case 404:
      return 'NOT_FOUND';
    case 409:
      return 'CONFLICT';
    case 422:
      return 'VALIDATION_ERROR';
    case 429:
      return 'TOO_MANY_REQUESTS';
    default:
      return 'DEPLOY_JOB_FAILED';
  }
}

export class LogSourcesApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
    private longRequest?: LongRequest,
    private makeError: DeployErrorFactory = defaultErrorFactory,
  ) {}

  private deployRequest<T>(endpoint: string, options: RequestInit): Promise<T> {
    return this.longRequest
      ? this.longRequest<T>(endpoint, options, DEPLOY_REQUEST_TIMEOUT_MS)
      : this.request<T>(endpoint, options);
  }

  /**
   * Start a deploy job and follow it to the end. Resolves to the job's final
   * body exactly as the synchronous call returned it (`legacy` for deploy-all,
   * which has no per-source result); rejects with the status the synchronous
   * call would have returned when the job failed with an error.
   */
  private async runDeployJob<T>(
    endpoint: string,
    init: RequestInit,
    options: DeployCallOptions | undefined,
    legacy?: T,
  ): Promise<T> {
    const separator = endpoint.includes('?') ? '&' : '?';
    const started = await this.deployRequest<unknown>(`${endpoint}${separator}wait=false`, init);
    // A server without deploy jobs ignores `wait` and answers with the result.
    if (!isDeployJob(started)) return started as T;
    const job = await followDeployJob(started, (id) => this.getDeployJob(id), options);
    if (job.result) return job.result as T;
    if (job.error_status != null || job.state !== 'succeeded') {
      throw this.makeError(
        job.message || 'The deploy did not complete.',
        job.state === 'interrupted' ? 'DEPLOY_INTERRUPTED' : errorCode(job.error_status),
        job.error_status ?? undefined,
      );
    }
    return (legacy ?? ({ deployed: true } as T)) as T;
  }

  /** NAN-5132: one deploy job. */
  async getDeployJob(id: string): Promise<DeployJob> {
    return this.request(`/api/log-sources/deploy-jobs/${encodeURIComponent(id)}`);
  }

  /** NAN-5132: recent deploy jobs for a log source (newest first, includes deploy-all). */
  async listLogSourceDeployJobs(id: string, limit = 5): Promise<DeployJob[]> {
    return this.request(`/api/log-sources/${encodeURIComponent(id)}/deploy-jobs?limit=${limit}`);
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

  /**
   * NAN-5079: `validate_ocsf` is always sent; the server applies the OCSF
   * contract only on an OCSF deployment. With `logSourceId`, a passing test
   * of that source's STORED generation becomes its OCSF receipt (needs
   * log_sources:edit); an unsaved buffer is validated but never attested.
   */
  async testLogSourceVrl(
    vrlCode: string,
    sampleLog: string,
    extensionVrl?: string,
    logSourceId?: string,
  ): Promise<LogSourceTestResult> {
    return this.request('/api/log-sources/test-vrl', {
      method: 'POST',
      body: JSON.stringify({
        vrl_code: vrlCode,
        sample_log: sampleLog,
        validate_ocsf: true,
        ...(extensionVrl && extensionVrl.trim() !== ''
          ? { extension_vrl: extensionVrl }
          : {}),
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

  async deployLogSource(id: string, options?: DeployCallOptions): Promise<EnhancedDeploymentResponse> {
    return this.runDeployJob(
      `/api/log-sources/${id}/deploy`,
      { method: 'POST', ...jsonBody(ocsfGateBody(options?.ocsf)) },
      options,
    );
  }

  async undeployLogSource(id: string, options?: DeployCallOptions): Promise<EnhancedDeploymentResponse> {
    return this.runDeployJob(`/api/log-sources/${id}/undeploy`, { method: 'POST' }, options);
  }

  async deployAllLogSources(options?: DeployCallOptions): Promise<{ deployed: boolean }> {
    return this.runDeployJob('/api/log-sources/deploy-all', { method: 'POST' }, options, { deployed: true });
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
  async publishLogSource(
    id: string,
    expectedUpdatedAt?: string,
    options?: DeployCallOptions,
  ): Promise<EnhancedDeploymentResponse> {
    return this.runDeployJob(
      `/api/log-sources/${id}/publish`,
      {
        method: 'POST',
        ...jsonBody({
          ...(expectedUpdatedAt ? { expected_updated_at: expectedUpdatedAt } : {}),
          ...ocsfGateBody(options?.ocsf),
        }),
      },
      options,
    );
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
