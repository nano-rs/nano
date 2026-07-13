// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  CreateReportRequest,
  ReportDefinition,
  ReportListResponse,
  ReportResponse,
  ReportRun,
  ReportRunResponse,
  ReportRunsResponse,
  RunReportResponse,
  UpdateReportRequest,
} from './types';
import { getServiceUrl } from './utils';

/**
 * Scheduled Reports API (NAN-1793).
 *
 * Definitions schedule (cron) a saved SEARCH or a DASHBOARD to generate
 * downloadable artifacts (CSV + HTML for search; HTML for dashboard). Runs are
 * produced on the schedule or on demand; completed runs notify via the bell.
 */
export class ReportsApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
    // Needed for the binary artifact download, which cannot go through the
    // JSON-parsing `request` transport. Mirrors UploadApi.
    private getAccessToken?: () => string | null,
  ) {}

  /** filter=all only works for admins; default mine. */
  async listReports(filter: 'mine' | 'all' = 'mine'): Promise<ReportDefinition[]> {
    const res = await this.request<ReportListResponse>(`/api/reports?filter=${filter}`);
    return res.reports;
  }

  async createReport(request: CreateReportRequest): Promise<ReportDefinition> {
    const res = await this.request<ReportResponse>('/api/reports', {
      method: 'POST',
      body: JSON.stringify(request),
    });
    return res.report;
  }

  async getReport(id: string): Promise<ReportDefinition> {
    const res = await this.request<ReportResponse>(`/api/reports/${id}`);
    return res.report;
  }

  async updateReport(id: string, request: UpdateReportRequest): Promise<ReportDefinition> {
    const res = await this.request<ReportResponse>(`/api/reports/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
    return res.report;
  }

  async deleteReport(id: string): Promise<void> {
    await this.request<void>(`/api/reports/${id}`, { method: 'DELETE' });
  }

  /** Triggers a manual run; returns 202 with the new run id. */
  async runReport(id: string): Promise<string> {
    const res = await this.request<RunReportResponse>(`/api/reports/${id}/run`, {
      method: 'POST',
    });
    return res.run_id;
  }

  /**
   * List runs for a definition. NOTE: runs from this endpoint carry an empty
   * `artifacts` array — fetch a single run via getReportRun to get artifacts.
   */
  async getReportRuns(id: string): Promise<ReportRun[]> {
    const res = await this.request<ReportRunsResponse>(`/api/reports/${id}/runs`);
    return res.runs;
  }

  /** Single run, with populated `artifacts`. */
  async getReportRun(runId: string): Promise<ReportRun> {
    const res = await this.request<ReportRunResponse>(`/api/reports/runs/${runId}`);
    return res.run;
  }

  /**
   * Download an artifact file. The endpoint returns a binary attachment, so we
   * bypass the JSON `request` transport: authenticate with the same Bearer
   * token, read the blob, and trigger a browser download via an object URL.
   */
  async downloadArtifact(artifactId: string, filename: string): Promise<void> {
    const endpoint = `/api/reports/artifacts/${artifactId}/download`;
    const url = `${getServiceUrl(endpoint)}${endpoint}`;

    const headers: HeadersInit = {};
    const token = this.getAccessToken?.();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(url, {
      method: 'GET',
      headers,
      credentials: 'include',
    });

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({
        error: { code: 'UNKNOWN_ERROR', message: response.statusText },
      }));
      const error = errorBody.error || errorBody;
      throw new Error(error.message || 'Download failed');
    }

    const blob = await response.blob();
    const objectUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = objectUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(objectUrl);
  }
}
