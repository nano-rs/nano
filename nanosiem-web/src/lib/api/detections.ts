// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Detection and Alert API routes
 * Handles detection rules, alerts, and related operations
 */

import type {
  DetectionRule,
  CreateDetectionRequest,
  UpdateDetectionRequest,
  DetectionResponse,
  TestDetectionResult,
  ValidateDetectionResult,
  TimeRange,
  DailyStat,
  DetectionMatchesResponse,
  MatchReviewResponse,
  DispositionStatsResponse,
  MatchDisposition,
  MatchDispositionResponse,
  RulePredicatesResponse,
  Alert,
  AlertCounts,
  CloseAlertRequest,
  BulkAlertRequest,
  BulkUpdateRulesRequest,
  BulkUpdateRulesResponse,
  DetectionHealthSummary,
  FleetHealthSummary,
  NoisyRulesResponse,
  RuleVersionResponse,
} from './types';

export class DetectionsApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  // Detection rules
  async listDetections(params?: {
    severity?: string;
    mode?: string;
    search?: string;
  }): Promise<DetectionRule[]> {
    const searchParams = new URLSearchParams();
    if (params?.severity) searchParams.set('severity', params.severity);
    if (params?.mode) searchParams.set('mode', params.mode);
    if (params?.search) searchParams.set('search', params.search);

    const query = searchParams.toString();
    return this.request(`/api/rules${query ? `?${query}` : ''}`);
  }

  async getDetection(id: string): Promise<DetectionRule> {
    return this.request(`/api/rules/${id}`);
  }

  async createDetection(request: CreateDetectionRequest): Promise<DetectionResponse> {
    return this.request('/api/rules', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async updateDetection(id: string, request: UpdateDetectionRequest): Promise<DetectionResponse> {
    return this.request(`/api/rules/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async deleteDetection(id: string): Promise<void> {
    return this.request(`/api/rules/${id}`, {
      method: 'DELETE',
    });
  }

  async pauseDetection(id: string): Promise<DetectionRule> {
    return this.request(`/api/rules/${id}/pause`, {
      method: 'POST',
    });
  }

  async resumeDetection(id: string): Promise<DetectionRule> {
    return this.request(`/api/rules/${id}/resume`, {
      method: 'POST',
    });
  }

  async testDetection(
    id: string,
    options?: { days?: number; timeRange?: TimeRange },
  ): Promise<TestDetectionResult> {
    const body: Record<string, unknown> = {};
    if (options?.timeRange) {
      // NAN-741: backend now steps the saved rule's schedule + lookback across
      // this window. `days` is left out so the backend uses `time_range` only.
      body.time_range = options.timeRange;
    } else {
      body.days = options?.days ?? 7;
    }
    return this.request(`/api/rules/${id}/test`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  async testQuery(query: string, options?: { days?: number; timeRange?: TimeRange }): Promise<TestDetectionResult> {
    const body: Record<string, unknown> = { query };
    if (options?.timeRange) {
      body.time_range = options.timeRange;
    } else {
      body.days = options?.days ?? 7;
    }
    return this.request('/api/rules/test', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  async formatQuery(query: string): Promise<{ formatted_query: string }> {
    return this.request('/api/rules/format', {
      method: 'POST',
      body: JSON.stringify({ query }),
    });
  }

  async validateDetection(query: string, detectionMode?: string): Promise<ValidateDetectionResult> {
    return this.request('/api/rules/validate', {
      method: 'POST',
      body: JSON.stringify({ query, detection_mode: detectionMode }),
    });
  }

  async promoteDetection(id: string): Promise<DetectionRule> {
    return this.request(`/api/rules/${id}/promote`, {
      method: 'POST',
    });
  }

  async demoteDetection(id: string): Promise<DetectionRule> {
    return this.request(`/api/rules/${id}/demote`, {
      method: 'POST',
    });
  }

  async listRuleVersions(id: string): Promise<RuleVersionResponse[]> {
    return this.request(`/api/rules/${id}/versions`);
  }

  async revertRuleVersion(id: string, versionId: number): Promise<{ success: boolean; message?: string }> {
    return this.request(`/api/rules/${id}/versions/${versionId}/revert`, {
      method: 'POST',
    });
  }

  async getDetectionStats(days: number = 28): Promise<Record<string, DailyStat[]>> {
    return this.request(`/api/rules/stats?days=${days}`);
  }

  async getTodayCounts(): Promise<Record<string, number>> {
    return this.request('/api/rules/today-counts');
  }

  /** Detection engine health counts for the Home "Detection health" pulse card (NAN-370). */
  async getHealthSummary(): Promise<DetectionHealthSummary> {
    return this.request('/api/rules/health-summary');
  }

  /** Fleet-health rollup for the /rules overview strip "Fleet health" cell (NAN-612). */
  async getFleetHealth(): Promise<FleetHealthSummary> {
    return this.request('/api/rules/fleet-health');
  }

  /** Top-N noisiest detection rules by 7-day match count (NAN-370). */
  async getNoisyRules(limit?: number): Promise<NoisyRulesResponse> {
    const params = limit ? `?limit=${limit}` : '';
    return this.request(`/api/rules/noisy${params}`);
  }

  async getDetectionMatches(
    id: string,
    params?: {
      limit?: number;
      offset?: number;
      start_time?: string;
      end_time?: string;
    }
  ): Promise<DetectionMatchesResponse> {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));
    if (params?.start_time) searchParams.set('start_time', params.start_time);
    if (params?.end_time) searchParams.set('end_time', params.end_time);

    const query = searchParams.toString();
    return this.request(`/api/rules/${id}/matches${query ? `?${query}` : ''}`);
  }

  /**
   * NAN-494 — flag a detection match as reviewed (or clear with `reviewed: false`).
   * Permission: detections:edit.
   */
  async markMatchReviewed(
    id: string,
    options?: { reviewed?: boolean; note?: string },
  ): Promise<MatchReviewResponse> {
    const body: Record<string, unknown> = {
      reviewed: options?.reviewed ?? true,
    };
    if (options?.note !== undefined) body.note = options.note;
    return this.request(`/api/matches/${id}/review`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  /** NAN-494 — clear the reviewed flag on a match. */
  async unmarkMatchReviewed(id: string): Promise<MatchReviewResponse> {
    return this.request(`/api/matches/${id}/review`, {
      method: 'DELETE',
    });
  }

  /**
   * NAN-498 — get disposition counts (FP/TP/benign/unclassified) for a rule
   * over a recent window. Used by the Matches hero to show the FP rate.
   */
  async getRuleDispositionStats(
    ruleId: string,
    days: number = 28,
  ): Promise<DispositionStatsResponse> {
    return this.request(`/api/rules/${ruleId}/disposition-stats?days=${days}`);
  }

  /** NAN-498 — set the disposition on a single match. detections:edit. */
  async setMatchDisposition(
    id: string,
    disposition: MatchDisposition,
  ): Promise<MatchDispositionResponse> {
    return this.request(`/api/matches/${id}/disposition`, {
      method: 'POST',
      body: JSON.stringify({ disposition }),
    });
  }

  /** NAN-501 — fetch parsed nPL predicates for a rule (detections:view). */
  async getRulePredicates(ruleId: string): Promise<RulePredicatesResponse> {
    return this.request(`/api/rules/${ruleId}/predicates`);
  }

  async importDetections(data: string, format: 'yaml' | 'json'): Promise<{ imported: number }> {
    return this.request('/api/rules/import', {
      method: 'POST',
      body: JSON.stringify({ data, format }),
    });
  }

  async exportDetections(format: 'yaml' | 'json'): Promise<string> {
    return this.request(`/api/rules/export?format=${format}`);
  }

  // Alerts
  async listAlerts(params?: {
    status?: string;
    severity?: string;
    rule_id?: string;
    limit?: number;
    offset?: number;
  }): Promise<Alert[]> {
    const searchParams = new URLSearchParams();
    if (params?.status) searchParams.set('status', params.status);
    if (params?.severity) searchParams.set('severity', params.severity);
    if (params?.rule_id) searchParams.set('rule_id', params.rule_id);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));

    const query = searchParams.toString();
    return this.request(`/api/alerts${query ? `?${query}` : ''}`);
  }

  async getAlert(id: string): Promise<Alert> {
    return this.request(`/api/alerts/${id}`);
  }

  async getAlertCounts(): Promise<AlertCounts> {
    return this.request('/api/alerts/counts');
  }

  async acknowledgeAlert(id: string): Promise<Alert> {
    return this.request(`/api/alerts/${id}/acknowledge`, {
      method: 'POST',
    });
  }

  async closeAlert(id: string, request: CloseAlertRequest): Promise<Alert> {
    return this.request(`/api/alerts/${id}/close`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async assignAlert(id: string, assignedTo: string): Promise<Alert> {
    return this.request(`/api/alerts/${id}/assign`, {
      method: 'POST',
      body: JSON.stringify({ assigned_to: assignedTo }),
    });
  }

  async bulkAlerts(request: BulkAlertRequest): Promise<{ updated: number }> {
    return this.request('/api/alerts/bulk', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async bulkUpdateRules(request: BulkUpdateRulesRequest): Promise<BulkUpdateRulesResponse> {
    return this.request('/api/rules/bulk-update', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // ── Folder settings (NAN-730) ─────────────────────────────────────────
  // Per-folder display metadata — currently just the icon. Folders without
  // a row fall back to the frontend default icon mapping.

  async getFolderSettings(): Promise<{ icons: Record<string, string> }> {
    return this.request('/api/folder-settings');
  }

  async setFolderIcon(name: string, icon: string): Promise<{ name: string; icon: string }> {
    return this.request(`/api/folder-settings/${encodeURIComponent(name)}`, {
      method: 'PUT',
      body: JSON.stringify({ icon }),
    });
  }

  async clearFolderIcon(name: string): Promise<void> {
    await this.request(`/api/folder-settings/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    });
  }
}
