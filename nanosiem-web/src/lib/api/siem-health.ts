// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * SIEM Health Check API routes
 * Handles health check reports, listing, and manual trigger
 */

export interface SourceVolumeMetric {
  source_type: string;
  count_24h: number;
  count_prior_24h: number;
  change_pct: number;
}

export interface FailedDictionary {
  name: string;
  last_exception: string;
}

/** A failing/stale dictionary-staging refresh MV (NAN-1407): stale
 * enrichment, NOT data loss — rows keep landing with the last good
 * snapshot. */
export interface StaleDictRefresh {
  view: string;
  exception: string;
  /** Seconds since the last successful refresh; 0 = never succeeded. */
  last_success_age_secs: number;
}

/** Insert-path integrity signals (NAN-1405) — NAN-1404 silent-loss probes.
 * Optional: reports stored before NAN-1405 lack the block entirely. */
export interface InsertIntegrityMetrics {
  probes_available: boolean;
  logs_inserts_1h: number;
  new_parts_1h: number;
  memory_limit_errors: number;
  cache_dictionary_update_fails: number;
  failed_logs_dictionaries: FailedDictionary[];
  async_insert_failures_1h: number | null;
  last_async_insert_error: string | null;
  /** Optional: reports stored before NAN-1407 lack this field. */
  stale_dict_refreshes?: StaleDictRefresh[];
}

export interface IngestionMetrics {
  source_volumes: SourceVolumeMetric[];
  total_events_24h: number;
  total_events_prior_24h: number;
  silent_sources: string[];
  insert_integrity?: InsertIntegrityMetrics;
}

export interface FieldCoverageMetric {
  source_type: string;
  total_events: number;
  src_ip_filled_pct: number;
  user_filled_pct: number;
  event_type_filled_pct: number;
  message_filled_pct: number;
}

export interface ExtUsageMetric {
  source_type: string;
  total_events: number;
  ext_usage_pct: number;
}

export interface ParsingMetrics {
  field_coverage: FieldCoverageMetric[];
  high_ext_sources: ExtUsageMetric[];
}

export interface RulesByMode {
  mode: string;
  count: number;
}

export interface StaleRule {
  rule_name: string;
  last_matched: string | null;
  days_since_match: number;
}

export interface NoisyRule {
  rule_name: string;
  matches_24h: number;
  severity: string;
}

export interface AlertsBySeverity {
  severity: string;
  count: number;
}

export interface DetectionMetrics {
  total_enabled_rules: number;
  rules_by_mode: RulesByMode[];
  stale_rules: StaleRule[];
  noisy_rules: NoisyRule[];
  alerts_24h_by_severity: AlertsBySeverity[];
}

export interface EnrichmentCoverageMetric {
  source_type: string;
  total_events: number;
  geoip_pct: number;
  ioc_pct: number;
  identity_pct: number;
}

export interface EnrichmentMetrics {
  total_events_24h: number;
  geoip_fill_pct: number;
  asn_fill_pct: number;
  ioc_hit_pct: number;
  identity_fill_pct: number;
  per_source_coverage: EnrichmentCoverageMetric[];
}

export interface AlertStatusCount {
  status: string;
  count: number;
}

export interface AlertingMetrics {
  total_alerts_24h: number;
  total_alerts_prior_24h: number;
  by_status: AlertStatusCount[];
  mean_mtta_minutes: number | null;
  active_webhooks: number;
  webhook_deliveries_24h: number;
  webhook_success_pct: number | null;
  active_routing_rules: number;
}

export interface CollectedMetrics {
  ingestion: IngestionMetrics;
  parsing: ParsingMetrics;
  enrichment: EnrichmentMetrics;
  detection: DetectionMetrics;
  alerting: AlertingMetrics;
  collected_at: string;
}

export interface SiemHealthReport {
  id: string;
  overall_score: number;
  overall_status: string;
  ingestion_score: number;
  parsing_score: number;
  detection_score: number;
  /** NAN-569: nullable for backward compat with reports older than the enrichment scoring landed. */
  enrichment_score: number | null;
  /** NAN-569: nullable for backward compat with reports older than the alerting scoring landed. */
  alerting_score: number | null;
  summary: string;
  metrics: CollectedMetrics | null;
  recommendations: Recommendation[];
  dimension_details: DimensionDetails;
  triggered_by: string | null;
  created_at: string;
  duration_ms: number | null;
}

export interface SiemHealthReportSummary {
  id: string;
  overall_score: number;
  overall_status: string;
  ingestion_score: number;
  parsing_score: number;
  detection_score: number;
  enrichment_score: number | null;
  alerting_score: number | null;
  summary: string;
  triggered_by: string | null;
  created_at: string;
  duration_ms: number | null;
}

export interface Recommendation {
  title: string;
  description: string;
  priority: string;
}

export interface DimensionDetails {
  ingestion: string;
  parsing: string;
  enrichment: string;
  detection: string;
  alerting: string;
}

export interface ListReportsResponse {
  reports: SiemHealthReportSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface TriggerResponse {
  report_id: string | null;
  message: string;
}

/** NAN-615: a /health finding the operator has marked as not-an-issue. */
export interface FindingSuppression {
  /** typeid form: hsupp_<base32> */
  id: string;
  finding_signature: string;
  /** Verbatim title at suppression time. Frontend filters current report by exact title match. */
  title: string;
  reason: string;
  /** typeid form: user_<base32> */
  created_by: string;
  created_at: string;
  /** Null when active; non-null when undone. */
  deactivated_at: string | null;
  deactivated_by: string | null;
}

export interface ListSuppressionsResponse {
  suppressions: FindingSuppression[];
}

export class SiemHealthApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async listReports(limit: number = 20, offset: number = 0): Promise<ListReportsResponse> {
    return this.request(`/api/siem-health/reports?limit=${limit}&offset=${offset}`);
  }

  async getLatest(): Promise<SiemHealthReport> {
    return this.request('/api/siem-health/reports/latest');
  }

  async getReport(id: string): Promise<SiemHealthReport> {
    return this.request(`/api/siem-health/reports/${encodeURIComponent(id)}`);
  }

  async trigger(): Promise<TriggerResponse> {
    return this.request('/api/siem-health/reports/trigger', {
      method: 'POST',
    });
  }

  // NAN-615: finding suppressions

  async listSuppressions(includeDeactivated = false): Promise<ListSuppressionsResponse> {
    const qs = includeDeactivated ? '?include_deactivated=true' : '';
    return this.request(`/api/siem-health/findings/suppressions${qs}`);
  }

  async createSuppression(title: string, reason: string): Promise<FindingSuppression> {
    return this.request('/api/siem-health/findings/suppressions', {
      method: 'POST',
      body: JSON.stringify({ title, reason }),
    });
  }

  async deactivateSuppression(id: string): Promise<FindingSuppression> {
    return this.request(
      `/api/siem-health/findings/suppressions/${encodeURIComponent(id)}`,
      { method: 'DELETE' }
    );
  }
}
