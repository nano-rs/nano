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

export interface IngestWatchdogHealth {
  node: string;
  action: string;
  mode: 'auto' | 'manual' | string;
  reason: string;
  event_age_secs: number;
  disabled_views: string[];
  replicas?: Array<{
    replica: string;
    endpoint: string;
    reachable: boolean;
    error: string;
    hot: boolean;
    sample_age_secs: number;
    /** NAN-5819: the latest sample is past the staleness bound (old evidence). */
    stale?: boolean;
  }>;
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
  /** NAN-4957: resident memory per dictionary, largest first. Optional:
   * reports stored before NAN-4957 lack these fields. */
  dictionary_memory?: DictionaryMemory[];
  dictionary_bytes_total?: number;
  /** Effective ClickHouse server memory limit; 0 = unknown. */
  server_memory_limit_bytes?: number;
  /** False when system.dictionaries could not be read (grant missing). */
  dictionary_memory_probe_ok?: boolean;
  /** NAN-4988: latest durable watchdog transition on each ClickHouse shard. */
  ingest_watchdog?: IngestWatchdogHealth[];
  /** NAN-5976: ClickHouse errors from inside an upgrade's own restart window.
   * Shown, not scored. Absent when there are none. */
  upgrade_transient_errors?: UpgradeTransientError[];
}

/** NAN-5976: a ClickHouse error counter the upgrade's own restart caused. */
export interface UpgradeTransientError {
  name: string;
  count: number;
  last_at: string;
  upgrade_run_id: string;
}

/** One ClickHouse dictionary's resident memory (NAN-4957). */
export interface DictionaryMemory {
  name: string;
  /** Layout as ClickHouse reports it: Trie, Hashed, ComplexKeyCache, … */
  layout: string;
  status: string;
  element_count: number;
  bytes_allocated: number;
}

/**
 * NAN-5760: data from a deleted log source still inside the 48h health
 * window. Informational: never silent, never scored, not in the totals.
 */
export interface RemovedSourceMetric {
  source_type: string;
  log_source_name: string;
  deleted_at: string;
  count_24h: number;
  count_prior_24h: number;
}

export interface IngestionMetrics {
  source_volumes: SourceVolumeMetric[];
  total_events_24h: number;
  total_events_prior_24h: number;
  silent_sources: string[];
  /** Absent on reports written before NAN-5760. */
  removed_sources?: RemovedSourceMetric[];
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
  /** NAN-4954: security-critical audit outbox (PostgreSQL → ClickHouse). Absent on older reports / failed probe. */
  audit_durability?: AuditDurabilityMetrics | null;
  /** NAN-5450: ClickHouse, PostgreSQL and Vector buffer volume usage. Absent on older reports. */
  disk?: DiskHealthReport | null;
  collected_at: string;
}

/**
 * NAN-5450: warning at 80 %, critical at 90 % (or forecast to fill within 24 h),
 * imminent at 95 %; `unknown` when not measurable.
 */
export type DiskLevel = 'ok' | 'unknown' | 'warning' | 'critical' | 'imminent';

export interface DiskForecast {
  /** Least-squares growth of used bytes per hour over the last 6 hours. */
  growth_bytes_per_hour: number;
  /** Hours until "full" at that rate; absent when not growing. */
  hours_to_full?: number;
  /** What "full" means: the ingest-pause fraction (0.92) on the ClickHouse disk, 1.0 elsewhere. */
  full_fraction?: number;
  samples: number;
  span_hours: number;
  /** The forecast raised the level to critical below 90 %. */
  escalated: boolean;
}

export interface DiskVolumeHealth {
  component: 'clickhouse' | 'postgres' | 'vector_buffer';
  host?: string;
  name: string;
  path?: string;
  total_bytes?: number;
  used_bytes?: number;
  free_bytes?: number;
  usage_fraction?: number;
  level: DiskLevel;
  detail: string;
  forecast?: DiskForecast;
  /** Key of the volume whose filesystem this one shares (single host). */
  shared_with?: string;
}

export interface DiskHealthReport {
  status: DiskLevel;
  warn_fraction: number;
  critical_fraction: number;
  imminent_fraction?: number;
  forecast_critical_hours?: number;
  volumes: DiskVolumeHealth[];
  notes: string[];
  checked_at: string;
}

export interface AuditDurabilityMetrics {
  pending: number;
  overdue: number;
  oldest_pending_age_secs: number | null;
  max_attempts: number;
  last_error: string | null;
  last_error_at: string | null;
  recorded_24h: number;
  deferred_24h: number;
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
  /** typeid form: user_<base32>; null once the user is deleted (NAN-5721). */
  created_by: string | null;
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

  /**
   * Latest report, or `null` when none has been generated yet. NAN-5683:
   * `allow_empty=true` makes "no report yet" a 200 + `null` instead of a 404,
   * so a fresh install doesn't log a failed request on every page.
   */
  async getLatest(): Promise<SiemHealthReport | null> {
    return this.request('/api/siem-health/reports/latest?allow_empty=true');
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
