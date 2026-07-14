// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * React hooks for API data fetching
 * Provides loading states, error handling, and data caching
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { 
  api, 
  DetectionRule, 
  Alert, 
  ApiClientError,
  TimeRange,
  QueryWarning,
} from '@/lib/api';

interface UseQueryResult<T> {
  data: T | null;
  loading: boolean;
  error: ApiClientError | null;
  refetch: () => Promise<void>;
}

interface UseQueryOptions {
  /** Skip the query (useful for conditional fetching based on permissions) */
  skip?: boolean;
}

// Export for use in other files
export type { UseQueryOptions };
export type { QueryWarning };

interface UseMutationResult<TData, TVariables> {
  mutate: (variables: TVariables) => Promise<TData>;
  loading: boolean;
  error: ApiClientError | null;
}

// Generic hook for queries
function useQuery<T>(
  queryFn: () => Promise<T>,
  deps: unknown[] = [],
  options?: UseQueryOptions
): UseQueryResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(!options?.skip);
  const [error, setError] = useState<ApiClientError | null>(null);

  // NAN-1719 (DSH10): monotonic request token. Every fetch captures the current
  // value up-front and the effect cleanup bumps it, so a slow response whose
  // token no longer matches the latest is dropped instead of overwriting a newer
  // fetch's data. Without this a slow dashboard-A response can land after a fast
  // dashboard-B fetch and render A's content under B's URL.
  const requestSeq = useRef(0);

  const fetch = useCallback(async () => {
    const seq = ++requestSeq.current;
    if (options?.skip) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const result = await queryFn();
      if (seq !== requestSeq.current) return; // superseded by a newer fetch
      setData(result);
    } catch (err) {
      if (seq !== requestSeq.current) return; // superseded by a newer fetch
      setError(err instanceof ApiClientError ? err : new ApiClientError(String(err), 'UNKNOWN_ERROR'));
    } finally {
      if (seq === requestSeq.current) setLoading(false);
    }
  }, [...deps, options?.skip]);

  useEffect(() => {
    fetch();
    // Invalidate the in-flight request on deps change / unmount so its late
    // resolve is discarded (DSH10).
    return () => {
      requestSeq.current++;
    };
  }, [fetch]);

  return { data, loading, error, refetch: fetch };
}

// Generic hook for mutations
function useMutation<TData, TVariables>(
  mutationFn: (variables: TVariables) => Promise<TData>
): UseMutationResult<TData, TVariables> {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<ApiClientError | null>(null);

  const mutate = useCallback(async (variables: TVariables): Promise<TData> => {
    setLoading(true);
    setError(null);
    try {
      const result = await mutationFn(variables);
      return result;
    } catch (err) {
      const apiError = err instanceof ApiClientError ? err : new ApiClientError(String(err), 'UNKNOWN_ERROR');
      setError(apiError);
      throw apiError;
    } finally {
      setLoading(false);
    }
  }, [mutationFn]);

  return { mutate, loading, error };
}

// Detection hooks
export function useDetections(params?: {
  severity?: string;
  mode?: string;
  enabled?: boolean;
  search?: string;
}, options?: UseQueryOptions) {
  return useQuery(
    () => api.listDetections(params),
    [params?.severity, params?.mode, params?.enabled, params?.search],
    options
  );
}

export function useDetection(id: string | undefined) {
  return useQuery(
    () => id ? api.getDetection(id) : Promise.resolve(null),
    [id]
  );
}

export function useCreateDetection() {
  return useMutation(api.createDetection.bind(api));
}

export function useUpdateDetection() {
  return useMutation(
    ({ id, data }: { id: string; data: Parameters<typeof api.updateDetection>[1] }) =>
      api.updateDetection(id, data)
  );
}

export function useDeleteDetection() {
  return useMutation((id: string) => api.deleteDetection(id));
}

// Folder settings (NAN-730)
export function useFolderSettings() {
  return useQuery(
    () => api.getFolderSettings().then((r) => r.icons),
    [],
  );
}

export function useSetFolderIcon() {
  return useMutation(
    ({ name, icon }: { name: string; icon: string }) => api.setFolderIcon(name, icon),
  );
}

export function useClearFolderIcon() {
  return useMutation((name: string) => api.clearFolderIcon(name));
}

export function usePauseDetection() {
  return useMutation((id: string) => api.pauseDetection(id));
}

export function useResumeDetection() {
  return useMutation((id: string) => api.resumeDetection(id));
}

export function usePromoteDetection() {
  return useMutation((id: string) => api.promoteDetection(id));
}

export function useDemoteDetection() {
  return useMutation((id: string) => api.demoteDetection(id));
}

export function useRuleVersions(ruleId: string | undefined) {
  return useQuery(
    () => (ruleId ? api.listRuleVersions(ruleId) : Promise.resolve([])),
    [ruleId],
  );
}

export function useIdentityUserLookup(identifier: string | undefined | null) {
  return useQuery(
    () => (identifier ? api.lookupIdentityUser(identifier) : Promise.resolve(null)),
    [identifier],
  );
}

export function useRevertRuleVersion() {
  return useMutation(
    ({ ruleId, versionId }: { ruleId: string; versionId: number }) =>
      api.revertRuleVersion(ruleId, versionId),
  );
}

export function useTuningSettings(ruleId: string | undefined) {
  return useQuery(
    () => (ruleId ? api.getTuningSettings(ruleId) : Promise.resolve(null)),
    [ruleId],
  );
}

export function useUpdateTuningSettings() {
  return useMutation(
    ({ ruleId, settings }: { ruleId: string; settings: import('@/lib/api/types').TuningSettings }) =>
      api.updateTuningSettings(ruleId, settings),
  );
}

export function useDetectionStats(days: number = 28) {
  return useQuery(
    () => api.getDetectionStats(days),
    [days]
  );
}

export function useTodayCounts() {
  return useQuery(
    () => api.getTodayCounts(),
    []
  );
}

/**
 * NAN-612 — fleet-health rollup for the /rules overview strip "Fleet health"
 * cell. Returns total / healthy / slow / errors counts over Live & Alerting
 * scheduled rules. The card falls back to em-dashes if this returns null.
 */
export function useFleetHealth() {
  return useQuery(
    () => api.getFleetHealth(),
    []
  );
}

export function useDetectionMatches(
  id: string | undefined,
  params?: {
    limit?: number;
    offset?: number;
    start_time?: string;
    end_time?: string;
  }
) {
  return useQuery(
    () => id ? api.getDetectionMatches(id, params) : Promise.resolve(null),
    [id, params?.limit, params?.offset, params?.start_time, params?.end_time]
  );
}

export function useTestDetection() {
  return useMutation(
    ({ id, days, timeRange }: { id: string; days?: number; timeRange?: TimeRange }) =>
      api.testDetection(id, { days, timeRange })
  );
}

/** NAN-498 — rule-level disposition rollup for the Matches hero FP tile. */
export function useRuleDispositionStats(
  ruleId: string | undefined,
  days: number = 28,
) {
  return useQuery(
    () => (ruleId ? api.getRuleDispositionStats(ruleId, days) : Promise.resolve(null)),
    [ruleId, days],
  );
}

/** NAN-501 — parsed nPL predicates for the Matches detail Rule conditions card. */
export function useRulePredicates(ruleId: string | undefined) {
  return useQuery(
    () => (ruleId ? api.getRulePredicates(ruleId) : Promise.resolve(null)),
    [ruleId],
  );
}

export function useTestQuery() {
  return useMutation(
    ({ query, days, timeRange }: { query: string; days?: number; timeRange?: { start: string; end: string } }) => 
      api.testQuery(query, timeRange ? { timeRange } : { days })
  );
}

export function useFormatQuery() {
  return useMutation(
    (query: string) => api.formatQuery(query)
  );
}

// Alert hooks
export function useAlerts(params?: {
  status?: string;
  severity?: string;
  rule_id?: string;
  /** NAN-1541: alert-kind filter ('detection' vs observability monitors). */
  kinds?: string[];
  limit?: number;
  offset?: number;
}, options?: UseQueryOptions) {
  return useQuery(
    () => api.listAlerts(params),
    [params?.status, params?.severity, params?.rule_id, params?.kinds?.join(','), params?.limit, params?.offset],
    options
  );
}

export function useAlert(id: string | undefined) {
  return useQuery(
    () => id ? api.getAlert(id) : Promise.resolve(null),
    [id]
  );
}

export function useAlertCounts(kinds?: string[], options?: UseQueryOptions) {
  return useQuery(() => api.getAlertCounts(kinds), [kinds?.join(',')], options);
}

/** NAN-1019: hourly alert-velocity histogram over the last N hours
 *  (default 24). Powers the FIRING NOW sparkline on /rules.
 *  NAN-1541: optional kinds filter (detection vs observability monitors). */
export function useAlertVelocity(hours: number = 24, kinds?: string[], options?: UseQueryOptions) {
  return useQuery(() => api.getAlertVelocity(hours, kinds), [hours, kinds?.join(',')], options);
}

export function useAcknowledgeAlert() {
  return useMutation((id: string) => api.acknowledgeAlert(id));
}

export function useCloseAlert() {
  return useMutation(
    ({ id, disposition, notes }: { id: string; disposition: 'true_positive' | 'false_positive' | 'benign'; notes?: string }) =>
      api.closeAlert(id, { disposition, notes })
  );
}

export function useAssignAlert() {
  return useMutation(
    ({ id, assignedTo }: { id: string; assignedTo: string }) =>
      api.assignAlert(id, assignedTo)
  );
}

export function useBulkAlerts() {
  return useMutation(api.bulkAlerts.bind(api));
}

// Search hooks
export function useSearch() {
  return useMutation(api.search.bind(api));
}

export function useSearchSql() {
  return useMutation(api.searchSql.bind(api));
}

export function useExplainQuery() {
  return useMutation(
    ({ query, timeRange, dataset }: { query: string; timeRange: TimeRange; dataset?: import('@/lib/api/types').SearchDataset }) =>
      api.explainQuery(query, timeRange, dataset)
  );
}

export function useFieldStats() {
  return useMutation(
    (request: import('@/lib/api/types').FieldStatsRequest) =>
      api.getFieldStats(request)
  );
}

// On-demand search field values (Kibana-style, fetched when user expands a field)
export function useSearchFieldValues() {
  return useMutation(
    ({ field, query, start, end, limit, dataset }: { field: string; query: string; start: string; end: string; limit?: number; dataset?: import('@/lib/api/types').SearchDataset }) =>
      // NAN-1559: forward the per-query dataset so a spans/metrics field drill-in
      // resolves the field + base table against the dataset, not UDM `logs`.
      api.getSearchFieldValues({ field, query, start, end, limit, dataset })
  );
}

// Saved search hooks
export function useSavedSearches() {
  return useQuery(() => api.listSavedSearches(), []);
}

export function useSharedSearches() {
  return useQuery(() => api.listSharedSearches(), []);
}

export function useMySavedSearches() {
  return useQuery(() => api.listMySavedSearches(), []);
}

export function useCreateSavedSearch() {
  return useMutation(api.createSavedSearch.bind(api));
}

export function useUpdateSavedSearch() {
  return useMutation(
    ({ id, data }: { id: string; data: Parameters<typeof api.updateSavedSearch>[1] }) =>
      api.updateSavedSearch(id, data)
  );
}

export function useDeleteSavedSearch() {
  return useMutation((id: string) => api.deleteSavedSearch(id));
}

export function useShareSavedSearch() {
  return useMutation(
    ({ id, data }: { id: string; data: Parameters<typeof api.shareSavedSearch>[1] }) =>
      api.shareSavedSearch(id, data)
  );
}

// Groups hook for sharing
export function useGroups() {
  return useQuery(() => api.listGroups().then(r => r.groups), []);
}

// Shared search hooks (short URLs)
export function useCreateSharedSearch() {
  return useMutation(api.createSharedSearch.bind(api));
}

export function useGetSharedSearch() {
  return useMutation((id: string) => api.getSharedSearch(id));
}

// Query explanation hooks (AI reasoning cache)
export function useStoreQueryExplanation() {
  return useMutation(api.storeQueryExplanation.bind(api));
}

export function useGetQueryExplanation() {
  return useMutation((query: string) => api.getQueryExplanation(query));
}

// Field hooks
export function useFieldValues(name: string, limit: number = 10) {
  return useQuery(
    () => api.getFieldValues(name, limit),
    [name, limit]
  );
}

// Ingestion hooks
export function useIngestEvent() {
  return useMutation((event: Record<string, unknown>) => api.ingestEvent(event));
}

// Moved to lib/time-range.ts so the desktop app can share it; re-exported
// here because much of the app imports these from this module.
export { toApiTimeRange } from '@/lib/time-range';
export type { TimeRangeValue } from '@/lib/time-range';

// Helper function to parse timestamps as UTC
// Ensures that timestamps without timezone info are treated as UTC, not local time
function parseUTCTimestamp(ts: string): Date {
  let tsString = ts.trim();
  // Ensure timezone info is present - if not, assume UTC
  if (!tsString.includes('Z') && !tsString.includes('+') && !tsString.includes('-', 10)) {
    // No timezone info, add Z for UTC
    if (tsString.includes('T')) {
      tsString = tsString + 'Z';
    } else {
      // Space-separated format, convert to ISO with Z
      tsString = tsString.replace(' ', 'T') + 'Z';
    }
  }
  return new Date(tsString);
}

// Convert API detection to frontend format
export function fromApiDetection(rule: DetectionRule) {
  return {
    id: rule.id,
    name: rule.name,
    query: rule.query,
    severity: rule.severity === 'informational' ? 'info' : rule.severity,
    mode: rule.mode,
    status: rule.mode === 'paused' || rule.mode === 'staging' ? 'inactive' : 'active',
    lastRun: rule.last_run_at ? parseUTCTimestamp(rule.last_run_at) : undefined,
    lastMatch: rule.last_match_at ? parseUTCTimestamp(rule.last_match_at) : undefined,
    liveMatchCount: rule.live_match_count,
    schedule: rule.schedule_cron || '',
    mitreAttack: {
      tactics: rule.mitre_tactics,
      techniques: rule.mitre_techniques,
    },
    narrative: rule.narrative,
    referenceUrl: rule.reference_url,
    author: rule.author || 'Unknown',
    tags: rule.tags,
    aiGenerated: rule.ai_generated || false,
    realtimeEnabled: rule.realtime_enabled || false,
    riskScore: rule.risk_score,
    riskEntityField: rule.risk_entity_field,
    riskModifiers: rule.risk_modifiers || [],
    matchCount: rule.match_count || 0,
    createdAt: parseUTCTimestamp(rule.created_at),
    updatedAt: parseUTCTimestamp(rule.updated_at),
  };
}

// Convert API alert to frontend format
// Extract key entities from matched events for display
function extractEntities(events: Record<string, unknown>[]): string[] {
  if (!events || events.length === 0) return [];
  
  const entities: string[] = [];
  const firstEvent = events[0];
  
  // Priority order for entity extraction
  const entityFields = ['user', 'src_ip', 'dest_ip', 'dest_host', 'hostname', 'file_hash', 'url_domain'];
  
  for (const field of entityFields) {
    const value = firstEvent[field];
    if (value && typeof value === 'string' && value.trim()) {
      entities.push(value);
      if (entities.length >= 2) break; // Max 2 entities
    }
  }
  
  return entities;
}

export function fromApiAlert(alert: Alert) {
  const ruleName = alert.rule_name || 'Unknown Rule';
  const eventCount = alert.matched_event_count || alert.matched_events?.length || 0;
  const entities = extractEntities(alert.matched_events || []);
  
  // Build descriptive message with entities
  let alertMessage = `${ruleName}`;
  if (entities.length > 0) {
    alertMessage += ` (${entities.join(', ')})`;
  }
  
  return {
    id: alert.id,
    ruleId: alert.rule_id,
    ruleName: ruleName,
    alertMessage: alertMessage,
    severity: alert.severity === 'informational' ? 'info' : alert.severity,
    status: alert.status === 'new' ? 'open' : alert.status,
    disposition: alert.disposition,
    matchedEventCount: eventCount,
    matchedEvents: alert.matched_events,
    riskScore: alert.risk_score,
    timestamp: parseUTCTimestamp(alert.created_at),
    acknowledgedAt: alert.acknowledged_at ? parseUTCTimestamp(alert.acknowledged_at) : undefined,
    acknowledgedBy: alert.acknowledged_by,
    closedAt: alert.closed_at ? parseUTCTimestamp(alert.closed_at) : undefined,
    closedBy: alert.closed_by,
    // AI Triage status
    triageStatus: alert.triage_status,
    triageVerdict: alert.triage_verdict,
    // NAN-1541 alert-spine: discriminator + producer id. `detection` for rule
    // alerts; metric_monitor/slo/synthetic for observability monitor alerts.
    kind: alert.kind ?? 'detection',
    sourceId: alert.source_id,
  };
}


// Log Source hooks
export function useLogSources() {
  return useQuery(() => api.listLogSources(), []);
}

export function useLogSource(id: string | undefined) {
  return useQuery(
    () => id ? api.getLogSource(id) : Promise.resolve(null),
    [id]
  );
}

export function useCreateLogSource() {
  return useMutation(api.createLogSource.bind(api));
}

export function useUpdateLogSource() {
  return useMutation(
    ({ id, data }: { id: string; data: Parameters<typeof api.updateLogSource>[1] }) =>
      api.updateLogSource(id, data)
  );
}

export function useDeleteLogSource() {
  return useMutation((id: string) => api.deleteLogSource(id));
}

export function useToggleLogSource() {
  return useMutation(
    ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.toggleLogSource(id, enabled)
  );
}

export function useValidateLogSource() {
  return useMutation((id: string) => api.validateLogSource(id));
}

export function useValidateLogSourceVrl() {
  return useMutation((vrlCode: string) => api.validateLogSourceVrl(vrlCode));
}

export function useTestLogSourceVrl() {
  return useMutation(
    ({
      vrlCode,
      sampleLog,
      extensionVrl,
    }: {
      vrlCode: string;
      sampleLog: string;
      /** NAN-874: when present, run vrlCode → extensionVrl as a chain. */
      extensionVrl?: string;
    }) => api.testLogSourceVrl(vrlCode, sampleLog, extensionVrl)
  );
}

export function useTestLogSourceVrlLive() {
  return useMutation(
    ({ vrlCode, sourceType, currentVrl, limit }: { vrlCode: string; sourceType: string; currentVrl?: string; limit?: number }) =>
      api.testLogSourceVrlLive(vrlCode, sourceType, currentVrl, limit)
  );
}

export function useDeployLogSource() {
  return useMutation((id: string) => api.deployLogSource(id));
}

export function useUndeployLogSource() {
  return useMutation((id: string) => api.undeployLogSource(id));
}

export function useDeployAllLogSources() {
  return useMutation(() => api.deployAllLogSources());
}

export function useLogSourceDeployments(id: string | undefined) {
  return useQuery(
    () => id ? api.getLogSourceDeployments(id) : Promise.resolve([]),
    [id]
  );
}

export function useLogSourceHealth(id: string | undefined) {
  return useQuery(
    () => id ? api.getLogSourceHealth(id) : Promise.resolve(null),
    [id]
  );
}

export function useIngestionHistory(hours?: number) {
  return useQuery(
    () => api.getIngestionHistory(hours),
    [hours]
  );
}

// Log source version hooks

export function useLogSourceVersions(id: string | undefined) {
  return useQuery(
    () => id ? api.getLogSourceVersions(id) : Promise.resolve([]),
    [id]
  );
}

export function usePublishLogSource() {
  return useMutation((id: string) => api.publishLogSource(id));
}

export function useRevertLogSourceVersion() {
  return useMutation(({ id, versionId }: { id: string; versionId: number }) =>
    api.revertLogSourceVersion(id, versionId)
  );
}

export function useDiscardLogSourceDraft() {
  return useMutation((id: string) => api.discardLogSourceDraft(id));
}

export function useLogSourceDraftStatus(id: string | undefined) {
  return useQuery(
    () => id ? api.getLogSourceDraftStatus(id) : Promise.resolve(null),
    [id]
  );
}

// Cloud Credential hooks
export function useCredentials() {
  return useQuery(
    () => api.listCredentials().then(r => r.credentials),
    []
  );
}

export function useCredential(id: string | undefined) {
  return useQuery(
    () => id ? api.getCredential(id) : Promise.resolve(null),
    [id]
  );
}

export function useCreateCredential() {
  return useMutation(api.createCredential.bind(api));
}

export function useUpdateCredential() {
  return useMutation(
    ({ id, data }: { id: string; data: Parameters<typeof api.updateCredential>[1] }) =>
      api.updateCredential(id, data)
  );
}

export function useDeleteCredential() {
  return useMutation((id: string) => api.deleteCredential(id));
}

// meloD status hook — derives AI availability from provider data (no legacy endpoint)
export function useMelodStatus() {
  const { data: providers, loading, error, refetch } = useAiProviders();
  const providersArray = Array.isArray(providers) ? providers : [];
  const hasAnyEnabled = providersArray.some(p => p.enabled && p.has_credentials);
  return {
    data: hasAnyEnabled ? { connected: true, model_available: true } : { connected: false, model_available: false },
    loading,
    error,
    refetch,
  };
}

// Organizational Context hooks
export function useOrganizationalContext() {
  return useQuery(() => api.getOrganizationalContext(), []);
}

export function useUpdateOrganizationalContext() {
  return useMutation(api.updateOrganizationalContext.bind(api));
}

// Risk Settings hooks
export function useRiskConfig() {
  return useQuery(() => api.getRiskConfig(), []);
}

export function useUpdateRiskConfig() {
  return useMutation(api.updateRiskConfig.bind(api));
}

export function useRiskDecayConfig() {
  return useQuery(() => api.getRiskDecayConfig(), []);
}

export function useUpdateRiskDecayConfig() {
  return useMutation(api.updateRiskDecayConfig.bind(api));
}

export function useRiskNotableConfig() {
  return useQuery(() => api.getRiskNotableConfig(), []);
}

export function useUpdateRiskNotableConfig() {
  return useMutation(api.updateRiskNotableConfig.bind(api));
}

// Risk Analytics hooks
export function useRiskyEntities(params?: import('@/lib/api').RiskEntitiesQuery) {
  return useQuery(
    () => api.getRiskyEntities(params),
    [params?.window, params?.entity_type, params?.min_score, params?.limit, params?.offset]
  );
}

export function useRiskOverview() {
  return useQuery(() => api.getRiskOverview(), []);
}

export function useTimeWindowedRiskScores(params?: import('@/lib/api').TimeWindowedRiskQuery) {
  return useQuery(
    () => api.getTimeWindowedRiskScores(params),
    [params?.min_score_24h, params?.min_score_7d, params?.limit]
  );
}

export function useClearEntityRisk() {
  return useMutation(api.clearEntityRisk.bind(api));
}

export function useClearAllRiskScores() {
  return useMutation((_: void) => api.clearAllRiskScores());
}

export function useEntityRiskActivity(entities: { entity: string; entity_type: string }[]) {
  const key = entities.map(e => `${e.entity}|${e.entity_type}`).join(',');
  return useQuery(
    () => api.getEntityRiskActivity(entities),
    [key],
    { skip: entities.length === 0 }
  );
}

export function useEntityContext(entityType: string, entityValue: string, skip = false) {
  return useQuery(
    () => api.getEntityContext(entityType, entityValue),
    [entityType, entityValue],
    { skip }
  );
}

// System metrics hooks
export function useSystemOverview(hours?: number) {
  return useQuery(
    () => api.getSystemOverview(hours),
    [hours]
  );
}

export function useSystemConfig() {
  return useQuery(
    () => api.getSystemConfig(),
    []
  );
}

// Upload hooks
export function useUploadHistory(filter?: import('@/lib/api').UploadHistoryFilter) {
  return useQuery(
    () => api.getUploadHistory(filter),
    [filter?.destination_type, filter?.destination_name, filter?.status, filter?.start_date, filter?.end_date, filter?.limit, filter?.offset]
  );
}

export function usePreviewUpload() {
  return useMutation(
    async ({ file, format, delimiter }: { file: File; format?: import('@/lib/api').FileFormat; delimiter?: string }) => {
      return api.previewUpload(file, format, delimiter);
    }
  );
}

// Lookup table hooks
export function useLookupTables() {
  return useQuery(() => api.listLookupTables(), []);
}

export function useLookupTable(name: string | undefined) {
  return useQuery(
    () => name ? api.getLookupTable(name) : Promise.resolve(null),
    [name]
  );
}

export function useCreateLookupTable() {
  return useMutation(
    async ({ file, config }: { file: File; config: import('@/lib/api').CreateLookupTableConfig }) => {
      return api.createLookupTable(config, file);
    }
  );
}

export function useDeleteLookupTable() {
  return useMutation((name: string) => api.deleteLookupTable(name));
}

export function useLookupQuery() {
  return useMutation(api.lookupQuery.bind(api));
}

export function useLookupSampleRows(name: string | undefined) {
  return useQuery(
    () => name ? api.sampleLookupRows(name, 20) : Promise.resolve({ rows: [] }),
    [name]
  );
}

/**
 * Detection rules referencing a lookup table.
 *
 * Powers the Usage section of the LookupTableView Details inspector
 * (NAN-509 / NAN-510 / NAN-511). Returns an empty array when no rules
 * reference the table; the request errors if the table does not exist.
 */
export function useLookupUsage(name: string | undefined) {
  return useQuery(
    () => name ? api.getLookupUsage(name) : Promise.resolve([] as import('@/lib/api').LookupUsage[]),
    [name]
  );
}

/**
 * Recent activity (refresh + edit + upload) on a lookup table.
 *
 * Powers the History tab on the redesigned LookupTableView (NAN-510 slice 3
 * PR 3 / NAN-512). Returns an empty array when no activity is recorded; the
 * request errors if the table does not exist.
 */
export function useLookupHistory(name: string | undefined, limit: number = 50) {
  return useQuery(
    () =>
      name
        ? api.getLookupHistory(name, limit)
        : Promise.resolve([] as import('@/lib/api').LookupHistoryEntry[]),
    [name, limit],
  );
}

export function useLookupRows(name: string | undefined, page: number = 1, pageSize: number = 50) {
  return useQuery(
    () => name ? api.listLookupRows(name, page, pageSize) : Promise.resolve(null),
    [name, page, pageSize]
  );
}

export function useCreateLookupTableFromSchema() {
  return useMutation(
    (req: import('@/lib/api').CreateLookupTableFromSchemaRequest) => api.createLookupTableFromSchema(req)
  );
}

export function useAddLookupRows() {
  return useMutation(
    ({ name, rows }: { name: string; rows: Record<string, unknown>[] }) => api.addLookupRows(name, rows)
  );
}

export function useUpdateLookupRow() {
  return useMutation(
    ({ name, rowId, fields }: { name: string; rowId: number; fields: Record<string, unknown> }) =>
      api.updateLookupRow(name, rowId, fields)
  );
}

export function useDeleteLookupRow() {
  return useMutation(
    ({ name, rowId }: { name: string; rowId: number }) => api.deleteLookupRow(name, rowId)
  );
}

export function useDeleteLookupRows() {
  return useMutation(
    ({ name, rowIds }: { name: string; rowIds: number[] }) => api.deleteLookupRows(name, rowIds)
  );
}

// Lookup ingestion hooks (replaces scheduled job hooks)
export function useLookupIngestion(name: string | undefined) {
  return useQuery(
    () => name ? api.getLookupIngestion(name) : Promise.resolve(null),
    [name]
  );
}

export function useUpsertLookupIngestion() {
  return useMutation(
    ({ name, request }: { name: string; request: import('@/lib/api').UpsertLookupIngestionRequest }) =>
      api.upsertLookupIngestion(name, request)
  );
}

export function useDeleteLookupIngestion() {
  return useMutation((name: string) => api.deleteLookupIngestion(name));
}

export function useTriggerLookupIngestion() {
  return useMutation((name: string) => api.triggerLookupIngestion(name));
}

export function useToggleLookupIngestion() {
  return useMutation(
    ({ name, enabled }: { name: string; enabled: boolean }) =>
      enabled ? api.enableLookupIngestion(name) : api.disableLookupIngestion(name)
  );
}

export function useValidateCron() {
  return useMutation(api.validateCron.bind(api));
}

// Dashboard hooks
export function useDashboards(filter: 'my' | 'all' = 'my') {
  return useQuery(() => api.listDashboards(filter), [filter]);
}

export function useDashboard(id: string | undefined) {
  return useQuery(
    () => id ? api.getDashboard(id) : Promise.resolve(null),
    [id]
  );
}

export function useCreateDashboard() {
  return useMutation(api.createDashboard.bind(api));
}

export function useUpdateDashboard() {
  return useMutation(
    ({ id, data }: { id: string; data: Parameters<typeof api.updateDashboard>[1] }) =>
      api.updateDashboard(id, data)
  );
}

export function useDeleteDashboard() {
  return useMutation((id: string) => api.deleteDashboard(id));
}

export function usePanelQuery() {
  return useMutation(api.panelQuery.bind(api));
}

export function useExportDashboard() {
  return useMutation((id: string) => api.exportDashboard(id));
}

export function useImportDashboard() {
  return useMutation(api.importDashboard.bind(api));
}

// ============================================================================
// Prevalence Tracking Hooks
// ============================================================================

export function useHashPrevalence(hash: string | undefined) {
  return useQuery(
    () => hash ? api.getHashPrevalence(hash) : Promise.resolve(null),
    [hash]
  );
}

export function useDomainPrevalence(domain: string | undefined) {
  return useQuery(
    () => domain ? api.getDomainPrevalence(domain) : Promise.resolve(null),
    [domain]
  );
}

export function useBulkPrevalence() {
  return useMutation(api.getBulkPrevalence.bind(api));
}

export function useRareArtifacts(params?: { window?: string; type?: string; limit?: number; offset?: number }) {
  return useQuery(
    () => api.getRareArtifacts(params),
    [params?.window, params?.type, params?.limit, params?.offset]
  );
}

export function useNewArtifacts(params?: { since?: string; type?: string; limit?: number; offset?: number }) {
  return useQuery(
    () => api.getNewArtifacts(params),
    [params?.since, params?.type, params?.limit, params?.offset]
  );
}

export function useArtifactExplorer(params?: { window?: string; type?: string; risk_level?: string; search?: string; limit?: number; offset?: number }) {
  return useQuery(
    () => api.getArtifactExplorer(params),
    [params?.window, params?.type, params?.risk_level, params?.search, params?.limit, params?.offset]
  );
}

export function useArtifactDetail(artifact: string | undefined, window?: string) {
  return useQuery(
    () => artifact ? api.getArtifactDetail(artifact, window) : Promise.resolve(null),
    [artifact, window]
  );
}

/**
 * Reactive bulk-prevalence lookup. Used by the prevalence smart-search bar
 * (NAN-871) to render header stats — host_count, first_seen, last_seen,
 * prevalence_score, is_rare — for one or many artifacts in parallel with the
 * facet-detail fetch. Pass `null` to skip the request.
 */
export function useArtifactLookup(artifacts: string[] | null, window?: string) {
  const key = artifacts ? artifacts.join('|') : '';
  return useQuery(
    () =>
      artifacts && artifacts.length > 0
        ? api.getBulkPrevalence({ artifacts, window })
        : Promise.resolve(null),
    [key, window]
  );
}

export function usePrevalenceScatterData() {
  return useMutation(api.getPrevalenceScatterData.bind(api));
}

export function usePrevalenceArtifactsForQuery() {
  return useMutation(api.getPrevalenceArtifactsForQuery.bind(api));
}

export function usePrevalenceSettings() {
  return useQuery(() => api.getPrevalenceSettings(), []);
}

export function useUpdatePrevalenceSettings() {
  return useMutation(api.updatePrevalenceSettings.bind(api));
}

// ============================================================================
// Search Admission Settings Hooks
// ============================================================================

export function useSearchAdmissionConfig() {
  return useQuery(() => api.getSearchAdmissionConfig(), []);
}

export function useUpdateSearchAdmissionConfig() {
  return useMutation(api.updateSearchAdmissionConfig.bind(api));
}

// ============================================================================
// Search Query Safety Limits Hooks
// ============================================================================

export function useSearchQueryLimits() {
  return useQuery(() => api.getSearchQueryLimits(), []);
}

export function useUpdateSearchQueryLimits() {
  return useMutation(api.updateSearchQueryLimits.bind(api));
}

// ============================================================================
// Agent Enrichment Hooks (AI-powered threat intelligence)
// ============================================================================

export function useAgentEnrichmentProviders() {
  return useQuery(
    () => api.listAgentEnrichmentProviders().then(r => r.providers),
    []
  );
}

export function useAgentEnrichmentProvider(providerId: string | undefined) {
  return useQuery(
    () => providerId ? api.getAgentEnrichmentProvider(providerId) : Promise.resolve(null),
    [providerId]
  );
}

export function useCreateAgentEnrichmentProvider() {
  return useMutation(api.createAgentEnrichmentProvider.bind(api));
}

export function useUpdateAgentEnrichmentProvider() {
  return useMutation(
    ({ providerId, data }: { providerId: string; data: Parameters<typeof api.updateAgentEnrichmentProvider>[1] }) =>
      api.updateAgentEnrichmentProvider(providerId, data)
  );
}

export function useDeleteAgentEnrichmentProvider() {
  return useMutation((providerId: string) => api.deleteAgentEnrichmentProvider(providerId));
}

export function useUpdateAgentEnrichmentCredentials() {
  return useMutation(
    ({ providerId, apiKey }: { providerId: string; apiKey: string }) =>
      api.updateAgentEnrichmentCredentials(providerId, { api_key: apiKey })
  );
}

export function useTestAgentEnrichmentConnection() {
  return useMutation((providerId: string) => api.testAgentEnrichmentConnection(providerId));
}

export function useAgentEnrichmentUsage() {
  return useQuery(
    () => api.getAgentEnrichmentUsage(),
    []
  );
}

// ============================================================================
// AI Provider Credentials Hooks (LiteLLM multi-provider support)
// ============================================================================

export function useAiProviders() {
  return useQuery(() => api.listAiProviders(), []);
}

export function useAiProvider(provider: string | undefined) {
  return useQuery(
    () => provider ? api.getAiProvider(provider) : Promise.resolve(null),
    [provider]
  );
}

export function useUpdateAiProvider() {
  return useMutation(
    ({ provider, data }: { provider: string; data: Parameters<typeof api.updateAiProvider>[1] }) =>
      api.updateAiProvider(provider, data)
  );
}

export function useValidateAiProvider() {
  return useMutation((provider: string) => api.validateAiProvider(provider));
}

// ============================================================================
// Agent Model Configuration Hooks
// ============================================================================

export function useAgentModelConfigs() {
  return useQuery(() => api.listAgentModelConfigs(), []);
}

export function useAgentModelConfig(agentId: string | undefined) {
  return useQuery(
    () => agentId ? api.getAgentModelConfig(agentId) : Promise.resolve(null),
    [agentId]
  );
}

export function useUpdateAgentModelConfig() {
  return useMutation(
    ({ agentId, data }: { agentId: string; data: Parameters<typeof api.updateAgentModelConfig>[1] }) =>
      api.updateAgentModelConfig(agentId, data)
  );
}

// ============================================================================
// Available Models Hooks
// ============================================================================

export function useAvailableModels() {
  return useQuery(() => api.listAvailableModels(), []);
}

export function useAllAvailableModels() {
  return useQuery(() => api.listAllAvailableModels(), []);
}

export function useCreateAvailableModel() {
  return useMutation(
    (request: Parameters<typeof api.createAvailableModel>[0]) =>
      api.createAvailableModel(request)
  );
}

export function useUpdateAvailableModel() {
  return useMutation(
    ({ modelId, data }: { modelId: string; data: Parameters<typeof api.updateAvailableModel>[1] }) =>
      api.updateAvailableModel(modelId, data)
  );
}

export function useDeleteAvailableModel() {
  return useMutation((modelId: string) => api.deleteAvailableModel(modelId));
}

// ============================================================================
// Model Catalog Sync Hooks
// ============================================================================

export function useModelCatalogStatus() {
  return useQuery(() => api.getModelCatalogStatus(), []);
}

export function useSyncModelCatalog() {
  return useMutation(() => api.syncModelCatalog());
}

// ============================================================================
// GDPR Anonymization Hooks
// ============================================================================

export function useGdprRequests(limit: number = 50, offset: number = 0) {
  return useQuery(
    () => api.listGdprRequests({ limit, offset }),
    [limit, offset]
  );
}

// ============================================================================
// Onboarding Wizard Hooks
// ============================================================================

export function useOnboardingProgress(options?: UseQueryOptions) {
  return useQuery(
    () => api.onboarding.getProgress(),
    [],
    options
  );
}

export function useOnboardingStatus(options?: UseQueryOptions) {
  return useQuery(
    () => api.onboarding.getStatus(),
    [],
    options
  );
}

export function useCompleteOnboardingStep() {
  return useMutation((req: import('@/lib/api/onboarding').StepActionRequest) =>
    api.onboarding.completeStep(req)
  );
}

export function useSkipOnboardingStep() {
  return useMutation((req: import('@/lib/api/onboarding').StepActionRequest) =>
    api.onboarding.skipStep(req)
  );
}

export function useDismissOnboarding() {
  return useMutation((_?: void) => api.onboarding.dismiss());
}

export function useResetOnboarding() {
  return useMutation((_?: void) => api.onboarding.reset());
}

export function useUpdateOnboardingProgress() {
  return useMutation((req: import('@/lib/api/onboarding').UpdateProgressRequest) =>
    api.onboarding.updateProgress(req)
  );
}

// Tuning
export function useTuningProposals() {
  return useQuery(() => api.listTuningProposals(), []);
}

export function useTuningLogs() {
  return useQuery(() => api.listTuningLogs(), []);
}

export function useTuningProposal(id: string | undefined) {
  return useQuery(
    () => id ? api.getTuningProposal(id) : Promise.resolve(null),
    [id]
  );
}

export function useApproveTuningProposal() {
  return useMutation(({ id, opts }: { id: string; opts?: { comment?: string; modified_query?: string } }) =>
    api.approveTuningProposal(id, opts)
  );
}

export function useRejectTuningProposal() {
  return useMutation(({ id, reason }: { id: string; reason: string }) =>
    api.rejectTuningProposal(id, reason)
  );
}

// ============================================================================
// Home page hooks (NAN-370)
// ============================================================================

/** 4-card Home pulse strip → "Detection health" count aggregates. */
export function useDetectionHealthSummary() {
  return useQuery(() => api.getDetectionHealthSummary(), []);
}

/** Top-N noisiest rules for the Home "Noisiest rules" strip. */
export function useNoisyRules(limit: number = 5) {
  return useQuery(() => api.getNoisyRules(limit), [limit]);
}

/** Current user's open cases for the Home "My work" column. */
export function useMyCases(limit: number = 10) {
  return useQuery(() => api.getMyCases(limit), [limit]);
}

/** Unassigned triage queue for the Home "Unassigned" list.
 *  Backend `assigned_to` filter expects a user ID, so we fetch open/in-progress/pending
 *  cases and filter client-side (matches the prior Dashboard implementation). */
export function useUnassignedCases(limit: number = 10) {
  return useQuery(
    async () => {
      const { cases } = await api.listCases({
        status: ['open', 'in_progress', 'pending'],
        limit: limit * 3,
      });
      return cases.filter((c) => !c.assigned_to).slice(0, limit);
    },
    [limit]
  );
}

/** Current user's recent notebooks, sorted by most-recently-updated. */
export function useRecentNotebooks(limit: number = 5) {
  return useQuery(
    async () => {
      const all = await api.listNotebooks('my', 'all');
      return [...all]
        .sort((a, b) => (b.updated_at ?? '').localeCompare(a.updated_at ?? ''))
        .slice(0, limit);
    },
    [limit]
  );
}

/** Latest SIEM health report — feeds the Home "Ingest" and "Detection health" pulses. */
export function useSiemHealthLatest() {
  return useQuery(() => api.getSiemHealthLatest(), []);
}

// ---------------------------------------------------------------------------
// NAN-393 Asset dossier — aggregates for the redesigned Asset view
// ---------------------------------------------------------------------------
/**
 * Fetch the asset dossier aggregates for the redesigned Asset view. Returns
 * identity header, activity timeline, and per-section card data. Callers pass
 * null for `request` to defer the query (e.g. until the entity is known).
 */
export function useAssetDossier(request: import('@/lib/api/types').AssetDossierRequest | null) {
  return useQuery(
    async () => (request ? api.getAssetDossier(request) : null),
    [
      request?.identifier_field,
      request?.identifier_value,
      request?.time_range?.start,
      request?.time_range?.end,
      // identities list is stable for a given entity+range — only key by length
      request?.identities?.length,
    ]
  );
}

// ---------------------------------------------------------------------------
// NAN-394 Cloud overview — aggregates for the redesigned `| cloud` landing
// ---------------------------------------------------------------------------
export function useCloudOverview(request: import('@/lib/api/types').CloudOverviewRequest | null) {
  return useQuery(
    async () => (request ? api.getCloudOverview(request) : null),
    [
      request?.provider ?? null,
      request?.account ?? null,
      request?.time_range?.start,
      request?.time_range?.end,
    ]
  );
}

// ---------------------------------------------------------------------------
// NAN-395 Cloud principal dossier — aggregates for `| cloud principal=X`
// ---------------------------------------------------------------------------
export function useCloudDossier(request: import('@/lib/api/types').CloudDossierRequest | null) {
  // Facet filters mutate frequently (every chip toggle) — serialize into the
  // dep key so React re-runs the query when they change. String comparison
  // is fine since arrays stay small (< 20 entries in practice).
  const filterKey = request
    ? [
        request.services ?? [],
        request.regions ?? [],
        request.accounts ?? [],
        request.resource_types ?? [],
        request.change_types ?? [],
      ]
        .map((a) => a.join(','))
        .join('|')
    : '';
  return useQuery(
    async () => (request ? api.getCloudDossier(request) : null),
    [
      request?.principal ?? null,
      request?.account ?? null,
      request?.provider ?? null,
      request?.time_range?.start,
      request?.time_range?.end,
      filterKey,
    ]
  );
}

/**
 * Generic audit-log query hook. Used by the Home page for both the
 * "Fleet — last 24h" changes feed and the "Team activity" tail.
 */
export function useAuditLog(query: {
  action?: string;
  source?: string;
  user_id?: string;
  start_time?: string;
  end_time?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery(
    () => api.queryAuditLogs(query),
    [query.action, query.source, query.user_id, query.start_time, query.end_time, query.limit, query.offset]
  );
}

// ---------------------------------------------------------------------------
// NAN-443 Playbooks — library read surface
// ---------------------------------------------------------------------------

/** List playbooks (filterable, sortable). Backend endpoint: GET /api/playbooks. */
export function usePlaybooks(query: import('@/lib/api/types').ListPlaybooksQuery = {}) {
  return useQuery(
    () => api.playbooks.list(query),
    [
      query.category ?? null,
      query.status ?? null,
      query.signal ?? null,
      query.search ?? null,
      query.sort ?? null,
      query.limit ?? null,
      query.offset ?? null,
      query.adaptive ?? null,
    ],
  );
}

/** Single playbook by id. Skipped when id is null/empty. */
export function usePlaybook(id: string | null | undefined) {
  return useQuery(
    async () => (id ? api.playbooks.get(id) : null),
    [id ?? null],
    { skip: !id },
  );
}

/** Version history for a playbook. */
export function usePlaybookVersions(id: string | null | undefined) {
  return useQuery(
    async () => (id ? api.playbooks.listVersions(id) : []),
    [id ?? null],
    { skip: !id },
  );
}

/** Attach/run events for a playbook. */
export function usePlaybookRuns(id: string | null | undefined) {
  return useQuery(
    async () => (id ? api.playbooks.listRuns(id) : []),
    [id ?? null],
    { skip: !id },
  );
}

/** Per-role ACL rows for a playbook. */
export function usePlaybookPermissions(id: string | null | undefined) {
  return useQuery(
    async () => (id ? api.playbooks.listPermissions(id) : []),
    [id ?? null],
    { skip: !id },
  );
}

// ---------------------------------------------------------------------------
// NAN-444 Playbooks authoring — create / update / fork mutations
// ---------------------------------------------------------------------------

/** POST /api/playbooks — submit a new playbook draft. */
export function useCreatePlaybook() {
  return useMutation(
    (req: import('@/lib/api/types').CreatePlaybookRequest) =>
      api.playbooks.create(req),
  );
}

/** PATCH /api/playbooks/:id — partial update, bumps version. */
export function useUpdatePlaybook() {
  return useMutation(
    ({
      id,
      req,
    }: {
      id: string;
      req: import('@/lib/api/types').UpdatePlaybookRequest;
    }) => api.playbooks.update(id, req),
  );
}

/** DELETE /api/playbooks/:id — soft-archive via status='archived'. */
export function useArchivePlaybook() {
  return useMutation((id: string) => api.playbooks.archive(id));
}

/** NAN-456: DELETE /api/playbooks/:id/permanent — hard delete. */
export function useDeletePlaybookPermanent() {
  return useMutation((id: string) => api.playbooks.deletePermanent(id));
}

/** Resolve a nanosiem local user typeid (e.g. `user_5dze…`) to the
 *  UserDetail record via `/api/users/:id` so surfaces that store raw
 *  user ids (playbook maintainer, wall actors, etc.) can show a real
 *  name. Returns null when id is missing or the lookup fails. */
export function useLocalUser(id: string | null | undefined) {
  return useQuery(
    async () => {
      if (!id) return null;
      try {
        return await api.getUser(id);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn('useLocalUser lookup failed', id, err);
        return null;
      }
    },
    [id],
  );
}

/** POST /api/playbooks/:id/fork — clone as a draft for the current user. */
export function useForkPlaybook() {
  return useMutation(
    ({
      id,
      req,
    }: {
      id: string;
      req?: import('@/lib/api/types').ForkPlaybookRequest;
    }) => api.playbooks.fork(id, req ?? {}),
  );
}

// ---------------------------------------------------------------------------
// NAN-450 — FE wiring: hooks for Phase 4/5/5b/6/7 endpoints.
// ---------------------------------------------------------------------------

/** GET /api/playbooks/:id/analytics — real aggregates from playbook_runs. */
export function usePlaybookAnalytics(id: string | null | undefined) {
  return useQuery(
    () => (id ? api.playbooks.getAnalytics(id) : Promise.resolve(null)),
    [id],
  );
}

/** GET /api/playbooks/:id/approvals */
export function usePlaybookApprovals(id: string | null | undefined) {
  return useQuery(
    () => (id ? api.playbooks.listApprovals(id) : Promise.resolve([])),
    [id],
  );
}

/** GET /api/playbooks/suggest-for-rule/:rule_id */
export function useSuggestPlaybooksForRule(ruleId: string | null | undefined) {
  return useQuery(
    () => (ruleId ? api.playbooks.suggestForRule(ruleId) : Promise.resolve([])),
    [ruleId],
  );
}

/** GET /api/cases/:case_id/playbook-runs */
export function usePlaybookRunsForCase(caseId: string | null | undefined) {
  return useQuery(
    () => (caseId ? api.playbooks.listRunsForCase(caseId) : Promise.resolve([])),
    [caseId],
  );
}

/** POST /api/playbooks/:id/runs */
export function useAttachPlaybookToCase() {
  return useMutation(
    ({
      id,
      req,
    }: {
      id: string;
      req: import('@/lib/api/types').AttachToCaseRequest;
    }) => api.playbooks.attachToCase(id, req),
  );
}

/** NAN-468 — PATCH /api/playbook-runs/:id — terminal-state finish a run. */
export function useFinishRun() {
  return useMutation(
    ({
      runId,
      req,
    }: {
      runId: string;
      req?: import('@/lib/api/types').FinishRunRequest;
    }) => api.playbooks.finishRun(runId, req ?? {}),
  );
}

/** POST /api/playbooks/:id/promote */
export function usePromotePlaybook() {
  return useMutation((id: string) => api.playbooks.promote(id));
}

/** POST /api/cases/:case_id/compose-adaptive-playbook */
export function useComposeAdaptivePlaybook() {
  return useMutation((caseId: string) =>
    api.playbooks.composeAdaptiveFromCase(caseId),
  );
}

/** NAN-462 — GET /api/playbook-runs/:id/resolved */
export function useResolvedRun(runId: string | null | undefined) {
  return useQuery(
    () =>
      runId
        ? api.playbooks.getResolvedRun(runId)
        : Promise.resolve(null),
    [runId],
  );
}

/** NAN-473 — POST /api/playbooks/dry-resolve. Preview a draft doc against
 *  a recent alert without writing a `playbook_runs` row. */
export function useDryResolvePlaybook() {
  return useMutation(
    (req: import('@/lib/api/types').DryResolveRequest) =>
      api.playbooks.dryResolve(req),
  );
}

/** NAN-463 — PATCH /api/playbook-runs/:run_id/steps/:step_id */
export function useUpdateStepCompletion() {
  return useMutation(
    ({
      runId,
      stepId,
      req,
    }: {
      runId: string;
      stepId: string;
      req: import('@/lib/api/types').UpdateStepCompletionRequest;
    }) => api.playbooks.updateStepCompletion(runId, stepId, req),
  );
}

/** POST /api/playbooks/:id/submit-for-review */
export function useSubmitPlaybookForReview() {
  return useMutation(
    ({
      id,
      req,
    }: {
      id: string;
      req?: import('@/lib/api/types').SubmitForReviewRequest;
    }) => api.playbooks.submitForReview(id, req ?? {}),
  );
}

/** POST /api/playbook-approvals/:id/approve */
export function useApprovePlaybook() {
  return useMutation(
    ({
      approvalId,
      req,
    }: {
      approvalId: string;
      req?: import('@/lib/api/types').ApprovalResponseRequest;
    }) => api.playbooks.approve(approvalId, req ?? {}),
  );
}

/** POST /api/playbook-approvals/:id/reject */
export function useRejectPlaybook() {
  return useMutation(
    ({
      approvalId,
      req,
    }: {
      approvalId: string;
      req?: import('@/lib/api/types').ApprovalResponseRequest;
    }) => api.playbooks.reject(approvalId, req ?? {}),
  );
}

/** PUT /api/playbooks/:id/permissions/:role — upsert a role ACL row. */
export function useSetPlaybookPermission() {
  return useMutation(
    ({
      id,
      role,
      req,
    }: {
      id: string;
      role: string;
      req: import('@/lib/api/types').SetPermissionRequest;
    }) => api.playbooks.setPermission(id, role, req),
  );
}

/** DELETE /api/playbooks/:id/permissions/:role */
export function useDeletePlaybookPermission() {
  return useMutation(
    ({ id, role }: { id: string; role: string }) =>
      api.playbooks.deletePermission(id, role),
  );
}

// NAN-470 — playbook-repository hooks moved out. The dedicated admin page
// (`pages/PlaybookRepositories.tsx`) calls `api.playbooks.*` directly via
// `@tanstack/react-query`, mirroring `RuleRepositories.tsx`.
