// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NanoSIEM API Client
 * Handles all communication with the backend API
 *
 * In microservices mode, routes requests to different services:
 * - Main API (port 3000): detections, alerts, log sources, auth, settings, etc.
 * - Ingest Service (port 3001): /api/ingest/*
 * - Search Service (port 3002): /api/search, /api/search/sql, /api/search/explain, /api/search/saved/*
 */

import { getServiceUrl, API_BASE_URL } from './utils';
import { getAccessToken as getInMemoryToken } from '../auth-token';
import { AuthApi } from './auth';
import { SearchApi } from './search';
import { ObservabilityApi } from './observability';
import { DetectionsApi } from './detections';
import { CredentialsApi } from './credentials';
import { MelodApi } from '@/enterprise/api/melod';
import { CoreApi } from './core';
import { TuningAPI } from '@/enterprise/api/tuning';
import { CasesApi } from '@/enterprise/api/cases';
import { QueuesApi } from '@/enterprise/api/queues';
import { IncidentsApi } from '@/enterprise/api/incidents';
import { NotebooksApi } from '@/enterprise/api/notebooks';
import { LogSourcesApi } from './log-sources';
import { SourceConfigsApi } from './source-configs';
import { SourceScopesApi } from './source-scopes';
import { AccessControlApi } from './access-control';
import { DashboardsApi } from './dashboards';
import { StorageApi } from './storage';
import { RiskApi } from '@/enterprise/api/risk';
import { NotificationsApi } from './notifications';
import { FeedbackApi } from '@/enterprise/api/feedback';
import { EnrichmentApi } from './enrichment';
import { IdentityApi } from './identity';
import { CustomEnrichmentApi } from '@/enterprise/api/custom-enrichment';
import { PrevalenceApi } from './prevalence';
import { UploadApi } from './upload';
import { LookupTablesApi } from './lookup-tables';
import { AuditApi } from './audit';
import { ContextApi } from './context';
import { RuleRepositoriesApi } from './rule-repositories';
import { DetectionCodeTargetsApi } from './detection-code-targets';
import { ParserRepositoriesApi } from './parser-repositories';
import { WebhooksApi } from './webhooks';
import { MarketplaceApi } from './marketplace';
import { IntegrationsApi } from './integrations';
import { GdprApi } from './gdpr';
import { TierApi } from './tier';
import { IpAllowlistApi } from './ip-allowlist';
import { OnboardingApi } from './onboarding';
import { DemoApi } from './demo';
import { SiemHealthApi } from './siem-health';
import { SystemHealthApi } from './system-health';
import { PlaybooksApi } from '@/enterprise/api/playbooks';
import { ReportsApi } from './reports';

// Re-export types
export * from './types';

export interface LicenseStatusResponse {
  state: 'active' | 'grace_period' | 'locked';
  valid: boolean;
  tier?: string;
  locked_reason?: string;
  grace_ends_at?: string;
  expires_at?: string;
  enforcement_enabled: boolean;
  /**
   * Air-gapped deployment (AIRGAP_MODE on). Air-gap installs enforce a signed
   * offline license but have no phone-home, so `enforcement_enabled` is false
   * here; treat `airgap || enforcement_enabled` as "enforced" (NAN-1222).
   */
  airgap?: boolean;
}
export type {
  MarketplaceCatalogEntry, EnrichmentMarketplaceRepo, CatalogStats,
  CatalogFilter, InstallRequest, ConfigureRequest, EnrichmentStatus as MarketplaceEnrichmentStatus,
  CreateMarketplaceRepoRequest, UpdateMarketplaceRepoRequest, RepoBrowseEntry,
  CatalogListResponse, CredentialFieldDef,
} from './marketplace';
export type {
  IntegrationInstance, StreamStatus, CreateInstanceRequest as CreateIntegrationInstanceRequest,
  UpdateInstanceRequest as UpdateIntegrationInstanceRequest, ListInstancesResponse,
  TriggerRunResponse, CollectorStreamDef, CollectorConfigFieldDef, StreamProvisionReport,
  CollectorManifestAuth, CollectorAuthType, CustomCollectorDefinitionRequest,
  CustomCollectorDefinition, CustomCollectorValidationResponse,
  CustomCollectorPreviewRequest, CustomCollectorPreviewEvent, CustomCollectorPreviewResponse,
  GenerateCustomCollectorCodeRequest, GenerateCustomCollectorCodeResponse,
} from './integrations';
export { collectorManifest, streamNeedsAttention } from './integrations';

/**
 * Cache transparency (NAN-1595). Parsed from the `x-nano-cache` / `x-nano-cache-age`
 * response headers the search service stamps on every cacheable endpoint, so any
 * view (including a shared-link follower whose client cache is cold) can show
 * "cached Ns ago · refresh".
 */
export interface CacheMeta {
  /** True when the body was served from the server cache. */
  hit: boolean;
  /** Age in seconds of the cache hit (null on a miss or when unknown). */
  ageSecs: number | null;
}

/** Per-call cache controls threaded down to the low-level request. */
export interface CacheRequestOpts {
  /** Invoked with the server cache status parsed from response headers. */
  onMeta?: (meta: CacheMeta) => void;
  /** When true, send `x-nano-cache-bypass: 1` so the server recomputes live (refresh). */
  bypass?: boolean;
}

/** Parse the cache-status headers off a fetch Response. */
function parseCacheMeta(response: Response): CacheMeta {
  const status = response.headers.get('x-nano-cache');
  const ageRaw = response.headers.get('x-nano-cache-age');
  const age = ageRaw != null ? Number(ageRaw) : NaN;
  return { hit: status === 'hit', ageSecs: Number.isFinite(age) ? age : null };
}

// Re-export error class
export class ApiClientError extends Error {
  constructor(
    message: string,
    public code: string,
    public details?: unknown,
    /** HTTP status code, when the error originated from an HTTP response. */
    public status?: number
  ) {
    super(message);
    this.name = 'ApiClientError';
  }
}

/**
 * Main API client that provides access to all API endpoints
 */
class ApiClient {
  private baseUrl: string;
  private authFailureCallback: (() => void) | null = null;
  private refreshCallback: (() => Promise<boolean>) | null = null;

  // Route modules (internal)
  private _auth: AuthApi;
  private _search: SearchApi;
  private _observability: ObservabilityApi;
  private _detections: DetectionsApi;
  private _credentials: CredentialsApi;
  private _melod: MelodApi;
  private _core: CoreApi;
  private _tuning: TuningAPI;
  private _cases: CasesApi;
  private _queues: QueuesApi;
  private _incidents: IncidentsApi;
  private _notebooks: NotebooksApi;
  private _logSources: LogSourcesApi;
  private _sourceConfigs: SourceConfigsApi;
  private _sourceScopes: SourceScopesApi;
  private _accessControl: AccessControlApi;
  private _dashboards: DashboardsApi;
  private _storage: StorageApi;
  private _risk: RiskApi;
  private _notifications: NotificationsApi;
  private _feedback: FeedbackApi;
  private _enrichment: EnrichmentApi;
  private _identity: IdentityApi;
  private _customEnrichment: CustomEnrichmentApi;
  private _prevalence: PrevalenceApi;
  private _upload: UploadApi;
  private _lookupTables: LookupTablesApi;
  private _audit: AuditApi;
  private _context: ContextApi;
  private _ruleRepositories: RuleRepositoriesApi;
  private _detectionCodeTargets: DetectionCodeTargetsApi;
  private _parserRepositories: ParserRepositoriesApi;
  private _webhooks: WebhooksApi;
  private _marketplace: MarketplaceApi;
  private _integrations: IntegrationsApi;
  private _gdpr: GdprApi;
  private _tier: TierApi;
  private _ipAllowlist: IpAllowlistApi;
  private _onboarding: OnboardingApi;
  private _demo: DemoApi;
  private _siemHealth: SiemHealthApi;
  private _systemHealth: SystemHealthApi;
  private _playbooks: PlaybooksApi;
  private _reports: ReportsApi;

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl;

    // Initialize route modules with the request function
    this._auth = new AuthApi(this.request.bind(this));
    this._search = new SearchApi(
      this.request.bind(this),
      this.getAccessToken.bind(this),
      this.baseUrl
    );
    this._observability = new ObservabilityApi(
      this.request.bind(this),
      // Traces/Metrics passthroughs delegate to the SearchApi instance so the
      // console consumes a single `api.observability` facade (NAN-1536).
      (req, cacheOpts) => this._search.listTraces(req, cacheOpts),
      (service) => this._search.listMetricNames(service),
      (req) => this._search.queryMetrics(req),
      // NAN-1540: multi-series metrics + tag discovery.
      (req, cacheOpts) => this._search.queryMetricsV2(req, cacheOpts),
      (metricName, key) => this._search.listMetricTags(metricName, key)
    );
    this._detections = new DetectionsApi(this.request.bind(this));
    this._credentials = new CredentialsApi(this.request.bind(this));
    this._melod = new MelodApi(
      this.request.bind(this),
      this.getAccessToken.bind(this),
      this.baseUrl
    );
    this._core = new CoreApi(this.request.bind(this));
    this._tuning = new TuningAPI();
    this._cases = new CasesApi(this.request.bind(this));
    this._queues = new QueuesApi(this.request.bind(this));
    this._incidents = new IncidentsApi(this.request.bind(this));
    this._notebooks = new NotebooksApi(
      this.request.bind(this),
      this.getAccessToken.bind(this),
      this.baseUrl
    );
    this._logSources = new LogSourcesApi(this.request.bind(this));
    this._sourceConfigs = new SourceConfigsApi(this.request.bind(this));
    this._sourceScopes = new SourceScopesApi(this.request.bind(this));
    this._accessControl = new AccessControlApi(this.request.bind(this));
    this._dashboards = new DashboardsApi(this.request.bind(this));
    this._storage = new StorageApi(this.request.bind(this));
    this._risk = new RiskApi(this.request.bind(this));
    this._notifications = new NotificationsApi(this.request.bind(this));
    this._feedback = new FeedbackApi(this.request.bind(this));
    this._enrichment = new EnrichmentApi(this.request.bind(this));
    this._identity = new IdentityApi(this.request.bind(this));
    this._customEnrichment = new CustomEnrichmentApi(this.request.bind(this));
    this._prevalence = new PrevalenceApi(this.request.bind(this));
    this._upload = new UploadApi(this.request.bind(this), this.getAccessToken.bind(this));
    this._lookupTables = new LookupTablesApi(this.request.bind(this), this.getAccessToken.bind(this));
    this._audit = new AuditApi(this.request.bind(this));
    this._context = new ContextApi(this.request.bind(this));
    this._ruleRepositories = new RuleRepositoriesApi(this.request.bind(this));
    this._detectionCodeTargets = new DetectionCodeTargetsApi(this.request.bind(this));
    this._parserRepositories = new ParserRepositoriesApi(this.request.bind(this));
    this._webhooks = new WebhooksApi(this.request.bind(this));
    this._marketplace = new MarketplaceApi(this.request.bind(this));
    this._integrations = new IntegrationsApi(this.request.bind(this));
    this._gdpr = new GdprApi(this.request.bind(this));
    this._tier = new TierApi(this.request.bind(this));
    this._ipAllowlist = new IpAllowlistApi(this.request.bind(this));
    this._onboarding = new OnboardingApi(this.request.bind(this));
    this._demo = new DemoApi(this.request.bind(this));
    this._siemHealth = new SiemHealthApi(this.request.bind(this));
    this._systemHealth = new SystemHealthApi(this.request.bind(this));
    this._playbooks = new PlaybooksApi(this.request.bind(this));
    this._reports = new ReportsApi(this.request.bind(this), this.getAccessToken.bind(this));
  }

  // Expose modules for direct access when needed
  get auth(): AuthApi {
    return this._auth;
  }

  get dashboards(): DashboardsApi {
    return this._dashboards;
  }

  get cases(): CasesApi {
    return this._cases;
  }

  get queues(): QueuesApi {
    return this._queues;
  }

  get notebooks(): NotebooksApi {
    return this._notebooks;
  }

  get ruleRepositories(): RuleRepositoriesApi {
    return this._ruleRepositories;
  }

  get detectionCodeTargets(): DetectionCodeTargetsApi {
    return this._detectionCodeTargets;
  }

  get parserRepositories(): ParserRepositoriesApi {
    return this._parserRepositories;
  }

  get webhooks(): WebhooksApi {
    return this._webhooks;
  }

  get marketplace(): MarketplaceApi {
    return this._marketplace;
  }

  /** Integration collectors (NAN-2189) — instances of collector-category
   *  marketplace entries. Enterprise only; the routes 404 on open builds. */
  get integrations(): IntegrationsApi {
    return this._integrations;
  }

  get tier(): TierApi {
    return this._tier;
  }

  get ipAllowlist(): IpAllowlistApi {
    return this._ipAllowlist;
  }

  get onboarding(): OnboardingApi {
    return this._onboarding;
  }

  get demo(): DemoApi {
    return this._demo;
  }

  get siemHealth(): SiemHealthApi {
    return this._siemHealth;
  }

  get systemHealth(): SystemHealthApi {
    return this._systemHealth;
  }

  get playbooks(): PlaybooksApi {
    return this._playbooks;
  }

  get observability(): ObservabilityApi {
    return this._observability;
  }

  get reports(): ReportsApi {
    return this._reports;
  }

  get sourceScopes(): SourceScopesApi {
    return this._sourceScopes;
  }

  private getAccessToken(): string | null {
    return getInMemoryToken();
  }

  setAuthFailureCallback(callback: (() => void) | null): void {
    this.authFailureCallback = callback;
  }

  setRefreshCallback(callback: (() => Promise<boolean>) | null): void {
    this.refreshCallback = callback;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
    cacheOpts?: CacheRequestOpts
  ): Promise<T> {
    // Use service-aware routing for microservices architecture
    const serviceUrl = getServiceUrl(endpoint);
    const url = `${serviceUrl}${endpoint}`;
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      // NAN-1595: refresh forces a live server recompute (bypasses Dragonfly).
      ...(cacheOpts?.bypass ? { 'x-nano-cache-bypass': '1' } : {}),
      ...options.headers,
    };

    // Add Authorization header if we have a token
    const token = this.getAccessToken();
    if (token) {
      (headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
    }

    // Set up timeout using AbortController (60s — AI ops are async jobs now)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60000);

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        credentials: 'include',
        signal: controller.signal,
      });

      if (!response.ok) {
        // On 401, attempt a silent refresh and retry once
        if (response.status === 401 && this.refreshCallback) {
          const refreshed = await this.refreshCallback();
          if (refreshed) {
            // Retry the original request with the new token (fresh headers object)
            const retryToken = this.getAccessToken();
            const retryHeaders = { ...headers } as Record<string, string>;
            if (retryToken) {
              retryHeaders['Authorization'] = `Bearer ${retryToken}`;
            }
            const retryResponse = await fetch(url, {
              ...options,
              headers: retryHeaders,
              credentials: 'include',
              signal: controller.signal,
            });
            if (retryResponse.ok) {
              cacheOpts?.onMeta?.(parseCacheMeta(retryResponse));
              if (retryResponse.status === 204) return undefined as T;
              return retryResponse.json();
            }
          }
          // Refresh failed or retry still 401 — notify auth context
          if (this.authFailureCallback) {
            this.authFailureCallback();
          }
        } else if (response.status === 401 && this.authFailureCallback) {
          this.authFailureCallback();
        }
        const errorBody = await response.json().catch(() => ({
          error: {
            code: 'UNKNOWN_ERROR',
            message: response.statusText,
          }
        }));
        const error = errorBody.error || errorBody;

        // Handle IP_DENIED — redirect to deny page instead of login
        if (error.code === 'IP_DENIED' && typeof window !== 'undefined') {
          window.location.href = '/denied';
          // Throw to halt further execution
          throw new ApiClientError(error.message, 'IP_DENIED');
        }

        throw new ApiClientError(error.message || 'Request failed', error.code, error.details, response.status);
      }

      // NAN-1595: surface server cache status to the caller (badge driver).
      cacheOpts?.onMeta?.(parseCacheMeta(response));

      // Handle 204 No Content responses (e.g., DELETE operations)
      if (response.status === 204) {
        return undefined as T;
      }

      return response.json();
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new ApiClientError('Request timeout', 'TIMEOUT');
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // Legacy compatibility methods (direct access to frequently used endpoints)
  // These delegate to the route modules for backward compatibility

  // Health check
  async healthCheck(): Promise<{ status: string }> {
    return this._core.healthCheck();
  }

  // Version info
  async getVersion(): Promise<{ version: string; status: string }> {
    return this._core.getVersion();
  }

  // Search
  async search(request: import('./types').SearchRequest): Promise<import('./types').SearchResponse> {
    return this._search.search(request);
  }

  async searchSql(request: import('./types').RawSqlRequest): Promise<import('./types').SearchResponse> {
    return this._search.searchSql(request);
  }

  async explainQuery(query: string, timeRange: import('./types').TimeRange, dataset?: import('./types').SearchDataset): Promise<{ sql: string }> {
    return this._search.explainQuery(query, timeRange, true, dataset);
  }

  // Fetch single log by ID (for table_view mode row expansion).
  // NAN-1032: sourceType lets ClickHouse use the (source_type, timestamp, ...) PK
  // for a tight range read — without it, S3-backed historical lookups take 12–60s.
  async fetchLog(id: string, timeRange?: import('./types').TimeRange, sourceType?: string): Promise<{ event: Record<string, unknown> | null }> {
    return this._search.fetchLog(id, timeRange, sourceType);
  }

  async getFieldStats(
    request: import('./types').FieldStatsRequest,
    cacheOpts?: CacheRequestOpts
  ): Promise<import('./types').FieldStatsResponse> {
    return this._search.getFieldStats(request, cacheOpts);
  }

  // On-demand field values (Kibana-style)
  async getSearchFieldValues(
    request: import('./types').FieldValuesRequest,
    cacheOpts?: CacheRequestOpts
  ): Promise<import('./types').FieldValuesResponse> {
    return this._search.getSearchFieldValues(request, cacheOpts);
  }

  // OpenTelemetry observability (NAN-1528)
  async getTrace(traceId: string): Promise<import('./types').TraceResponse> {
    return this._search.getTrace(traceId);
  }

  async queryMetrics(request: import('./types').MetricsQueryRequest): Promise<import('./types').MetricsQueryResponse> {
    return this._search.queryMetrics(request);
  }

  // Observability explorers (NAN-1534)
  async listTraces(request: import('./types').ListTracesRequest): Promise<import('./types').ListTracesResponse> {
    return this._search.listTraces(request);
  }

  async listMetricNames(service?: string): Promise<import('./types').MetricNamesResponse> {
    return this._search.listMetricNames(service);
  }

  // Saved searches
  async listSavedSearches(): Promise<import('./types').SavedSearchWithContext[]> {
    return this._search.listSavedSearches();
  }

  async listSharedSearches(): Promise<import('./types').SavedSearchWithContext[]> {
    return this._search.listSharedSearches();
  }

  async listMySavedSearches(): Promise<import('./types').SavedSearchWithContext[]> {
    return this._search.listMySavedSearches();
  }

  async createSavedSearch(request: import('./types').CreateSavedSearchRequest): Promise<import('./types').SavedSearch> {
    return this._search.createSavedSearch(request);
  }

  async getSavedSearch(id: string): Promise<import('./types').SavedSearchWithContext> {
    return this._search.getSavedSearch(id);
  }

  async updateSavedSearch(id: string, request: import('./types').UpdateSavedSearchRequest): Promise<import('./types').SavedSearch> {
    return this._search.updateSavedSearch(id, request);
  }

  async deleteSavedSearch(id: string): Promise<void> {
    return this._search.deleteSavedSearch(id);
  }

  async shareSavedSearch(id: string, request: import('./types').ShareSavedSearchRequest): Promise<import('./types').SavedSearchWithContext> {
    return this._search.shareSavedSearch(id, request);
  }

  // Shared searches (short URLs)
  async createSharedSearch(request: import('./types').CreateSharedSearchRequest): Promise<import('./types').CreateSharedSearchResponse> {
    return this._search.createSharedSearch(request);
  }

  async getSharedSearch(id: string): Promise<import('./types').SharedSearchResponse> {
    return this._search.getSharedSearch(id);
  }

  // Query explanations
  async storeQueryExplanation(request: import('./types').StoreQueryExplanationRequest): Promise<import('./types').QueryExplanationResponse> {
    return this._search.storeQueryExplanation(request);
  }

  async getQueryExplanation(query: string): Promise<import('./types').QueryExplanationResponse> {
    return this._search.getQueryExplanation(query);
  }

  // Query cancellation (server-side)
  async cancelSearch(requestId: string): Promise<{ cancelled: boolean }> {
    return this._search.cancelSearch(requestId);
  }

  // Async search methods
  async searchAsync(request: Omit<import('./types').SearchRequest, 'async_mode'>): Promise<import('./types').AsyncSearchResponse> {
    return this._search.searchAsync(request);
  }

  searchStreamSSE(
    request: Omit<import('./types').SearchRequest, 'async_mode'>,
    callbacks: import('./types').SearchStreamCallbacks,
    opts?: { bypass?: boolean }
  ): AbortController {
    return this._search.searchStreamSSE(request, callbacks, opts);
  }

  async getSearchJob(jobId: string): Promise<import('./types').SearchJobStatus> {
    return this._search.getSearchJob(jobId);
  }

  async cancelSearchJob(jobId: string): Promise<{ cancelled: boolean }> {
    return this._search.cancelSearchJob(jobId);
  }

  // Paginated asset events (for infinite scroll and server-side filtering)
  async getAssetEvents(
    request: import('./types').AssetEventsRequest,
    cacheOpts?: CacheRequestOpts
  ): Promise<import('./types').AssetEventsResponse> {
    return this._search.getAssetEvents(request, cacheOpts);
  }

  // Lazy-loaded true time range (first/last seen) for asset view
  async getAssetTrueTimeRange(
    request: import('./types').AssetTrueTimeRangeRequest,
    cacheOpts?: CacheRequestOpts
  ): Promise<import('./types').AssetTrueTimeRangeResponse> {
    return this._search.getAssetTrueTimeRange(request, cacheOpts);
  }

  // Lazy-loaded artifact summaries (hashes/domains) for asset prevalence scatter
  async getAssetArtifacts(
    request: import('./types').AssetArtifactsRequest,
    cacheOpts?: CacheRequestOpts
  ): Promise<import('./types').AssetArtifactsResponse> {
    return this._search.getAssetArtifacts(request, cacheOpts);
  }

  // Asset dossier aggregates for the redesigned Asset view (NAN-393)
  async getAssetDossier(
    request: import('./types').AssetDossierRequest,
    cacheOpts?: CacheRequestOpts
  ): Promise<import('./types').AssetDossierResponse> {
    return this._search.getAssetDossier(request, cacheOpts);
  }

  // Cloud overview aggregates for the redesigned `| cloud` landing view (NAN-394)
  async getCloudOverview(
    request: import('./types').CloudOverviewRequest,
    cacheOpts?: CacheRequestOpts
  ): Promise<import('./types').CloudOverviewResponse> {
    return this._search.getCloudOverview(request, cacheOpts);
  }

  // IOC retro-hunt summary / campaign-list / pivot rollup (NAN-1580)
  async getRetro(
    request: import('./types').RetroRequest,
    cacheOpts?: CacheRequestOpts
  ): Promise<import('./types').RetroResponse> {
    return this._search.getRetro(request, cacheOpts);
  }

  // Cloud principal dossier aggregates for `| cloud principal=X` (NAN-395)
  async getCloudDossier(
    request: import('./types').CloudDossierRequest,
    cacheOpts?: CacheRequestOpts
  ): Promise<import('./types').CloudDossierResponse> {
    return this._search.getCloudDossier(request, cacheOpts);
  }

  // Paginated cloud events (for infinite scroll and server-side filtering)
  async getCloudEvents(
    request: import('./types').CloudEventsRequest,
    cacheOpts?: CacheRequestOpts
  ): Promise<import('./types').CloudEventsResponse> {
    return this._search.getCloudEvents(request, cacheOpts);
  }

  // Cloud user timeline (for user investigation sheet)
  async getCloudUserTimeline(
    request: import('./types').CloudUserTimelineRequest,
    cacheOpts?: CacheRequestOpts
  ): Promise<import('./types').CloudUserTimelineResponse> {
    return this._search.getCloudUserTimeline(request, cacheOpts);
  }

  // Cloud entity pivot (for entity correlation sheet)
  async getCloudEntityPivot(
    request: import('./types').CloudEntityPivotRequest,
    cacheOpts?: CacheRequestOpts
  ): Promise<import('./types').CloudEntityPivotResponse> {
    return this._search.getCloudEntityPivot(request, cacheOpts);
  }

  // Authentication
  async login(email: string, password: string): Promise<import('./types').AuthResponse> {
    return this._auth.login(email, password);
  }

  async logout(refreshToken: string): Promise<void> {
    return this._auth.logout(refreshToken);
  }

  async refreshToken(refreshToken: string): Promise<import('./types').TokenPairResponse> {
    return this._auth.refreshToken(refreshToken);
  }

  async getCurrentUser(): Promise<import('./types').CurrentUser> {
    return this._auth.getCurrentUser();
  }

  // Detections
  async listDetections(params?: Parameters<DetectionsApi['listDetections']>[0]): Promise<import('./types').DetectionRule[]> {
    return this._detections.listDetections(params);
  }

  async getDetection(id: string): Promise<import('./types').DetectionRule> {
    return this._detections.getDetection(id);
  }

  async createDetection(request: import('./types').CreateDetectionRequest): Promise<import('./types').DetectionResponse> {
    return this._detections.createDetection(request);
  }

  async updateDetection(id: string, request: import('./types').UpdateDetectionRequest): Promise<import('./types').DetectionResponse> {
    return this._detections.updateDetection(id, request);
  }

  async deleteDetection(id: string): Promise<void> {
    return this._detections.deleteDetection(id);
  }

  // Auto retro-hunt rules (NAN-1791)
  async listRetroHuntFeeds(): Promise<string[]> {
    return this._detections.listRetroHuntFeeds();
  }

  async createRetroHunt(request: import('./types').CreateRetroHuntRequest): Promise<import('./types').DetectionResponse> {
    return this._detections.createRetroHunt(request);
  }

  async getRetroHunt(id: string): Promise<import('./types').RetroHuntRuleView> {
    return this._detections.getRetroHunt(id);
  }

  async updateRetroHunt(id: string, request: import('./types').UpdateRetroHuntConfigRequest): Promise<import('./types').RetroHuntConfig> {
    return this._detections.updateRetroHunt(id, request);
  }

  async listRetroHuntRuns(id: string): Promise<import('./types').RetroHuntRun[]> {
    return this._detections.listRetroHuntRuns(id);
  }

  async pauseDetection(id: string): Promise<import('./types').DetectionRule> {
    return this._detections.pauseDetection(id);
  }

  async resumeDetection(id: string): Promise<import('./types').DetectionRule> {
    return this._detections.resumeDetection(id);
  }

  async testDetection(
    id: string,
    options?: { days?: number; timeRange?: import('./types').TimeRange },
  ): Promise<import('./types').TestDetectionResult> {
    return this._detections.testDetection(id, options);
  }

  async testQuery(query: string, options?: { days?: number; timeRange?: import('./types').TimeRange }): Promise<import('./types').TestDetectionResult> {
    return this._detections.testQuery(query, options);
  }

  async formatQuery(query: string): Promise<{ formatted_query: string }> {
    return this._detections.formatQuery(query);
  }

  async validateDetection(query: string, detectionMode?: string): Promise<import('./types').ValidateDetectionResult> {
    return this._detections.validateDetection(query, detectionMode);
  }

  async promoteDetection(id: string): Promise<import('./types').DetectionRule> {
    return this._detections.promoteDetection(id);
  }

  async demoteDetection(id: string): Promise<import('./types').DetectionRule> {
    return this._detections.demoteDetection(id);
  }

  async listRuleVersions(id: string): Promise<import('./types').RuleVersionResponse[]> {
    return this._detections.listRuleVersions(id);
  }

  async revertRuleVersion(id: string, versionId: number): Promise<{ success: boolean; message?: string }> {
    return this._detections.revertRuleVersion(id, versionId);
  }

  async getDetectionStats(days?: number): Promise<Record<string, import('./types').DailyStat[]>> {
    return this._detections.getDetectionStats(days);
  }

  async getTodayCounts(): Promise<Record<string, number>> {
    return this._detections.getTodayCounts();
  }

  async getDetectionHealthSummary(): Promise<import('./types').DetectionHealthSummary> {
    return this._detections.getHealthSummary();
  }

  /** NAN-612 — fleet-health rollup for the /rules overview strip Fleet health cell. */
  async getFleetHealth(): Promise<import('./types').FleetHealthSummary> {
    return this._detections.getFleetHealth();
  }

  async getNoisyRules(limit?: number): Promise<import('./types').NoisyRulesResponse> {
    return this._detections.getNoisyRules(limit);
  }

  async getDetectionMatches(id: string, params?: { limit?: number; offset?: number; start_time?: string; end_time?: string }): Promise<import('./types').DetectionMatchesResponse> {
    return this._detections.getDetectionMatches(id, params);
  }

  /** NAN-498 — disposition rollup for the Matches hero FP tile. */
  async getRuleDispositionStats(
    ruleId: string,
    days?: number,
  ): Promise<import('./types').DispositionStatsResponse> {
    return this._detections.getRuleDispositionStats(ruleId, days);
  }

  /** NAN-501 — parsed nPL predicates for the Matches detail Rule conditions card. */
  async getRulePredicates(ruleId: string): Promise<import('./types').RulePredicatesResponse> {
    return this._detections.getRulePredicates(ruleId);
  }

  async importDetections(data: string, format: 'yaml' | 'json'): Promise<{ imported: number }> {
    return this._detections.importDetections(data, format);
  }

  async exportDetections(format: 'yaml' | 'json'): Promise<string> {
    return this._detections.exportDetections(format);
  }

  // Alerts
  async listAlerts(params?: Parameters<DetectionsApi['listAlerts']>[0]): Promise<import('./types').Alert[]> {
    return this._detections.listAlerts(params);
  }

  async getAlert(id: string): Promise<import('./types').Alert> {
    return this._detections.getAlert(id);
  }

  async getAlertCounts(kinds?: string[]): Promise<import('./types').AlertCounts> {
    return this._detections.getAlertCounts(kinds);
  }

  async getAlertVelocity(hours?: number, kinds?: string[]): Promise<import('./types').AlertVelocityBucket[]> {
    return this._detections.getAlertVelocity(hours, kinds);
  }

  async acknowledgeAlert(id: string): Promise<import('./types').Alert> {
    return this._detections.acknowledgeAlert(id);
  }

  async closeAlert(id: string, request: import('./types').CloseAlertRequest): Promise<import('./types').Alert> {
    return this._detections.closeAlert(id, request);
  }

  async assignAlert(id: string, assignedTo: string): Promise<import('./types').Alert> {
    return this._detections.assignAlert(id, assignedTo);
  }

  async bulkAlerts(request: import('./types').BulkAlertRequest): Promise<{ updated: number }> {
    return this._detections.bulkAlerts(request);
  }

  async bulkUpdateRules(request: import('./types').BulkUpdateRulesRequest): Promise<import('./types').BulkUpdateRulesResponse> {
    return this._detections.bulkUpdateRules(request);
  }

  // Folder settings (NAN-730)
  async getFolderSettings(): Promise<{ icons: Record<string, string> }> {
    return this._detections.getFolderSettings();
  }
  async setFolderIcon(name: string, icon: string): Promise<{ name: string; icon: string }> {
    return this._detections.setFolderIcon(name, icon);
  }
  async clearFolderIcon(name: string): Promise<void> {
    return this._detections.clearFolderIcon(name);
  }

  // Fields
  async getFieldValues(name: string, limit: number = 10): Promise<[string, number][]> {
    return this._core.getFieldValues(name, limit);
  }

  async getExtFieldNames(query?: string, start?: string, end?: string): Promise<string[]> {
    return this._core.getExtFieldNames(query, start, end);
  }

  async getSourceTypes(timeRange?: { start: string; end: string }): Promise<[string, number][]> {
    return this._core.getSourceTypes(timeRange);
  }

  async getSchemaFields(): ReturnType<CoreApi['getSchemaFields']> {
    return this._core.getSchemaFields();
  }

  // Credentials
  async listCredentials(): Promise<import('./types').CredentialListResponse> {
    return this._credentials.listCredentials();
  }

  async getCredential(id: string): Promise<import('./types').CloudCredential> {
    return this._credentials.getCredential(id);
  }

  async createCredential(request: import('./types').CreateCloudCredentialRequest): Promise<import('./types').CloudCredential> {
    return this._credentials.createCredential(request);
  }

  async updateCredential(id: string, request: import('./types').UpdateCloudCredentialRequest): Promise<import('./types').CloudCredential> {
    return this._credentials.updateCredential(id, request);
  }

  async deleteCredential(id: string): Promise<{ deleted: boolean; id: string }> {
    return this._credentials.deleteCredential(id);
  }

  async listCredentialsByProvider(provider: 'aws_s3' | 'azure_blob'): Promise<import('./types').CredentialListResponse> {
    return this._credentials.listCredentialsByProvider(provider);
  }

  async rotateCredential(
    id: string,
    request: import('./types').RotateCredentialRequest,
  ): Promise<import('./types').CredentialRotationResponse> {
    return this._credentials.rotateCredential(id, request);
  }

  async listCredentialVersions(
    id: string,
  ): Promise<import('./types').CredentialVersionListResponse> {
    return this._credentials.listCredentialVersions(id);
  }

  async rollbackCredential(
    id: string,
    request: import('./types').RollbackCredentialRequest,
  ): Promise<import('./types').CredentialRotationResponse> {
    return this._credentials.rollbackCredential(id, request);
  }

  // meloD
  async melodChat(request: import('./types').MelodChatRequest): Promise<import('./types').MelodJobStartResponse> {
    return this._melod.melodChat(request);
  }

  async melodCreateParser(request: import('./types').MelodCreateParserRequest): Promise<import('./types').MelodJobStartResponse> {
    return this._melod.melodCreateParser(request);
  }

  melodCreateParserStreaming(
    request: import('./types').MelodCreateParserRequest,
    onProgress: (event: import('./types').ParserProgressEvent) => void,
    onComplete: (parser: import('./types').GeneratedParser | null, error?: string) => void
  ): AbortController {
    return this._melod.melodCreateParserStreaming(request, onProgress, onComplete);
  }

  async melodBuildQuery(request: import('./types').MelodBuildQueryRequest): Promise<import('./types').MelodJobStartResponse> {
    return this._melod.melodBuildQuery(request);
  }

  async correctQuery(request: import('./types').CorrectQueryRequest): Promise<import('./types').CorrectQueryResponse> {
    return this._melod.correctQuery(request);
  }

  async reviewQuery(request: import('./types').ReviewQueryRequest): Promise<import('./types').ReviewQueryResponse> {
    return this._melod.reviewQuery(request);
  }

  async melodCreateDetection(request: import('./types').MelodCreateDetectionRequest): Promise<import('./types').MelodJobStartResponse> {
    return this._melod.melodCreateDetection(request);
  }

  async melodSummarize(request: import('./types').MelodSummarizeRequest): Promise<import('./types').MelodJobStartResponse> {
    return this._melod.melodSummarize(request);
  }

  async melodTuneDetection(request: import('./types').MelodTuneDetectionRequest): Promise<import('./types').MelodJobStartResponse> {
    return this._melod.melodTuneDetection(request);
  }

  async melodEditParser(request: import('./types').MelodEditParserRequest): Promise<import('./types').MelodJobStartResponse> {
    return this._melod.melodEditParser(request);
  }

  async fetchUrlForDetection(url: string): Promise<import('./types').FetchUrlForDetectionResponse> {
    return this._melod.fetchUrlForDetection(url);
  }

  async generateDetectionHints(request: import('./types').GenerateDetectionHintsRequest): Promise<import('./types').MelodJobStartResponse> {
    return this._melod.generateDetectionHints(request);
  }

  // AI Providers (LiteLLM multi-provider support)
  async getAiAvailability(): Promise<import('./types').AiAvailability> {
    return this._melod.getAiAvailability();
  }

  async listAiProviders(): Promise<import('./types').ProviderCredentials[]> {
    return this._melod.listAiProviders();
  }

  async getAiProvider(provider: string): Promise<import('./types').ProviderCredentials> {
    return this._melod.getAiProvider(provider);
  }

  async updateAiProvider(provider: string, request: import('./types').UpdateProviderCredentialsRequest): Promise<import('./types').ProviderCredentials> {
    return this._melod.updateAiProvider(provider, request);
  }

  async validateAiProvider(provider: string): Promise<{ success: boolean; message: string }> {
    return this._melod.validateAiProvider(provider);
  }

  // Agent Model Configuration
  async listAgentModelConfigs(): Promise<import('./types').AgentModelConfig[]> {
    return this._melod.listAgentModelConfigs();
  }

  async getAgentModelConfig(agentId: string): Promise<import('./types').AgentModelConfig> {
    return this._melod.getAgentModelConfig(agentId);
  }

  async updateAgentModelConfig(agentId: string, request: import('./types').UpdateAgentModelConfigRequest): Promise<import('./types').AgentModelConfig> {
    return this._melod.updateAgentModelConfig(agentId, request);
  }

  // Available Models
  async listAvailableModels(): Promise<import('./types').AvailableModel[]> {
    return this._melod.listAvailableModels();
  }

  async listAllAvailableModels(): Promise<import('./types').AvailableModel[]> {
    return this._melod.listAllAvailableModels();
  }

  async createAvailableModel(request: import('./types').CreateAvailableModelRequest): Promise<import('./types').AvailableModel> {
    return this._melod.createAvailableModel(request);
  }

  async updateAvailableModel(modelId: string, request: import('./types').UpdateAvailableModelRequest): Promise<import('./types').AvailableModel> {
    return this._melod.updateAvailableModel(modelId, request);
  }

  async deleteAvailableModel(modelId: string): Promise<{ deleted: boolean }> {
    return this._melod.deleteAvailableModel(modelId);
  }

  // Model Catalog Sync
  async syncModelCatalog(): Promise<import('./types').ModelCatalogSyncResult> {
    return this._melod.syncModelCatalog();
  }

  async getModelCatalogStatus(): Promise<import('./types').ModelCatalogStatus> {
    return this._melod.getModelCatalogStatus();
  }

  // Core / Ingestion
  async ingestEvent(event: Record<string, unknown>): Promise<{ success: boolean; count: number; alerts_generated?: number }> {
    return this._core.ingestEvent(event);
  }

  // System
  async getSystemOverview(hours?: number): Promise<import('./types').SystemOverview> {
    return this._core.getSystemOverview(hours);
  }

  async getSystemConfig(): Promise<import('./types').SystemConfig> {
    return this._core.getSystemConfig();
  }

  // Developer Settings (Scheduler Control)
  async getDeveloperSettings(): Promise<import('./types').DeveloperSettings> {
    return this._core.getDeveloperSettings();
  }

  async updateDeveloperSettings(request: import('./types').UpdateDeveloperSettingsRequest): Promise<import('./types').DeveloperSettings> {
    return this._core.updateDeveloperSettings(request);
  }

  // Tuning
  async getTuningSettings(ruleId: string): Promise<import('./types').TuningSettings> {
    return this._tuning.getTuningSettings(ruleId);
  }

  async updateTuningSettings(ruleId: string, settings: import('./types').TuningSettings): Promise<import('./types').TuningSettings> {
    return this._tuning.updateTuningSettings(ruleId, settings);
  }

  async listTuningProposals(): Promise<import('@/enterprise/api/tuning').TuningProposal[]> {
    return this._tuning.listProposals();
  }

  async listTuningLogs(): Promise<import('@/enterprise/api/tuning').TuningLogEntry[]> {
    return this._tuning.listLogs();
  }

  async getTuningProposal(id: string): Promise<import('@/enterprise/api/tuning').TuningProposal> {
    return this._tuning.getProposal(id);
  }

  async approveTuningProposal(
    id: string,
    opts?: { comment?: string; modified_query?: string },
  ): Promise<import('@/enterprise/api/tuning').ApprovalResponse> {
    return this._tuning.approveProposal(id, opts);
  }

  async rejectTuningProposal(
    id: string,
    reason: string,
  ): Promise<import('@/enterprise/api/tuning').RejectionResponse> {
    return this._tuning.rejectProposal(id, reason);
  }

  // Cases
  async listCases(params?: import('./types').CaseFilter): Promise<import('./types').CaseListResponse> {
    return this._cases.listCases(params);
  }

  // NAN-1093: Signal Inbox aggregation endpoints — see CasesApi.
  async getInboxCounts(params?: {
    queue_group?: string;
    groups?: string[];
  }): Promise<import('./types').InboxCountsResponse> {
    return this._cases.getInboxCounts(params);
  }

  async getInboxIncidents(params?: {
    queue_group?: string;
  }): Promise<import('./types').InboxIncidentsResponse> {
    return this._cases.getInboxIncidents(params);
  }

  async getMyCases(limit?: number): Promise<import('./types').CaseSummary[]> {
    return this._cases.getMyCases(limit);
  }

  async getCaseStats(): Promise<import('./types').CaseStats> {
    return this._cases.getCaseStats();
  }

  async createCase(request: import('./types').CreateCaseRequest): Promise<{ case: import('./types').Case; message: string }> {
    return this._cases.createCase(request);
  }

  async getCase(id: string): Promise<import('./types').CaseFullResponse> {
    return this._cases.getCase(id);
  }

  async updateCase(id: string, request: import('./types').UpdateCaseRequest): Promise<import('./types').Case> {
    return this._cases.updateCase(id, request);
  }

  async deleteCase(id: string): Promise<{ message: string }> {
    return this._cases.deleteCase(id);
  }

  async addAlertToCase(caseId: string, request: import('./types').AddAlertToCaseRequest): Promise<{ message: string }> {
    return this._cases.addAlertToCase(caseId, request);
  }

  async removeAlertFromCase(caseId: string, alertId: string): Promise<{ message: string }> {
    return this._cases.removeAlertFromCase(caseId, alertId);
  }

  async getCaseWall(caseId: string, limit?: number, offset?: number): Promise<import('./types').CaseWallEntry[]> {
    return this._cases.getCaseWall(caseId, limit, offset);
  }

  async addCaseWallEntry(caseId: string, request: import('./types').AddWallEntryRequest): Promise<import('./types').CaseWallEntry> {
    return this._cases.addCaseWallEntry(caseId, request);
  }

  async assignCase(caseId: string, assignedTo: string | null, assignedGroup?: string | null): Promise<import('./types').Case> {
    return this._cases.assignCase(caseId, assignedTo, assignedGroup);
  }

  async escalateCase(caseId: string, request: import('./types').EscalateCaseRequest): Promise<import('./types').Case> {
    return this._cases.escalateCase(caseId, request);
  }

  async changeCaseStatus(caseId: string, request: import('./types').ChangeCaseStatusRequest): Promise<import('./types').Case> {
    return this._cases.changeCaseStatus(caseId, request);
  }

  async createHandoff(caseId: string, request: import('./types').CreateHandoffRequest): Promise<import('./types').CaseHandoff> {
    return this._cases.createHandoff(caseId, request);
  }

  async acceptHandoff(caseId: string, handoffId: string): Promise<import('./types').CaseHandoff> {
    return this._cases.acceptHandoff(caseId, handoffId);
  }

  async bounceHandoff(caseId: string, handoffId: string, request: import('./types').BounceHandoffRequest): Promise<import('./types').CaseHandoff> {
    return this._cases.bounceHandoff(caseId, handoffId, request);
  }

  async cancelHandoff(caseId: string, handoffId: string): Promise<import('./types').CaseHandoff> {
    return this._cases.cancelHandoff(caseId, handoffId);
  }

  // NAN-420: collab-presence heartbeat for the case detail page
  async postCasePresenceHeartbeat(
    caseId: string,
  ): Promise<import('./types').PresenceHeartbeatResponse> {
    return this._cases.postCasePresenceHeartbeat(caseId);
  }

  // NAN-417: Incidents
  async createIncident(request: import('./types').CreateIncidentRequest): Promise<import('./types').Incident> {
    return this._incidents.createIncident(request);
  }

  async listIncidents(params?: { status?: string; limit?: number; offset?: number }): Promise<import('./types').IncidentListResponse> {
    return this._incidents.listIncidents(params);
  }

  async getIncident(id: string): Promise<import('./types').IncidentWithCases> {
    return this._incidents.getIncident(id);
  }

  async addCaseToIncident(incidentId: string, request: import('./types').AddCaseToIncidentRequest): Promise<void> {
    return this._incidents.addCaseToIncident(incidentId, request);
  }

  async removeCaseFromIncident(incidentId: string, caseId: string): Promise<void> {
    return this._incidents.removeCaseFromIncident(incidentId, caseId);
  }

  async bulkChangeCaseStatus(request: import('./types').BulkChangeCaseStatusRequest): Promise<import('./types').BulkChangeCaseStatusResponse> {
    return this._cases.bulkChangeCaseStatus(request);
  }

  // NAN-421: single-call bulk assign for the Cases list page.
  async bulkAssignCases(request: import('./types').BulkAssignRequest): Promise<import('./types').BulkAssignResponse> {
    return this._cases.bulkAssignCases(request);
  }

  async mergeCases(targetCaseId: string, sourceCaseIds: string[]): Promise<import('./types').MergeCasesResponse> {
    return this._cases.mergeCases(targetCaseId, sourceCaseIds);
  }

  async getRelatedCases(caseId: string): Promise<import('./types').RelatedCaseSummary[]> {
    return this._cases.getRelatedCases(caseId);
  }

  // NAN-431: manual relation linking — analyst escape hatch for auto-detector misses.
  async linkRelatedCase(
    caseId: string,
    target: { targetCaseId?: string; targetCaseNumber?: number },
    reason?: string,
  ): Promise<void> {
    return this._cases.linkRelatedCase(caseId, target, reason);
  }

  async unlinkRelatedCase(caseId: string, targetCaseId: string): Promise<void> {
    return this._cases.unlinkRelatedCase(caseId, targetCaseId);
  }

  // NAN-421: duplicate-candidate detector (row-level hint on Cases list).
  async getDuplicateCandidates(caseId: string): Promise<import('./types').DuplicateCandidate[]> {
    return this._cases.getDuplicateCandidates(caseId);
  }

  async shareCase(caseId: string, request: import('./types').ShareCaseRequest): Promise<import('./types').CaseShareResult> {
    return this._cases.shareCase(caseId, request);
  }

  async listGroupingRules(): Promise<import('./types').CaseGroupingRule[]> {
    return this._cases.listGroupingRules();
  }

  async createGroupingRule(request: import('./types').CreateGroupingRuleRequest): Promise<import('./types').CaseGroupingRule> {
    return this._cases.createGroupingRule(request);
  }

  async updateGroupingRule(id: string, request: import('./types').UpdateGroupingRuleRequest): Promise<import('./types').CaseGroupingRule> {
    return this._cases.updateGroupingRule(id, request);
  }

  async deleteGroupingRule(id: string): Promise<{ message: string }> {
    return this._cases.deleteGroupingRule(id);
  }

  async getCaseSettings(): Promise<import('./types').CaseSettings> {
    return this._cases.getCaseSettings();
  }

  async updateCaseSettings(request: import('./types').UpdateCaseSettingsRequest): Promise<import('./types').CaseSettings> {
    return this._cases.updateCaseSettings(request);
  }

  // NAN-426 / NAN-427 — Queues + routing rules. Read methods (listQueues /
  // listMyQueues / getQueue / listQueueRoutingRules) are open to cases:view;
  // write methods (create/update/delete/preview) require settings:system.
  async listQueues(): Promise<import('./types').QueueWithMembership[]> {
    return this._queues.listQueues();
  }

  async listMyQueues(): Promise<import('./types').QueueWithMembership[]> {
    return this._queues.listMyQueues();
  }

  async getQueue(id: string): Promise<import('./types').QueueWithMembership> {
    return this._queues.getQueue(id);
  }

  async createQueue(input: import('./types').NewQueue): Promise<import('./types').Queue> {
    return this._queues.createQueue(input);
  }

  async updateQueue(id: string, input: import('./types').QueueUpdate): Promise<import('./types').Queue> {
    return this._queues.updateQueue(id, input);
  }

  async deleteQueue(id: string): Promise<void> {
    return this._queues.deleteQueue(id);
  }

  async listQueueRoutingRules(): Promise<import('./types').QueueRoutingRule[]> {
    return this._queues.listQueueRoutingRules();
  }

  async createQueueRoutingRule(
    input: import('./types').NewQueueRoutingRule,
  ): Promise<import('./types').QueueRoutingRule> {
    return this._queues.createQueueRoutingRule(input);
  }

  async updateQueueRoutingRule(
    id: string,
    input: import('./types').QueueRoutingRuleUpdate,
  ): Promise<import('./types').QueueRoutingRule> {
    return this._queues.updateQueueRoutingRule(id, input);
  }

  async deleteQueueRoutingRule(id: string): Promise<void> {
    return this._queues.deleteQueueRoutingRule(id);
  }

  async previewQueueRouting(
    input: import('./types').QueueRoutingPreviewRequest,
  ): Promise<import('./types').QueueRoutingPreviewResponse> {
    return this._queues.previewQueueRouting(input);
  }

  async getGroupMembers(groupId: string): Promise<import('./types').GroupMembersResponse> {
    return this._queues.getGroupMembers(groupId);
  }

  // Notebooks
  async listNotebooks(filter?: 'my' | 'shared' | 'all', status?: string): Promise<import('./types').NotebookSummary[]> {
    return this._notebooks.listNotebooks(filter, status);
  }

  async getNotebook(id: string): Promise<import('./types').NotebookResponse> {
    return this._notebooks.getNotebook(id);
  }

  async getActiveNotebook(): Promise<import('./types').NotebookWithOwner | null> {
    return this._notebooks.getActiveNotebook();
  }

  async createNotebook(request: import('./types').CreateNotebookRequest): Promise<import('./types').Notebook> {
    return this._notebooks.createNotebook(request);
  }

  async updateNotebook(id: string, request: import('./types').UpdateNotebookRequest): Promise<import('./types').Notebook> {
    return this._notebooks.updateNotebook(id, request);
  }

  async deleteNotebook(id: string): Promise<{ success: boolean }> {
    return this._notebooks.deleteNotebook(id);
  }

  async getNotebookEntries(notebookId: string, limit?: number, offset?: number): Promise<import('./types').NotebookEntryWithCreator[]> {
    return this._notebooks.getNotebookEntries(notebookId, limit, offset);
  }

  async addNotebookEntry(notebookId: string, request: import('./types').AddEntryRequest): Promise<import('./types').NotebookEntry> {
    return this._notebooks.addNotebookEntry(notebookId, request);
  }

  async deleteNotebookEntry(notebookId: string, entryId: string): Promise<{ success: boolean }> {
    return this._notebooks.deleteNotebookEntry(notebookId, entryId);
  }

  async getNotebookShares(notebookId: string): Promise<import('./types').NotebookShareWithNames[]> {
    return this._notebooks.getNotebookShares(notebookId);
  }

  async addNotebookShare(notebookId: string, request: import('./types').AddShareRequest): Promise<import('./types').NotebookShareWithNames> {
    return this._notebooks.addNotebookShare(notebookId, request);
  }

  async deleteNotebookShare(notebookId: string, shareId: string): Promise<{ success: boolean }> {
    return this._notebooks.deleteNotebookShare(notebookId, shareId);
  }

  async getCaseNotebook(caseId: string): Promise<import('./types').NotebookWithOwner | null> {
    return this._notebooks.getCaseNotebook(caseId);
  }

  async linkNotebookToCase(caseId: string, notebookId: string): Promise<import('./types').Notebook> {
    return this._notebooks.linkNotebookToCase(caseId, notebookId);
  }

  async unlinkNotebookFromCase(caseId: string): Promise<{ success: boolean }> {
    return this._notebooks.unlinkNotebookFromCase(caseId);
  }

  async getRelatedNotebooksForCase(caseId: string): Promise<import('./types').RelatedNotebook[]> {
    return this._notebooks.getRelatedNotebooksForCase(caseId);
  }

  async mergeNotebookIntoCase(caseId: string, sourceNotebookId: string): Promise<{ message: string; entries_merged: number }> {
    return this._notebooks.mergeNotebookIntoCase(caseId, sourceNotebookId);
  }

  async getNotebookReferences(notebookId: string): Promise<import('./types').NotebookReference[]> {
    return this._notebooks.getNotebookReferences(notebookId);
  }

  async addNotebookReference(notebookId: string, request: import('./types').AddReferenceRequest): Promise<import('./types').NotebookReference> {
    return this._notebooks.addNotebookReference(notebookId, request);
  }

  async deleteNotebookReference(notebookId: string, referenceId: string): Promise<{ success: boolean }> {
    return this._notebooks.deleteNotebookReference(notebookId, referenceId);
  }

  async findNotebooksByReference(referenceType: string, referenceId: string): Promise<import('./types').NotebookSummary[]> {
    return this._notebooks.findNotebooksByReference(referenceType, referenceId);
  }

  async summarizeNotebook(notebookId: string, entries: Array<{ entry_type: string; content: Record<string, unknown>; created_at: string }>): Promise<import('./types').MelodJobStartResponse> {
    return this._notebooks.summarizeNotebook(notebookId, entries);
  }

  async generateQuerySuggestions(request: import('./types').GenerateQuerySuggestionsRequest): Promise<import('./types').MelodJobStartResponse> {
    return this._notebooks.generateQuerySuggestions(request);
  }

  async analyzeNoteForQueries(request: import('./types').AnalyzeNoteRequest): Promise<import('./types').MelodJobStartResponse> {
    return this._notebooks.analyzeNoteForQueries(request);
  }

  async generateInvestigationTimeline(
    request: import('./types').GenerateInvestigationTimelineRequest
  ): Promise<import('./types').MelodJobStartResponse> {
    return this._notebooks.generateInvestigationTimeline(request);
  }

  // Notebook Tabs
  async listTabs(): Promise<import('./types').NotebookTabWithDetails[]> {
    return this._notebooks.listTabs();
  }

  async openTab(notebookId: string): Promise<import('./types').NotebookTab> {
    return this._notebooks.openTab(notebookId);
  }

  async closeTab(tabId: string): Promise<{ success: boolean }> {
    return this._notebooks.closeTab(tabId);
  }

  async updateTab(tabId: string, request: import('./types').UpdateTabRequest): Promise<import('./types').NotebookTab> {
    return this._notebooks.updateTab(tabId, request);
  }

  async reorderTabs(tabIds: string[]): Promise<{ success: boolean }> {
    return this._notebooks.reorderTabs(tabIds);
  }

  async setActiveTab(notebookId: string): Promise<import('./types').NotebookTab> {
    return this._notebooks.setActiveTab(notebookId);
  }

  // Notebook Merge & Link
  async mergeNotebooks(targetId: string, sourceIds: string[]): Promise<import('./types').MergeNotebooksResponse> {
    return this._notebooks.mergeNotebooks(targetId, sourceIds);
  }

  async unlinkFromCase(notebookId: string): Promise<import('./types').Notebook> {
    return this._notebooks.unlinkFromCase(notebookId);
  }

  async linkToCase(caseId: string, notebookId: string): Promise<import('./types').Notebook> {
    return this._notebooks.linkToCase(caseId, notebookId);
  }

  async notebookChat(notebookId: string, request: import('./types').NotebookChatRequest): Promise<import('./types').MelodJobStartResponse> {
    return this._notebooks.notebookChat(notebookId, request);
  }

  notebookChatStream(notebookId: string, request: import('./types').NotebookChatRequest, callbacks: import('./types').NotebookChatStreamCallbacks): AbortController {
    return this._notebooks.notebookChatStream(notebookId, request, callbacks);
  }

  // Log Sources
  async listLogSources(): Promise<import('./types').LogSource[]> {
    return this._logSources.listLogSources();
  }

  async getLogSource(id: string): Promise<import('./types').LogSource> {
    return this._logSources.getLogSource(id);
  }

  async createLogSource(request: import('./types').NewLogSource): Promise<import('./types').LogSource> {
    return this._logSources.createLogSource(request);
  }

  async updateLogSource(id: string, request: import('./types').UpdateLogSource): Promise<import('./types').LogSource> {
    return this._logSources.updateLogSource(id, request);
  }

  async deleteLogSource(id: string): Promise<{ deleted: boolean }> {
    return this._logSources.deleteLogSource(id);
  }

  async toggleLogSource(id: string, enabled: boolean): Promise<import('./types').LogSource> {
    return this._logSources.toggleLogSource(id, enabled);
  }

  async deployLogSource(id: string): Promise<import('./types').EnhancedDeploymentResponse> {
    return this._logSources.deployLogSource(id);
  }

  async undeployLogSource(id: string): Promise<import('./types').EnhancedDeploymentResponse> {
    return this._logSources.undeployLogSource(id);
  }

  async getLogSourceHealth(id: string): Promise<import('./types').LogSourceHealth> {
    return this._logSources.getLogSourceHealth(id);
  }

  async getIngestionHistory(hours?: number): Promise<import('./types').IngestionHistoryPoint[]> {
    return this._logSources.getIngestionHistory(hours);
  }

  async validateLogSource(id: string): Promise<import('./types').LogSourceVrlValidationResult> {
    return this._logSources.validateLogSource(id);
  }

  async validateLogSourceVrl(vrlCode: string): Promise<import('./types').LogSourceVrlValidationResult> {
    return this._logSources.validateLogSourceVrl(vrlCode);
  }

  async testLogSourceVrl(
    vrlCode: string,
    sampleLog: string,
    extensionVrl?: string,
  ): Promise<import('./types').LogSourceTestResult> {
    return this._logSources.testLogSourceVrl(vrlCode, sampleLog, extensionVrl);
  }

  async testLogSourceVrlLive(vrlCode: string, sourceType: string, currentVrl?: string, limit?: number): Promise<import('./types').LiveTestResult[]> {
    return this._logSources.testLogSourceVrlLive(vrlCode, sourceType, currentVrl, limit);
  }

  async deployAllLogSources(): Promise<{ deployed: boolean }> {
    return this._logSources.deployAllLogSources();
  }

  async getLogSourceDeployments(id: string): Promise<import('./types').LogSourceDeployment[]> {
    return this._logSources.getLogSourceDeployments(id);
  }

  async getLogSourceVersions(id: string): Promise<import('./types').LogSourceVersion[]> {
    return this._logSources.getLogSourceVersions(id);
  }

  async publishLogSource(id: string): Promise<import('./types').EnhancedDeploymentResponse> {
    return this._logSources.publishLogSource(id);
  }

  async revertLogSourceVersion(id: string, versionId: number): Promise<import('./types').LogSourceVersion> {
    return this._logSources.revertLogSourceVersion(id, versionId);
  }

  async validateNamespace(namespace: string): Promise<import('./types').NamespaceValidationResult> {
    return this._logSources.validateNamespace(namespace);
  }

  async discardLogSourceDraft(id: string): Promise<import('./types').LogSource> {
    return this._logSources.discardLogSourceDraft(id);
  }

  async getLogSourceDraftStatus(id: string): Promise<import('./types').LogSourceWithDraftStatus> {
    return this._logSources.getLogSourceDraftStatus(id);
  }

  // Source Configurations
  /**
   * NAN-649: per-driver source-config type metadata. Used by the routing-rule
   * UI to switch between push (HTTP/Vector) and pull (Pub/Sub/Kafka/S3/HEC)
   * shapes and to populate the `match_field` preset dropdown.
   */
  async listSourceConfigTypes(): Promise<import('./types').SourceConfigTypeInfo[]> {
    return this._sourceConfigs.listSourceConfigTypes();
  }

  async listSourceConfigs(params?: {
    config_type?: string;
    enabled?: boolean;
    deployed?: boolean;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<import('./types').SourceConfiguration[]> {
    return this._sourceConfigs.listSourceConfigs(params);
  }

  async getSourceConfig(id: string): Promise<import('./types').SourceConfiguration> {
    return this._sourceConfigs.getSourceConfig(id);
  }

  async getSourceConfigWithRules(id: string): Promise<import('./types').SourceConfigurationWithRules> {
    return this._sourceConfigs.getSourceConfigWithRules(id);
  }

  async createSourceConfig(request: import('./types').NewSourceConfiguration): Promise<import('./types').SourceConfiguration> {
    return this._sourceConfigs.createSourceConfig(request);
  }

  async updateSourceConfig(id: string, request: import('./types').UpdateSourceConfiguration): Promise<import('./types').SourceConfiguration> {
    return this._sourceConfigs.updateSourceConfig(id, request);
  }

  async deleteSourceConfig(id: string): Promise<{ deleted: boolean }> {
    return this._sourceConfigs.deleteSourceConfig(id);
  }

  async toggleSourceConfig(id: string, enabled: boolean): Promise<import('./types').SourceConfiguration> {
    return this._sourceConfigs.toggleSourceConfig(id, enabled);
  }

  async deploySourceConfig(id: string): Promise<import('./types').SourceConfigDeploymentResult> {
    return this._sourceConfigs.deploySourceConfig(id);
  }

  async undeploySourceConfig(id: string): Promise<import('./types').SourceConfigDeploymentResult> {
    return this._sourceConfigs.undeploySourceConfig(id);
  }

  async deployAllSourceConfigs(): Promise<import('./types').SourceConfigDeploymentResult[]> {
    return this._sourceConfigs.deployAllSourceConfigs();
  }

  async getSourceConfigDeployments(id: string): Promise<import('./types').SourceConfigDeployment[]> {
    return this._sourceConfigs.getSourceConfigDeployments(id);
  }

  async listRoutingRules(sourceConfigId: string): Promise<import('./types').RoutingRule[]> {
    return this._sourceConfigs.listRoutingRules(sourceConfigId);
  }

  async createRoutingRule(sourceConfigId: string, request: import('./types').NewRoutingRule): Promise<import('./types').RoutingRule> {
    return this._sourceConfigs.createRoutingRule(sourceConfigId, request);
  }

  async updateRoutingRule(sourceConfigId: string, ruleId: string, request: import('./types').UpdateRoutingRule): Promise<import('./types').RoutingRule> {
    return this._sourceConfigs.updateRoutingRule(sourceConfigId, ruleId, request);
  }

  async deleteRoutingRule(sourceConfigId: string, ruleId: string): Promise<{ deleted: boolean }> {
    return this._sourceConfigs.deleteRoutingRule(sourceConfigId, ruleId);
  }

  async reorderRoutingRules(sourceConfigId: string, ruleOrder: string[]): Promise<import('./types').RoutingRule[]> {
    return this._sourceConfigs.reorderRoutingRules(sourceConfigId, ruleOrder);
  }

  async checkRoutingRuleReachability(
    sourceConfigId: string,
    request: import('./types').RoutingRuleReachabilityRequest,
  ): Promise<import('./types').RoutingRuleReachability> {
    return this._sourceConfigs.checkRoutingRuleReachability(sourceConfigId, request);
  }

  // Access Control - Users
  async listUsers(): Promise<import('./types').UserListResponse> {
    return this._accessControl.listUsers();
  }

  async getUser(id: string): Promise<import('./types').UserDetail> {
    return this._accessControl.getUser(id);
  }

  async createUser(request: import('./types').CreateUserRequest): Promise<import('./types').UserDetail> {
    return this._accessControl.createUser(request);
  }

  async updateUser(id: string, request: import('./types').UpdateUserRequest): Promise<import('./types').UserDetail> {
    return this._accessControl.updateUser(id, request);
  }

  async deleteUser(id: string): Promise<void> {
    return this._accessControl.deleteUser(id);
  }

  async unlockUser(id: string): Promise<import('./types').UserDetail> {
    return this._accessControl.unlockUser(id);
  }

  async disableUser(id: string): Promise<import('./types').UserDetail> {
    return this._accessControl.disableUser(id);
  }

  async enableUser(id: string): Promise<import('./types').UserDetail> {
    return this._accessControl.enableUser(id);
  }

  // Access Control - Groups
  async listGroups(): Promise<import('./types').GroupListResponse> {
    return this._accessControl.listGroups();
  }

  async getGroup(id: string): Promise<import('./types').GroupDetail> {
    return this._accessControl.getGroup(id);
  }

  async createGroup(request: import('./types').CreateGroupRequest): Promise<import('./types').GroupDetail> {
    return this._accessControl.createGroup(request);
  }

  async updateGroup(id: string, request: import('./types').UpdateGroupRequest): Promise<import('./types').GroupDetail> {
    return this._accessControl.updateGroup(id, request);
  }

  async deleteGroup(id: string): Promise<void> {
    return this._accessControl.deleteGroup(id);
  }

  // Access Control - Roles
  async listRoles(): Promise<import('./types').RoleListResponse> {
    return this._accessControl.listRoles();
  }

  async getRole(id: string): Promise<import('./types').RoleDetail> {
    return this._accessControl.getRole(id);
  }

  async createRole(request: import('./types').CreateRoleRequest): Promise<import('./types').RoleDetail> {
    return this._accessControl.createRole(request);
  }

  async updateRole(id: string, request: import('./types').UpdateRoleRequest): Promise<import('./types').RoleDetail> {
    return this._accessControl.updateRole(id, request);
  }

  async deleteRole(id: string): Promise<void> {
    return this._accessControl.deleteRole(id);
  }

  async listPermissions(): Promise<import('./types').PermissionInfo[]> {
    return this._accessControl.listPermissions();
  }

  // Access Control - API Keys
  async listApiKeys(): Promise<import('./types').ApiKeyListResponse> {
    return this._accessControl.listApiKeys();
  }

  async createApiKey(request: import('./types').CreateApiKeyRequest): Promise<import('./types').ApiKeyCreatedResponse> {
    return this._accessControl.createApiKey(request);
  }

  async getApiKey(id: string): Promise<import('./types').ApiKeySummary> {
    return this._accessControl.getApiKey(id);
  }

  async getApiKeyUsage(id: string, days = 14): Promise<import('./types').ApiKeyUsageResponse> {
    return this._accessControl.getApiKeyUsage(id, days);
  }

  async updateApiKey(id: string, request: import('./types').UpdateApiKeyRequest): Promise<import('./types').ApiKeySummary> {
    return this._accessControl.updateApiKey(id, request);
  }

  async resetApiKey(id: string): Promise<import('./types').ApiKeyCreatedResponse> {
    return this._accessControl.resetApiKey(id);
  }

  async deleteApiKey(id: string): Promise<void> {
    return this._accessControl.deleteApiKey(id);
  }

  async enableApiKey(id: string): Promise<import('./types').ApiKeySummary> {
    return this._accessControl.enableApiKey(id);
  }

  async disableApiKey(id: string): Promise<import('./types').ApiKeySummary> {
    return this._accessControl.disableApiKey(id);
  }

  // Access Control - Sessions
  async listAllSessions(): Promise<import('./types').SessionListResponse> {
    return this._accessControl.listAllSessions();
  }

  async listMySessions(): Promise<import('./types').SessionListResponse> {
    return this._accessControl.listMySessions();
  }

  async terminateSession(id: string): Promise<void> {
    return this._accessControl.terminateSession(id);
  }

  // Access Control - OIDC Providers
  async getAuthMethodsSettings(): Promise<import('./types').AuthMethodsSettings> {
    return this._accessControl.getAuthMethodsSettings();
  }

  async updateAuthMethodsSettings(
    localPasswordEnabled: boolean,
  ): Promise<import('./types').AuthMethodsSettings> {
    return this._accessControl.updateAuthMethodsSettings(localPasswordEnabled);
  }

  async listOidcProviders(): Promise<import('./types').OidcProviderListResponse> {
    return this._accessControl.listOidcProviders();
  }

  async getOidcProvider(id: string): Promise<import('./types').OidcProviderSummary> {
    return this._accessControl.getOidcProvider(id);
  }

  async createOidcProvider(request: import('./types').CreateOidcProviderRequest): Promise<import('./types').OidcProviderSummary> {
    return this._accessControl.createOidcProvider(request);
  }

  async updateOidcProvider(id: string, request: import('./types').UpdateOidcProviderRequest): Promise<import('./types').OidcProviderSummary> {
    return this._accessControl.updateOidcProvider(id, request);
  }

  async deleteOidcProvider(id: string): Promise<void> {
    return this._accessControl.deleteOidcProvider(id);
  }

  async enableOidcProvider(id: string): Promise<import('./types').OidcProviderSummary> {
    return this._accessControl.enableOidcProvider(id);
  }

  async disableOidcProvider(id: string): Promise<import('./types').OidcProviderSummary> {
    return this._accessControl.disableOidcProvider(id);
  }

  async getOidcGroupMappings(providerId: string): Promise<import('./types').OidcGroupMappingsResponse> {
    return this._accessControl.getOidcGroupMappings(providerId);
  }

  async updateOidcGroupMappings(providerId: string, request: import('./types').UpdateOidcGroupMappingsRequest): Promise<import('./types').OidcGroupMappingsResponse> {
    return this._accessControl.updateOidcGroupMappings(providerId, request);
  }

  async getOidcTokenGroups(providerId: string): Promise<import('./types').OidcTokenGroupsResponse> {
    return this._accessControl.getOidcTokenGroups(providerId);
  }

  // Dashboards
  async listDashboards(filter?: 'my' | 'all'): Promise<import('./types').DashboardSummary[]> {
    return this._dashboards.listDashboards(filter);
  }

  async getDashboard(id: string): Promise<import('./types').Dashboard> {
    return this._dashboards.getDashboard(id);
  }

  async createDashboard(request: import('./types').CreateDashboardRequest): Promise<import('./types').Dashboard> {
    return this._dashboards.createDashboard(request);
  }

  async updateDashboard(id: string, request: import('./types').UpdateDashboardRequest): Promise<import('./types').Dashboard> {
    return this._dashboards.updateDashboard(id, request);
  }

  async deleteDashboard(id: string): Promise<{ success: boolean }> {
    return this._dashboards.deleteDashboard(id);
  }

  async panelQuery(request: import('./types').PanelQueryRequest): Promise<import('./types').PanelQueryResponse> {
    return this._dashboards.panelQuery(request);
  }

  async exportDashboard(id: string): Promise<import('./types').DashboardExport> {
    return this._dashboards.exportDashboard(id);
  }

  async importDashboard(request: import('./types').ImportDashboardRequest): Promise<import('./types').Dashboard> {
    return this._dashboards.importDashboard(request);
  }

  // Storage
  async getStorageOverview(): Promise<import('./types').StorageOverview> {
    return this._storage.getStorageOverview();
  }

  // Risk
  async getRiskConfig(): Promise<import('./types').RiskConfig> {
    return this._risk.getRiskConfig();
  }

  async updateRiskConfig(request: import('./types').UpdateRiskConfigRequest): Promise<import('./types').RiskConfig> {
    return this._risk.updateRiskConfig(request);
  }

  async getRiskDecayConfig(): Promise<import('./types').RiskDecayConfig> {
    return this._risk.getRiskDecayConfig();
  }

  async updateRiskDecayConfig(request: import('./types').UpdateRiskDecayConfigRequest): Promise<import('./types').RiskDecayConfig> {
    return this._risk.updateRiskDecayConfig(request);
  }

  async getRiskNotableConfig(): Promise<import('./types').RiskNotableConfig> {
    return this._risk.getRiskNotableConfig();
  }

  async updateRiskNotableConfig(request: import('./types').RiskNotableConfig): Promise<import('./types').RiskNotableConfig> {
    return this._risk.updateRiskNotableConfig(request);
  }

  async getRiskyEntities(params?: import('./types').RiskEntitiesQuery): Promise<import('./types').RiskEntitiesResponse> {
    return this._risk.getRiskyEntities(params);
  }

  async getRiskOverview(): Promise<import('./types').RiskOverviewResponse> {
    return this._risk.getRiskOverview();
  }

  async getTimeWindowedRiskScores(params?: import('./types').TimeWindowedRiskQuery): Promise<import('./types').TimeWindowedRiskResponse> {
    return this._risk.getTimeWindowedRiskScores(params);
  }

  async clearEntityRisk(request: import('./types').ClearEntityRiskRequest): Promise<import('./types').ClearRiskResponse> {
    return this._risk.clearEntityRisk(request);
  }

  async clearAllRiskScores(): Promise<import('./types').ClearRiskResponse> {
    return this._risk.clearAllRiskScores();
  }

  async getEntityRiskActivity(entities: { entity: string; entity_type: string }[]): Promise<import('./types').EntityActivityResponse> {
    return this._risk.getEntityRiskActivity(entities);
  }

  async getEntityContext(entityType: string, entityValue: string, identities?: string[]): Promise<import('./types').EntityContextResponse> {
    return this._risk.getEntityContext(entityType, entityValue, identities);
  }

  // Dashboard Generation (AI)
  async melodGenerateDashboard(request: import('./types').GenerateDashboardRequest): Promise<import('./types').MelodJobStartResponse> {
    return this._melod.melodGenerateDashboard(request);
  }

  /** @deprecated Use getMelodJobStatus instead */
  async melodGetDashboardJob(jobId: string): Promise<import('./types').MelodJobStatusResponse> {
    return this._melod.melodGetDashboardJob(jobId);
  }

  async melodRefineDashboard(request: import('./types').RefineDashboardRequest): Promise<import('./types').MelodJobStartResponse> {
    return this._melod.melodRefineDashboard(request);
  }

  // Generic meloD job polling
  async getMelodJobStatus(jobId: string): Promise<import('./types').MelodJobStatusResponse> {
    return this._melod.getMelodJobStatus(jobId);
  }

  // Notifications
  async getNotifications(limit?: number, unreadOnly?: boolean): Promise<import('./types').NotificationListResponse> {
    return this._notifications.getNotifications(limit, unreadOnly);
  }

  async getUnreadNotificationCount(): Promise<import('./types').UnreadCountResponse> {
    return this._notifications.getUnreadNotificationCount();
  }

  async markNotificationRead(id: string): Promise<import('./types').Notification> {
    return this._notifications.markNotificationRead(id);
  }

  async markAllNotificationsRead(): Promise<import('./types').MarkAllReadResponse> {
    return this._notifications.markAllNotificationsRead();
  }

  // Feedback
  async createFeedback(request: import('./types').CreateFeedbackRequest): Promise<import('./types').Feedback> {
    return this._feedback.createFeedback(request);
  }

  async listFeedback(options?: { category?: string; status?: string; limit?: number; offset?: number }): Promise<import('./types').FeedbackListResponse> {
    return this._feedback.listFeedback(options);
  }

  async updateFeedback(id: string, request: import('./types').UpdateFeedbackRequest): Promise<import('./types').Feedback> {
    return this._feedback.updateFeedback(id, request);
  }

  async deleteFeedback(id: string): Promise<{ success: boolean }> {
    return this._feedback.deleteFeedback(id);
  }

  // Enrichment
  async listEnrichmentSources(): Promise<import('./types').EnrichmentSource[]> {
    return this._enrichment.listEnrichmentSources();
  }

  async configureIpinfo(config: import('./types').IpinfoConfig): Promise<{ success: boolean; message: string }> {
    return this._enrichment.configureIpinfo(config);
  }

  async syncIpinfo(): Promise<import('./enrichment').SyncStartResult> {
    return this._enrichment.syncIpinfo();
  }

  async enableEnrichmentSource(sourceId: string): Promise<{ success: boolean; message: string }> {
    return this._enrichment.enableEnrichmentSource(sourceId);
  }

  async disableEnrichmentSource(sourceId: string): Promise<{ success: boolean; message: string }> {
    return this._enrichment.disableEnrichmentSource(sourceId);
  }

  async getEnrichmentStats(): Promise<Record<string, { total: number; last_updated?: string }>> {
    return this._enrichment.getEnrichmentStats();
  }

  async lookupIp(ip: string): Promise<import('./types').IpLookupResult> {
    return this._enrichment.lookupIp(ip);
  }

  async getAutoSyncConfig(): Promise<import('./types').AutoSyncConfig> {
    return this._enrichment.getAutoSyncConfig();
  }

  async configureAutoSync(config: { enabled: boolean; interval_hours?: number }): Promise<import('./types').AutoSyncConfig> {
    return this._enrichment.configureAutoSync(config);
  }

  async listAgentEnrichmentProviders(): Promise<import('./types').ListAgentEnrichmentProvidersResponse> {
    return this._enrichment.listAgentEnrichmentProviders();
  }

  async getAgentEnrichmentProvider(providerId: string): Promise<import('./types').AgentEnrichmentProvider> {
    return this._enrichment.getAgentEnrichmentProvider(providerId);
  }

  async createAgentEnrichmentProvider(request: import('./types').CreateAgentEnrichmentProviderRequest): Promise<import('./types').AgentEnrichmentProvider> {
    return this._enrichment.createAgentEnrichmentProvider(request);
  }

  async updateAgentEnrichmentProvider(providerId: string, request: import('./types').UpdateAgentEnrichmentProviderRequest): Promise<import('./types').AgentEnrichmentProvider> {
    return this._enrichment.updateAgentEnrichmentProvider(providerId, request);
  }

  async deleteAgentEnrichmentProvider(providerId: string): Promise<{ success: boolean; message: string; cache_entries_cleared: number }> {
    return this._enrichment.deleteAgentEnrichmentProvider(providerId);
  }

  async updateAgentEnrichmentCredentials(providerId: string, credentials: Record<string, string>): Promise<{ success: boolean; message: string }> {
    return this._enrichment.updateAgentEnrichmentCredentials(providerId, credentials);
  }

  async testAgentEnrichmentConnection(providerId: string): Promise<{ success: boolean; message: string; response_time_ms?: number; error?: string }> {
    return this._enrichment.testAgentEnrichmentConnection(providerId);
  }

  async getAgentEnrichmentUsage(): Promise<Record<string, { requests_today: number; requests_this_month: number }>> {
    return this._enrichment.getAgentEnrichmentUsage();
  }

  // Identity Providers
  async listIdentityProviders(): Promise<import('./types').ListIdentityProvidersResponse> {
    return this._identity.listProviders();
  }

  async getIdentityProvider(id: string): Promise<import('./types').IdentityProviderSummary> {
    return this._identity.getProvider(id);
  }

  async createIdentityProvider(request: import('./types').CreateIdentityProviderRequest): Promise<import('./types').IdentityProviderSummary> {
    return this._identity.createProvider(request);
  }

  async updateIdentityProvider(id: string, request: import('./types').UpdateIdentityProviderRequest): Promise<import('./types').IdentityProviderSummary> {
    return this._identity.updateProvider(id, request);
  }

  async deleteIdentityProvider(id: string): Promise<{ success: boolean; message: string }> {
    return this._identity.deleteProvider(id);
  }

  async updateIdentityCredentials(id: string, credentials: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
    return this._identity.updateCredentials(id, credentials);
  }

  async testIdentityConnection(id: string): Promise<import('./types').IdentityConnectionTestResponse> {
    return this._identity.testConnection(id);
  }

  async triggerIdentitySync(id: string): Promise<import('./types').IdentitySyncTriggerResponse> {
    return this._identity.triggerSync(id);
  }

  async listIdentityUsers(params?: { provider_id?: string; search?: string; account_status?: string; page?: number; page_size?: number }): Promise<import('./types').IdentityUserListResponse> {
    return this._identity.listUsers(params);
  }

  async getIdentityUser(id: string): Promise<import('./types').IdentityUser> {
    return this._identity.getUser(id);
  }

  async getIdentityStats(): Promise<import('./types').IdentityStats> {
    return this._identity.getStats();
  }

  async lookupIdentityUser(identifier: string): Promise<import('./types').IdentityUser | null> {
    return this._identity.lookupUser(identifier);
  }

  async resolveIpIdentity(ip: string, timestamp?: string): Promise<import('./types').IdentityResolveResponse> {
    return this._identity.resolveIdentity(ip, timestamp);
  }

  // NAN-1111: ThreatFox + TOR Exit Nodes delegate methods and the shared
  // lookupIoc / getIocStats delegates were deleted alongside the legacy
  // backend routes. Both providers moved to the marketplace + Deno
  // (nano-rs/nano-enrichments). See project_ipinfo_lite_stays_native for
  // why IPinfo Lite (above) stays native.

  // Custom Enrichments
  async listCustomEnrichments(enrichmentType?: 'data' | 'agent'): Promise<import('@/enterprise/api/custom-enrichment').CustomEnrichmentSummary[]> {
    return this._customEnrichment.list(enrichmentType);
  }

  async getCustomEnrichment(id: string): Promise<import('@/enterprise/api/custom-enrichment').CustomEnrichmentDetail> {
    return this._customEnrichment.get(id);
  }

  async createCustomEnrichment(request: import('@/enterprise/api/custom-enrichment').CreateCustomEnrichmentRequest): Promise<import('@/enterprise/api/custom-enrichment').CustomEnrichmentDetail> {
    return this._customEnrichment.create(request);
  }

  async updateCustomEnrichment(id: string, request: import('@/enterprise/api/custom-enrichment').UpdateCustomEnrichmentRequest): Promise<import('@/enterprise/api/custom-enrichment').CustomEnrichmentDetail> {
    return this._customEnrichment.update(id, request);
  }

  async deleteCustomEnrichment(id: string): Promise<{ deleted: boolean }> {
    return this._customEnrichment.delete(id);
  }

  async validateCustomEnrichment(id: string, testArtifact?: string, testArtifactType?: string): Promise<import('@/enterprise/api/custom-enrichment').ValidationResponse> {
    return this._customEnrichment.validate(id, testArtifact, testArtifactType);
  }

  async deployCustomEnrichment(id: string): Promise<import('@/enterprise/api/custom-enrichment').CustomEnrichmentDetail> {
    return this._customEnrichment.deploy(id);
  }

  async disableCustomEnrichment(id: string): Promise<import('@/enterprise/api/custom-enrichment').CustomEnrichmentDetail> {
    return this._customEnrichment.disable(id);
  }

  async getCustomEnrichmentVersions(id: string): Promise<import('@/enterprise/api/custom-enrichment').VersionInfo[]> {
    return this._customEnrichment.getVersions(id);
  }

  async getCustomEnrichmentVersionDiff(id: string, version: number): Promise<import('@/enterprise/api/custom-enrichment').VersionDiff> {
    return this._customEnrichment.getVersionDiff(id, version);
  }

  async triggerCustomEnrichmentRun(id: string): Promise<import('@/enterprise/api/custom-enrichment').RunInfo> {
    return this._customEnrichment.triggerRun(id);
  }

  async getCustomEnrichmentRuns(id: string, limit?: number): Promise<import('@/enterprise/api/custom-enrichment').RunInfo[]> {
    return this._customEnrichment.getRuns(id, limit);
  }

  async generateCustomEnrichmentCode(request: import('@/enterprise/api/custom-enrichment').GenerateCodeRequest): Promise<import('@/enterprise/api/custom-enrichment').GenerateCodeResponse> {
    return this._customEnrichment.generateCode(request);
  }

  async getCustomEnrichmentTemplates(): Promise<import('@/enterprise/api/custom-enrichment').CodeTemplates> {
    return this._customEnrichment.getTemplates();
  }

  // Prevalence
  async getHashPrevalence(hash: string): Promise<import('./types').PrevalenceResponse> {
    return this._prevalence.getHashPrevalence(hash);
  }

  async getDomainPrevalence(domain: string): Promise<import('./types').PrevalenceResponse> {
    return this._prevalence.getDomainPrevalence(domain);
  }

  async getBulkPrevalence(request: import('./types').BulkPrevalenceRequest): Promise<import('./types').BulkPrevalenceResponse> {
    return this._prevalence.getBulkPrevalence(request);
  }

  async getRareArtifacts(params?: import('./types').RareArtifactsQuery): Promise<import('./types').ArtifactListResponse> {
    return this._prevalence.getRareArtifacts(params);
  }

  async getNewArtifacts(params?: import('./types').NewArtifactsQuery): Promise<import('./types').ArtifactListResponse> {
    return this._prevalence.getNewArtifacts(params);
  }

  async getArtifactExplorer(params?: import('./types').ArtifactExplorerQuery): Promise<import('./types').ArtifactExplorerResponse> {
    return this._prevalence.getArtifactExplorer(params);
  }

  async getArtifactDetail(artifact: string, window?: string): Promise<import('./types').ArtifactDetailResponse> {
    return this._prevalence.getArtifactDetail(artifact, window);
  }

  async getPrevalenceScatterData(request: import('./types').ScatterPlotRequest): Promise<import('./types').PrevalenceScatterDataResponse> {
    return this._prevalence.getPrevalenceScatterData(request);
  }

  async getPrevalenceSettings(): Promise<import('./types').PrevalenceSettingsResponse> {
    return this._prevalence.getPrevalenceSettings();
  }

  async updatePrevalenceSettings(request: import('./types').UpdatePrevalenceSettingsRequest): Promise<import('./types').PrevalenceSettingsResponse> {
    return this._prevalence.updatePrevalenceSettings(request);
  }

  async getSearchAdmissionConfig(): Promise<import('./types').SearchAdmissionConfig> {
    return this.request('/api/settings/search');
  }

  async updateSearchAdmissionConfig(config: import('./types').SearchAdmissionConfig): Promise<import('./types').SearchAdmissionConfig> {
    return this.request('/api/settings/search', {
      method: 'PUT',
      body: JSON.stringify(config),
    });
  }

  async getSearchQueryLimits(): Promise<import('./types').SearchQueryLimitsConfig> {
    return this.request('/api/settings/search/query-limits');
  }

  async updateSearchQueryLimits(config: import('./types').SearchQueryLimitsConfig): Promise<import('./types').SearchQueryLimitsConfig> {
    return this.request('/api/settings/search/query-limits', {
      method: 'PUT',
      body: JSON.stringify(config),
    });
  }

  async listSearchJobs(): Promise<import('./types').SearchJobSummary[]> {
    return this._search.listSearchJobs();
  }

  async listAdminSearchJobs(): Promise<import('./types').AdminSearchJobsResponse> {
    return this._search.listAdminSearchJobs();
  }

  async getAdminStats(): Promise<import('./types').AdmissionStats> {
    return this._search.getAdminStats();
  }

  async adminCancelSearchJob(jobId: string): Promise<{ cancelled: boolean }> {
    return this._search.adminCancelSearchJob(jobId);
  }

  async getPrevalenceArtifactsForQuery(request: { query: string; time_range: string | { start: string; end: string } }): Promise<{
    hash_points: Array<{
      artifact: string;
      host_count: number;
      first_seen: string;
      last_seen: string;
      total_occurrences: number;
      is_rare: boolean;
      prevalence_score: number;
    }>;
    domain_points: Array<{
      artifact: string;
      host_count: number;
      first_seen: string;
      last_seen: string;
      total_occurrences: number;
      is_rare: boolean;
      prevalence_score: number;
    }>;
    rarity_threshold: number;
  }> {
    return this._prevalence.getPrevalenceArtifactsForQuery(request);
  }

  // Upload
  async previewUpload(file: File, format?: import('./types').FileFormat, delimiter?: string): Promise<import('./types').PreviewResult> {
    return this._upload.previewUpload(file, format, delimiter);
  }

  async getUploadHistory(filter?: import('./types').UploadHistoryFilter): Promise<import('./types').UploadRecord[]> {
    return this._upload.getUploadHistory(filter);
  }

  // Lookup Table Ingestion
  async getLookupIngestion(name: string): Promise<import('./types').ScheduledJob | null> {
    return this._lookupTables.getIngestion(name);
  }

  async upsertLookupIngestion(name: string, request: import('./types').UpsertLookupIngestionRequest): Promise<import('./types').ScheduledJob> {
    return this._lookupTables.upsertIngestion(name, request);
  }

  async deleteLookupIngestion(name: string): Promise<{ success: boolean }> {
    return this._lookupTables.deleteIngestion(name);
  }

  async triggerLookupIngestion(name: string): Promise<import('./types').JobExecution> {
    return this._lookupTables.triggerIngestion(name);
  }

  async enableLookupIngestion(name: string): Promise<import('./types').ScheduledJob> {
    return this._lookupTables.enableIngestion(name);
  }

  async disableLookupIngestion(name: string): Promise<import('./types').ScheduledJob> {
    return this._lookupTables.disableIngestion(name);
  }

  async validateCron(expression: string, previewCount?: number): Promise<import('./types').ValidateCronResponse> {
    return this._lookupTables.validateCron(expression, previewCount);
  }

  // Lookup Tables
  async listLookupTables(): Promise<import('./types').LookupTable[]> {
    return this._lookupTables.listLookupTables();
  }

  async getLookupTable(id: string): Promise<import('./types').LookupTable> {
    return this._lookupTables.getLookupTable(id);
  }

  async createLookupTable(config: import('./types').CreateLookupTableConfig, file: File): Promise<import('./types').CreateLookupTableResponse> {
    return this._lookupTables.createLookupTable(config, file);
  }

  async deleteLookupTable(id: string): Promise<{ success: boolean }> {
    return this._lookupTables.deleteLookupTable(id);
  }

  async lookupQuery(request: import('./types').LookupQueryRequest): Promise<import('./types').LookupResult | import('./types').BatchLookupResult> {
    return this._lookupTables.lookupQuery(request);
  }

  async sampleLookupRows(name: string, limit?: number): Promise<{ rows: Record<string, unknown>[] }> {
    return this._lookupTables.sampleRows(name, limit);
  }

  async getLookupUsage(name: string): Promise<import('./types').LookupUsage[]> {
    return this._lookupTables.usage(name);
  }

  async getLookupHistory(name: string, limit?: number): Promise<import('./types').LookupHistoryEntry[]> {
    return this._lookupTables.ingestionHistory(name, limit);
  }

  async createLookupTableFromSchema(req: import('./types').CreateLookupTableFromSchemaRequest): Promise<import('./types').LookupTable> {
    return this._lookupTables.createLookupTableFromSchema(req);
  }

  async listLookupRows(name: string, page?: number, pageSize?: number): Promise<import('./types').LookupRowsPage> {
    return this._lookupTables.listRows(name, page, pageSize);
  }

  async addLookupRows(name: string, rows: Record<string, unknown>[]): Promise<import('./types').AddRowsResponse> {
    return this._lookupTables.addRows(name, rows);
  }

  async updateLookupRow(name: string, rowId: number, fields: Record<string, unknown>): Promise<{ success: boolean }> {
    return this._lookupTables.updateRow(name, rowId, fields);
  }

  async deleteLookupRow(name: string, rowId: number): Promise<{ success: boolean }> {
    return this._lookupTables.deleteRow(name, rowId);
  }

  async deleteLookupRows(name: string, rowIds: number[]): Promise<{ deleted: number }> {
    return this._lookupTables.deleteRows(name, rowIds);
  }

  // Audit
  async queryAuditLogs(query: import('./types').AuditLogQuery): Promise<import('./types').AuditLogResponse> {
    return this._audit.queryAuditLogs(query);
  }

  // AI Debug
  async getAiFailures(request?: import('./types').GetAiFailuresRequest): Promise<import('./types').AiFailuresResponse> {
    const params = new URLSearchParams();
    if (request?.agent_type) params.set('agent_type', request.agent_type);
    if (request?.limit) params.set('limit', String(request.limit));
    if (request?.offset) params.set('offset', String(request.offset));
    const query = params.toString();
    return this.request(`/api/ai/failures${query ? `?${query}` : ''}`);
  }

  // Organizational Context
  async getOrganizationalContext(): Promise<import('./types').OrganizationalContext> {
    return this._context.getOrganizationalContext();
  }

  async updateOrganizationalContext(request: import('./types').UpdateOrganizationalContextRequest): Promise<import('./types').OrganizationalContext> {
    return this._context.updateOrganizationalContext(request);
  }

  // User Preferences
  async getUserPreferences(): Promise<import('./types').UserPreferences> {
    return this.request('/api/users/me/preferences');
  }

  async updateUserPreferences(request: import('./types').UpdateUserPreferencesRequest): Promise<import('./types').UserPreferences> {
    return this.request('/api/users/me/preferences', {
      method: 'PATCH',
      body: JSON.stringify(request),
    });
  }

  // Health Monitoring Settings
  async getHealthMonitoringSettings(): Promise<import('./types').HealthMonitoringSettings> {
    return this.request('/api/settings/health-monitoring');
  }

  async updateHealthMonitoringSettings(request: import('./types').UpdateHealthMonitoringSettingsRequest): Promise<import('./types').HealthMonitoringSettings> {
    return this.request('/api/settings/health-monitoring', {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  // Recent Activity (Continue Working)
  async getRecentActivity(params?: { limit?: number; item_type?: import('./types').RecentItemType }): Promise<import('./types').RecentActivityResponse> {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.item_type) searchParams.set('item_type', params.item_type);
    const query = searchParams.toString();
    return this.request(`/api/me/recent${query ? `?${query}` : ''}`);
  }

  async recordActivity(request: import('./types').RecordActivityRequest): Promise<{ recorded: boolean }> {
    return this.request('/api/me/recent', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async clearRecentActivity(): Promise<{ cleared: number }> {
    return this.request('/api/me/recent', {
      method: 'DELETE',
    });
  }

  // License status
  async getLicenseStatus(): Promise<LicenseStatusResponse> {
    return this.request('/api/license');
  }

  // GDPR Anonymization
  async submitGdprRequest(req: import('./types').GdprSubmitRequest): Promise<import('./types').GdprAnonymizationPreview> {
    return this._gdpr.submitRequest(req);
  }

  async listGdprRequests(params?: { limit?: number; offset?: number }): Promise<import('./types').GdprAnonymizationListResponse> {
    return this._gdpr.listRequests(params);
  }

  async getGdprRequest(id: string): Promise<import('./types').GdprAnonymizationRequest> {
    return this._gdpr.getRequest(id);
  }

  async executeGdprRequest(id: string): Promise<import('./types').GdprAnonymizationRequest> {
    return this._gdpr.executeRequest(id);
  }

  // SIEM Health Check
  async getSiemHealthReports(limit?: number, offset?: number): Promise<import('./siem-health').ListReportsResponse> {
    return this._siemHealth.listReports(limit, offset);
  }

  async getSiemHealthLatest(): Promise<import('./siem-health').SiemHealthReport> {
    return this._siemHealth.getLatest();
  }

  async getSiemHealthReport(id: string): Promise<import('./siem-health').SiemHealthReport> {
    return this._siemHealth.getReport(id);
  }

  async triggerSiemHealthCheck(): Promise<import('./siem-health').TriggerResponse> {
    return this._siemHealth.trigger();
  }
}

// Create and export a singleton instance
export const apiClient = new ApiClient();
// Export as 'api' for backwards compatibility with the old api.ts imports
export const api = apiClient;
export default apiClient;
