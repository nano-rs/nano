// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Marketplace API client
 *
 * Unified catalog for data enrichments, agent enrichments, custom enrichments,
 * and identity providers. Supports GitHub repository sync for community content.
 */

// =============================================================================
// Types
// =============================================================================

export interface MarketplaceCatalogEntry {
  id: string;
  slug: string;
  name: string;
  description?: string;
  category: 'data' | 'agent' | 'identity';
  tags: string[];
  icon?: string;
  author?: string;
  source_type: 'system' | 'repository' | 'custom';
  repository_id?: string;
  repository_file_path?: string;
  manifest_version: number;
  execution_backend: 'deno' | 'native' | 'identity';
  custom_enrichment_id?: string;
  native_source_id?: string;
  identity_provider_id?: string;
  installed: boolean;
  installed_at?: string;
  installed_version?: number;
  requires_credential: 'none' | 'optional' | 'required';
  credential_fields: CredentialFieldDef[];
  has_credentials: boolean;
  code?: string;
  allowed_domains: string[];
  config: Record<string, unknown>;
  enabled: boolean;
  last_sync_at?: string;
  last_sync_status?: string;
  last_error?: string;
  record_count: number;
  /** True when a sync is currently in flight for this entry. Derived
   *  per-query on the backend from custom_enrichment_runs. Drives the
   *  catalog card's footer-state badge (NAN-1108). */
  is_syncing?: boolean;
  /** True when the live install/sync path requires outbound internet (identity
   *  providers, native bulk feeds, or deno enrichments declaring allowed_domains).
   *  Derived on the backend from execution_backend + allowed_domains. In air-gap
   *  mode these badge "Requires connectivity" and route to import-from-file
   *  instead of live sync; offline-capable entries (custom transforms with no
   *  allowed_domains) are false. (NAN-1212) */
  requires_network?: boolean;
  changelog?: string;
  created_at: string;
  updated_at: string;
}

/**
 * Whether an entry is a bulk *data* feed (scheduled sync into ClickHouse) vs an
 * on-demand *agent* lookup or identity provider.
 *
 * `category` is a coarse UI grouping, not a functional type. Historically the
 * (now-retired, NAN-1998) 'security' category spanned both bulk feeds (ThreatFox,
 * Tor exit nodes) and on-demand lookups (urlhaus, shodan, malwarebazaar), so
 * gating sync UI on `category === 'data'` hid the "Sync now" button for those
 * data feeds (NAN-1585). Mirror the backend's `infer_enrichment_type`: prefer the
 * config markers (`artifact_types` ⇒ agent, `key_field` ⇒ data), fall back to
 * category.
 */
export function isDataFeed(entry: MarketplaceCatalogEntry): boolean {
  const config = entry.config ?? {};
  if ('artifact_types' in config) return false;
  if ('key_field' in config) return true;
  return entry.category === 'data';
}

export interface CredentialFieldDef {
  name: string;
  label: string;
  field_type: string;
  required: boolean;
  help?: string;
}

export interface EnrichmentMarketplaceRepo {
  id: string;
  name: string;
  slug: string;
  description?: string;
  url: string;
  branch: string;
  enrichments_path: string;
  auto_sync_enabled: boolean;
  sync_interval_hours: number;
  last_synced_at?: string;
  last_sync_commit?: string;
  last_sync_status?: string;
  last_sync_error?: string;
  enrichment_count: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CatalogStats {
  total_entries: number;
  installed_count: number;
  data_count: number;
  agent_count: number;
  identity_count: number;
}

export interface CatalogListResponse {
  entries: MarketplaceCatalogEntry[];
  total: number;
  stats: CatalogStats;
}

export interface CatalogFilter {
  category?: string;
  installed?: boolean;
  tag?: string;
  search?: string;
  source_type?: string;
}

export interface InstallRequest {
  credentials?: Record<string, string>;
  config?: Record<string, unknown>;
}

export interface ConfigureRequest {
  credentials?: Record<string, string>;
  config?: Record<string, unknown>;
  enabled?: boolean;
}

export interface EnrichmentStatus {
  slug: string;
  installed: boolean;
  enabled: boolean;
  last_sync_at?: string;
  last_sync_status?: string;
  last_error?: string;
  record_count: number;
}

export interface CreateMarketplaceRepoRequest {
  name: string;
  url: string;
  description?: string;
  branch?: string;
  enrichments_path?: string;
  auto_sync_enabled?: boolean;
  sync_interval_hours?: number;
}

export interface UpdateMarketplaceRepoRequest {
  name?: string;
  description?: string;
  branch?: string;
  enrichments_path?: string;
  auto_sync_enabled?: boolean;
  sync_interval_hours?: number;
  enabled?: boolean;
}

export interface RepoBrowseEntry {
  path: string;
  name: string;
  entry_type: string;
  has_manifest: boolean;
}

export interface ExportResponse {
  slug: string;
  directory: string;
  manifest_yaml: string;
  code: string;
}

export interface PreviewRequest {
  /** Sample artifact value. Defaults to a per-type well-known value. */
  artifact?: string;
  /** Artifact type: `ip` | `domain` | `hash` | `url` | `email` | `filename`. Defaults to `ip`. */
  artifact_type?: string;
}

export interface PreviewResponse {
  success: boolean;
  artifact: string;
  artifact_type: string;
  /** Parsed AgentEnrichmentResult JSON when success === true. */
  output: Record<string, unknown> | null;
  stdout: string;
  stderr: string;
  duration_ms: number;
  /** User-readable status when preview is unsupported. */
  note: string | null;
  error: string | null;
}

export type CoverageState = 'good' | 'partial' | 'gap';

export interface ArtifactCoverage {
  id: string;
  label: string;
  pct: number;
  state: CoverageState;
  /** Display labels of installed providers from the recommended set */
  have: string[];
  /** Display labels of recommended providers that are NOT installed */
  missing: string[];
}

export interface MarketplaceCoverage {
  artifacts: ArtifactCoverage[];
  /**
   * Wall-clock time (ISO-8601 UTC) the underlying SQL was last actually
   * run. Because the response is shared-cached for 6h on the server,
   * this is *not* the time the request was served — it's how stale the
   * data is. Render this in the hero so users know when they're looking
   * at fresh vs. cached numbers.
   */
  computed_at: string;
}

// =============================================================================
// Attribution
// =============================================================================

/**
 * The native IPinfo Lite IP geo/ASN enrichment is distributed under
 * CC BY-SA 4.0, so any surface that exposes it must carry an attribution
 * credit. This detects the IPinfo entry robustly (slug / name /
 * native_source_id contains "ipinfo", case-insensitive) rather than
 * pinning a generated UUID. (NAN-1216)
 */
export function isIpInfoEntry(entry: MarketplaceCatalogEntry): boolean {
  const haystack = [entry.slug, entry.name, entry.native_source_id]
    .filter((v): v is string => !!v)
    .join(' ')
    .toLowerCase();
  return haystack.includes('ipinfo');
}

/** Stable URL for the CC BY-SA 4.0 license deed used by the credit link. */
export const CC_BY_SA_4_URL = 'https://creativecommons.org/licenses/by-sa/4.0/';

// =============================================================================
// API Client
// =============================================================================

export class MarketplaceApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
  ) {}

  // ── Catalog ──────────────────────────────────────────────────────────

  async listCatalog(filter?: CatalogFilter): Promise<CatalogListResponse> {
    const params = new URLSearchParams();
    if (filter?.category) params.set('category', filter.category);
    if (filter?.installed !== undefined) params.set('installed', String(filter.installed));
    if (filter?.tag) params.set('tag', filter.tag);
    if (filter?.search) params.set('search', filter.search);
    if (filter?.source_type) params.set('source_type', filter.source_type);
    const qs = params.toString();
    return this.request<CatalogListResponse>(`/api/marketplace/catalog${qs ? `?${qs}` : ''}`);
  }

  async getCatalogEntry(slug: string): Promise<MarketplaceCatalogEntry> {
    return this.request<MarketplaceCatalogEntry>(`/api/marketplace/catalog/${encodeURIComponent(slug)}`);
  }

  async installEnrichment(slug: string, request?: InstallRequest): Promise<MarketplaceCatalogEntry> {
    return this.request<MarketplaceCatalogEntry>(`/api/marketplace/catalog/${encodeURIComponent(slug)}/install`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request ?? {}),
    });
  }

  async updateEnrichment(slug: string): Promise<MarketplaceCatalogEntry> {
    return this.request<MarketplaceCatalogEntry>(`/api/marketplace/catalog/${encodeURIComponent(slug)}/update`, {
      method: 'POST',
    });
  }

  async uninstallEnrichment(slug: string): Promise<MarketplaceCatalogEntry> {
    return this.request<MarketplaceCatalogEntry>(`/api/marketplace/catalog/${encodeURIComponent(slug)}/uninstall`, {
      method: 'POST',
    });
  }

  async configureEnrichment(slug: string, request: ConfigureRequest): Promise<MarketplaceCatalogEntry> {
    return this.request<MarketplaceCatalogEntry>(`/api/marketplace/catalog/${encodeURIComponent(slug)}/configure`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
  }

  async syncEnrichment(slug: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/api/marketplace/catalog/${encodeURIComponent(slug)}/sync`, {
      method: 'POST',
    });
  }

  async getEnrichmentStatus(slug: string): Promise<EnrichmentStatus> {
    return this.request<EnrichmentStatus>(`/api/marketplace/catalog/${encodeURIComponent(slug)}/status`);
  }

  async exportEnrichment(slug: string): Promise<ExportResponse> {
    return this.request<ExportResponse>(`/api/marketplace/catalog/${encodeURIComponent(slug)}/export`);
  }

  // ── Coverage ─────────────────────────────────────────────────────────

  async getCoverage(): Promise<MarketplaceCoverage> {
    return this.request<MarketplaceCoverage>('/api/marketplace/coverage');
  }

  /**
   * Force a recompute of the coverage hero, bypassing the 6h Dragonfly
   * cache. Returns the freshly-computed payload (which is also re-cached
   * server-side). Used by the manual-refresh button in the hero header.
   */
  async refreshCoverage(): Promise<MarketplaceCoverage> {
    return this.request<MarketplaceCoverage>('/api/marketplace/coverage/refresh', {
      method: 'POST',
    });
  }

  // ── Preview ──────────────────────────────────────────────────────────

  async previewEnrichment(slug: string, request?: PreviewRequest): Promise<PreviewResponse> {
    return this.request<PreviewResponse>(
      `/api/marketplace/catalog/${encodeURIComponent(slug)}/preview`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request ?? {}),
      },
    );
  }

  // ── Repos ────────────────────────────────────────────────────────────

  async listRepos(): Promise<EnrichmentMarketplaceRepo[]> {
    const response = await this.request<{ repos: EnrichmentMarketplaceRepo[] }>('/api/marketplace/repos');
    return response.repos;
  }

  async createRepo(request: CreateMarketplaceRepoRequest): Promise<EnrichmentMarketplaceRepo> {
    return this.request<EnrichmentMarketplaceRepo>('/api/marketplace/repos', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
  }

  async updateRepo(id: string, request: UpdateMarketplaceRepoRequest): Promise<EnrichmentMarketplaceRepo> {
    return this.request<EnrichmentMarketplaceRepo>(`/api/marketplace/repos/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
  }

  async deleteRepo(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/api/marketplace/repos/${id}`, {
      method: 'DELETE',
    });
  }

  async syncRepo(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/api/marketplace/repos/${id}/sync`, {
      method: 'POST',
    });
  }

  async browseRepo(id: string): Promise<RepoBrowseEntry[]> {
    const response = await this.request<{ entries: RepoBrowseEntry[] }>(`/api/marketplace/repos/${id}/browse`);
    return response.entries;
  }
}
