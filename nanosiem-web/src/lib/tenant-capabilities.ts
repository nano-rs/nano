// SPDX-License-Identifier: AGPL-3.0-or-later

import { exactActiveTenant, type ActiveTenant } from './tenant-runtime.ts';

export const TENANT_COMPONENT_CODES = [
  'api',
  'ingest',
  'parser_cells',
  'lake_storage',
  'search',
  'prevalence',
  'alerts',
  'detections',
  'dashboards',
  'reports',
  'siem_health',
  'observability',
  'cases',
  'notebooks',
  'risk',
  'melod',
  'custom_enrichment',
  'agent_enrichment',
  'ai_tuning',
  'playbooks',
  'incidents',
  'observability_convergence',
  'sso',
] as const;

export type TenantComponentCode = (typeof TENANT_COMPONENT_CODES)[number];

export const ENTERPRISE_SHARED_FEATURE_FLAG_CODES = [
  'parser_cell_canary',
  'r2_archive_cache_read',
  'soc_ai_long_hunts',
  'oidc_group_role_reconciliation',
] as const;

export type EnterpriseSharedFeatureFlagCode =
  (typeof ENTERPRISE_SHARED_FEATURE_FLAG_CODES)[number];

export interface TenantComponentGrant {
  enabled: boolean;
  configuration: Record<string, unknown>;
}

export interface TenantPlanIdentity {
  code: string;
  revision: number;
  assignmentRevision: number;
}

export interface TenantCapabilityIdentity {
  userId: string;
  roles: string[];
  permissions: string[];
  authorizationRevision: number;
}

export interface TenantCapabilityFeatureFlags {
  revision: number;
  flags: Record<EnterpriseSharedFeatureFlagCode, boolean>;
}

export interface TenantCapabilitySnapshot {
  edition: 'enterprise';
  version: string;
  deploymentMode: 'enterprise_shared';
  tenant: ActiveTenant;
  identity: TenantCapabilityIdentity;
  plan: TenantPlanIdentity;
  limits: Record<string, unknown>;
  haEnabled: true;
  components: Record<TenantComponentCode, TenantComponentGrant>;
  /** Rollout/UI implementation selectors only; never authorization. */
  featureFlags: TenantCapabilityFeatureFlags;
}

/**
 * Narrow shared query-correction affordance. This never enables generic meloD:
 * both server-owned plan components and both exact permissions must be present.
 */
export function tenantQueryCorrectionEnabled(
  snapshot: TenantCapabilitySnapshot,
): boolean {
  const permissions = new Set(snapshot.identity.permissions);
  const can = (permission: string) => permissions.has('*') || permissions.has(permission);
  return snapshot.components.search.enabled
    && snapshot.components.melod.enabled
    && can('search:execute')
    && can('melod:query');
}

/**
 * The platform half of "AI works for this tenant" (NAN-2361 wave 8), read from
 * `GET /api/settings/ai-availability` (`shared_melod.rs`, backed by
 * `nano_shared.platform_ai_availability()`): whether any platform provider
 * credential is enabled and a selectable, non-deprecated model exists. A plan
 * that includes meloD is worthless without it — every tenant AI call answers
 * 409 `ai_provider_not_configured` — so the shell folds it into the AI
 * capability flags rather than letting each page discover it by failing.
 */
export interface TenantAiAvailability {
  connected: boolean;
  modelAvailable: boolean;
}

/** Deny-all AI when the probe is unreadable: no wizard, no correct-query retry. */
export const TENANT_AI_UNAVAILABLE: TenantAiAvailability = { connected: false, modelAvailable: false };

export function parseTenantAiAvailability(value: unknown): TenantAiAvailability {
  if (!isRecord(value) || typeof value.connected !== 'boolean' || typeof value.model_available !== 'boolean') {
    throw new TenantCapabilityContractError('AI availability probe is not the expected shape');
  }
  return { connected: value.connected, modelAvailable: value.model_available };
}

/** AI capability flags that hold only when the plan grants them AND the platform can serve them. */
export interface TenantAiCapabilityFlags {
  melod: boolean;
  queryCorrection: boolean;
  aiTuning: boolean;
}

export function tenantAiCapabilities(
  snapshot: TenantCapabilitySnapshot,
  availability: TenantAiAvailability,
): TenantAiCapabilityFlags {
  const served = availability.connected && availability.modelAvailable;
  return {
    melod: snapshot.components.melod.enabled && served,
    queryCorrection: tenantQueryCorrectionEnabled(snapshot) && served,
    aiTuning: snapshot.components.ai_tuning.enabled && served,
  };
}

/**
 * What the tenant-pinned Search runtime serves (NAN-2361 wave 8). Every
 * `false` names a route the shared profile does not serve today; the Search
 * page hides that affordance (and its separator) instead of issuing a request
 * that answers 503. The dedicated deployment serves all of them.
 */
export interface SearchSurface {
  /**
   * Datasets `POST /api/search` accepts. The shared runtime serves the
   * tenant-pinned `logs` dataset only (`require_shared_npl_contract` in
   * nanosiem-search rejects spans/metrics/risk with 503).
   */
  datasets: readonly ('logs' | 'spans' | 'metrics' | 'risk')[];
  /** `POST /api/search/sql` — `reject_shared_raw_sql` answers 503 on shared. */
  rawSql: boolean;
  /**
   * `POST /api/search/share` + `GET /api/search/shared/{id}` (stored short
   * links). Served on shared by `shared_search_extras` (NAN-2361
   * wave 8): ids are minted per tenant in the same 8-character format, so the
   * `?s=` loader is unchanged.
   */
  storedShortLinks: boolean;
  /**
   * `POST|GET /api/search/explanation` (cached AI reasoning). Served on shared
   * by the same module, keyed by (tenant, scope-bound query hash).
   */
  explanationCache: boolean;
  /**
   * Reuse of browser-cached result rows on back-navigation. The shared browser
   * does not own the grant-authority revision, so rows fetched before a
   * revocation must never be shown again without a fresh server round-trip.
   */
  browserResultCache: boolean;
  /**
   * Execute through the tenant-pinned durable job coordinator (`POST
   * /api/search` + `GET /api/search/jobs/{id}`) rather than legacy SSE
   * streaming admission.
   */
  durableExecution: boolean;
}

export const DEDICATED_SEARCH_SURFACE: SearchSurface = {
  datasets: ['logs', 'spans', 'metrics', 'risk'],
  rawSql: true,
  storedShortLinks: true,
  explanationCache: true,
  browserResultCache: true,
  durableExecution: false,
};

export const SHARED_SEARCH_SURFACE: SearchSurface = {
  datasets: ['logs'],
  rawSql: false,
  storedShortLinks: true,
  explanationCache: true,
  browserResultCache: false,
  durableExecution: true,
};

/**
 * Shared Search for a tenant whose plan grants risk and whose member holds
 * `risk:view` (NAN-3018). Lean-lake cell tenants answer `dataset=risk` with
 * their own decay and clears. A gen1 tenant gets a 400 that names the limit.
 */
export const SHARED_RISK_SEARCH_SURFACE: SearchSurface = {
  ...SHARED_SEARCH_SURFACE,
  datasets: ['logs', 'risk'],
};

/** The Search surface for the current capability snapshot. */
export function tenantSearchSurface(tenantPlan: TenantCapabilitySnapshot | undefined): SearchSurface {
  if (!tenantPlan) return DEDICATED_SEARCH_SURFACE;
  const permissions = new Set(tenantPlan.identity.permissions);
  const riskVisible = tenantPlan.components.risk?.enabled === true
    && (permissions.has('*') || permissions.has('risk:view'));
  return riskVisible ? SHARED_RISK_SEARCH_SURFACE : SHARED_SEARCH_SURFACE;
}

export class TenantCapabilityContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TenantCapabilityContractError';
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactStringSet(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new TenantCapabilityContractError(`${label} is not an exact string list`);
  }
  const entries = value as string[];
  if (entries.some((entry) => entry.length === 0) || new Set(entries).size !== entries.length) {
    throw new TenantCapabilityContractError(`${label} contains an invalid or duplicate entry`);
  }
  return [...entries].sort();
}

function sameStringSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((entry, index) => entry === right[index]);
}

function containsCredentialShapedKey(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsCredentialShapedKey);
  if (!isRecord(value)) return false;
  return Object.entries(value).some(([key, entry]) => {
    const normalized = key.toLowerCase();
    return [
      'secret',
      'password',
      'credential',
      'private_key',
      'access_key',
      'api_key',
      'token',
    ].some((needle) => normalized.includes(needle)) || containsCredentialShapedKey(entry);
  });
}

export interface ExpectedTenantCapabilityIdentity {
  userId: string;
  tenant: ActiveTenant;
  roles: readonly string[];
  permissions: readonly string[];
}

/**
 * Validate the complete authenticated bootstrap response against the current
 * server-authenticated browser identity. This is a parser, not an authority:
 * it never accepts route/client plan flags and rejects missing/unknown fields.
 */
export function validateTenantCapabilitySnapshot(
  value: unknown,
  expected: ExpectedTenantCapabilityIdentity,
): TenantCapabilitySnapshot {
  if (!isRecord(value)) {
    throw new TenantCapabilityContractError('Tenant capability response is not an object');
  }
  if (value.edition !== 'enterprise' || value.deploymentMode !== 'enterprise_shared') {
    throw new TenantCapabilityContractError('Tenant capability response has the wrong profile');
  }
  if (typeof value.version !== 'string' || value.version.length === 0) {
    throw new TenantCapabilityContractError('Tenant capability response has no version');
  }
  const tenant = exactActiveTenant(value.tenant);
  if (!tenant || tenant.id !== expected.tenant.id || tenant.slug !== expected.tenant.slug) {
    throw new TenantCapabilityContractError('Tenant capability identity does not match runtime');
  }
  if (!isRecord(value.identity) || value.identity.userId !== expected.userId) {
    throw new TenantCapabilityContractError('Tenant capability user does not match runtime');
  }
  const roles = exactStringSet(value.identity.roles, 'Tenant roles');
  const permissions = exactStringSet(value.identity.permissions, 'Tenant permissions');
  if (!sameStringSet(roles, [...expected.roles].sort())
      || !sameStringSet(permissions, [...expected.permissions].sort())) {
    throw new TenantCapabilityContractError('Tenant membership changed during bootstrap');
  }
  if (!Number.isSafeInteger(value.identity.authorizationRevision)
      || Number(value.identity.authorizationRevision) <= 0) {
    throw new TenantCapabilityContractError('Tenant authorization revision is invalid');
  }
  if (!isRecord(value.plan)
      || typeof value.plan.code !== 'string'
      || !/^[a-z][a-z0-9-]{0,62}$/.test(value.plan.code)
      || !Number.isSafeInteger(value.plan.revision)
      || Number(value.plan.revision) <= 0
      || !Number.isSafeInteger(value.plan.assignmentRevision)
      || Number(value.plan.assignmentRevision) <= 0) {
    throw new TenantCapabilityContractError('Tenant plan identity is incomplete');
  }
  if (!isRecord(value.limits) || containsCredentialShapedKey(value.limits)) {
    throw new TenantCapabilityContractError('Tenant plan limits are not public metadata');
  }
  if (value.haEnabled !== true || value.limits.ha_enabled !== true) {
    throw new TenantCapabilityContractError('Shared tenant plan must be highly available');
  }
  if (!isRecord(value.components)) {
    throw new TenantCapabilityContractError('Tenant component manifest is missing');
  }
  const componentManifest = value.components;
  const actualComponentCodes = Object.keys(componentManifest).sort();
  const expectedComponentCodes = [...TENANT_COMPONENT_CODES].sort();
  if (!sameStringSet(actualComponentCodes, expectedComponentCodes)) {
    throw new TenantCapabilityContractError('Tenant component manifest is incomplete or unknown');
  }

  const components = Object.fromEntries(TENANT_COMPONENT_CODES.map((code) => {
    const grant = componentManifest[code];
    if (!isRecord(grant)
        || typeof grant.enabled !== 'boolean'
        || !isRecord(grant.configuration)
        || containsCredentialShapedKey(grant.configuration)) {
      throw new TenantCapabilityContractError(`Tenant component ${code} is invalid`);
    }
    return [code, {
      enabled: grant.enabled,
      configuration: grant.configuration,
    }];
  })) as Record<TenantComponentCode, TenantComponentGrant>;
  if (!components.sso.enabled) {
    throw new TenantCapabilityContractError('SSO is required for every shared tenant plan');
  }

  const featureFlagsValue = value.featureFlags;
  if (!isRecord(featureFlagsValue)
      || !Number.isSafeInteger(featureFlagsValue.revision)
      || Number(featureFlagsValue.revision) <= 0
      || !isRecord(featureFlagsValue.flags)) {
    throw new TenantCapabilityContractError('Tenant feature flag authority is incomplete');
  }
  const flagManifest = featureFlagsValue.flags;
  const actualFlagCodes = Object.keys(flagManifest).sort();
  const expectedFlagCodes = [...ENTERPRISE_SHARED_FEATURE_FLAG_CODES].sort();
  if (!sameStringSet(actualFlagCodes, expectedFlagCodes)) {
    throw new TenantCapabilityContractError('Tenant feature flag catalog is incomplete or unknown');
  }
  const flags = Object.fromEntries(ENTERPRISE_SHARED_FEATURE_FLAG_CODES.map((code) => {
    const enabled = flagManifest[code];
    if (typeof enabled !== 'boolean') {
      throw new TenantCapabilityContractError(`Tenant feature flag ${code} is invalid`);
    }
    return [code, enabled];
  })) as Record<EnterpriseSharedFeatureFlagCode, boolean>;

  return {
    edition: 'enterprise',
    version: value.version,
    deploymentMode: 'enterprise_shared',
    tenant,
    identity: {
      userId: expected.userId,
      roles,
      permissions,
      authorizationRevision: Number(value.identity.authorizationRevision),
    },
    plan: {
      code: value.plan.code,
      revision: Number(value.plan.revision),
      assignmentRevision: Number(value.plan.assignmentRevision),
    },
    limits: value.limits,
    haEnabled: true,
    components,
    featureFlags: {
      revision: Number(featureFlagsValue.revision),
      flags,
    },
  };
}

export interface TenantBootstrapAuthorityRevisions {
  authorization: number;
  planAssignment: number;
  featureFlags: number;
}

/** Every server authority generation is monotonic within one tenant runtime. */
export function acceptTenantBootstrapAuthorityRevisions(
  previous: TenantBootstrapAuthorityRevisions | undefined,
  next: TenantBootstrapAuthorityRevisions,
): TenantBootstrapAuthorityRevisions {
  if (!Object.values(next).every((revision) => Number.isSafeInteger(revision) && revision > 0)) {
    throw new TenantCapabilityContractError('Tenant bootstrap revision is invalid');
  }
  if (previous !== undefined
      && (next.authorization < previous.authorization
        || next.planAssignment < previous.planAssignment
        || next.featureFlags < previous.featureFlags)) {
    throw new TenantCapabilityContractError('Tenant bootstrap authority revision regressed');
  }
  return next;
}

/** Exact identity for any browser-resident authenticated bootstrap snapshot. */
export function tenantBootstrapCacheKey(snapshot: TenantCapabilitySnapshot): readonly [
  'tenant-bootstrap', string, string, number, number, number,
] {
  return [
    'tenant-bootstrap',
    snapshot.tenant.id,
    snapshot.identity.userId,
    snapshot.identity.authorizationRevision,
    snapshot.plan.assignmentRevision,
    snapshot.featureFlags.revision,
  ];
}
