// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  exactActiveTenant,
  type ActiveTenant,
  type DeploymentMode,
} from './tenant-runtime.ts';

const TENANT_SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const DEPLOYMENT_MODES = new Set<DeploymentMode>([
  'managed', 'enterprise_shared', 'self-hosted', 'demo',
]);

export class TenantAuthContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TenantAuthContractError';
  }
}

export function canonicalTenantSlug(value: unknown): string {
  if (typeof value !== 'string' || !TENANT_SLUG_PATTERN.test(value)) {
    throw new TenantAuthContractError('Tenant selector is not canonical');
  }
  return value;
}

// ---------------------------------------------------------------------------
// NAN-4152: web path alias (`/t/demo/...` serves the tenant whose real slug is
// `lean-internal-20261004b`). Resolved ONCE at boot (main.tsx) before render,
// from the public `GET /api/auth/shared/tenant-path-alias/{segment}`. Every
// selector parsed from a path below resolves the alias to the canonical slug,
// so every server-visible auth value (login / refresh / MFA / OIDC bodies,
// cookie slot, identity checks) is identical to the canonical path's. Path
// builders map the canonical slug back to the alias so a user who entered via
// `/t/demo` stays on `/t/demo`; the router basename keeps the raw segment.
// With no alias set every helper behaves exactly as before.
// ---------------------------------------------------------------------------

export interface TenantPathAlias {
  /** The `/t/<segment>` the browser is on. */
  pathSegment: string;
  /** The tenant's real slug, as answered by the server. */
  canonicalSlug: string;
}

let tenantPathAlias: TenantPathAlias | null = null;
const TENANT_PATH_ALIAS_TIMEOUT_MS = 3000;

/** Set (or clear with null) the boot-time alias. Refuses a non-canonical pair. */
export function setTenantPathAlias(alias: TenantPathAlias | null): void {
  if (alias === null) {
    tenantPathAlias = null;
    return;
  }
  const pathSegment = canonicalTenantSlug(alias.pathSegment);
  const canonicalSlug = canonicalTenantSlug(alias.canonicalSlug);
  if (pathSegment === canonicalSlug) {
    throw new TenantAuthContractError('Tenant path alias equals its slug');
  }
  tenantPathAlias = { pathSegment, canonicalSlug };
}

export function currentTenantPathAlias(): TenantPathAlias | null {
  return tenantPathAlias;
}

/** The canonical slug for a `/t/<segment>` (the alias resolves; anything else is itself). */
function slugForPathSegment(segment: string): string {
  const value = canonicalTenantSlug(segment);
  return tenantPathAlias !== null && value === tenantPathAlias.pathSegment
    ? tenantPathAlias.canonicalSlug
    : value;
}

/** The `/t/<segment>` to build for a canonical slug (the aliased tenant keeps its alias). */
export function tenantPathSegment(slug: string): string {
  const value = canonicalTenantSlug(slug);
  return tenantPathAlias !== null && value === tenantPathAlias.canonicalSlug
    ? tenantPathAlias.pathSegment
    : value;
}

/** The raw `/t/<segment>` of a browser path when it is a canonical slug shape. */
export function tenantPathSegmentOf(pathname: string): string | undefined {
  const match = pathname.match(/^\/t\/([^/]+)(?:\/|$)/);
  if (!match || !TENANT_SLUG_PATTERN.test(match[1])) return undefined;
  return match[1];
}

/**
 * Boot-time resolution: only for a `/t/<segment>` path. A 404, a network or
 * shape error, or a non-canonical answer leaves no alias, so the segment is
 * treated as a slug exactly as before.
 */
export async function resolveTenantPathAlias(
  pathname: string,
  fetchImpl: typeof globalThis.fetch = globalThis.fetch,
): Promise<TenantPathAlias | null> {
  const segment = tenantPathSegmentOf(pathname);
  if (segment === undefined) return null;
  try {
    const response = await fetchImpl(
      `/api/auth/shared/tenant-path-alias/${encodeURIComponent(segment)}`,
      {
        method: 'GET',
        credentials: 'omit',
        headers: { Accept: 'application/json' },
        // The first render waits on this: never let a hung request blank the app.
        ...(typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function'
          ? { signal: AbortSignal.timeout(TENANT_PATH_ALIAS_TIMEOUT_MS) }
          : {}),
      },
    );
    if (!response.ok) return null;
    const body: unknown = await response.json();
    if (body === null || typeof body !== 'object' || Array.isArray(body)) return null;
    const keys = Object.keys(body);
    const slug = (body as { canonical_slug?: unknown }).canonical_slug;
    if (keys.length !== 1 || keys[0] !== 'canonical_slug') return null;
    if (typeof slug !== 'string' || !TENANT_SLUG_PATTERN.test(slug) || slug === segment) return null;
    return { pathSegment: segment, canonicalSlug: slug };
  } catch {
    return null;
  }
}

/** Resolve and install the alias for this page load (call before render). */
export async function initTenantPathAlias(
  pathname: string,
  fetchImpl?: typeof globalThis.fetch,
): Promise<void> {
  setTenantPathAlias(await resolveTenantPathAlias(pathname, fetchImpl));
}

/** Parses only the exact, unencoded canonical shared-login path. */
export function tenantSlugFromLoginPath(pathname: string): string {
  const match = pathname.match(/^\/t\/([^/]+)\/login$/);
  if (!match) throw new TenantAuthContractError('Tenant login path is not canonical');
  // Percent escapes, Unicode lookalikes, uppercase aliases and decoded slashes
  // all fail the canonical slug expression instead of being normalized.
  return slugForPathSegment(match[1]);
}

export function tenantSlugFromShellPath(pathname: string): string {
  const match = pathname.match(/^\/t\/([^/]+)$/);
  if (!match) throw new TenantAuthContractError('Tenant shell path is not canonical');
  return slugForPathSegment(match[1]);
}

export function tenantSlugFromSearchPath(pathname: string): string {
  const match = pathname.match(/^\/t\/([^/]+)\/search$/);
  if (!match) throw new TenantAuthContractError('Tenant Search path is not canonical');
  return slugForPathSegment(match[1]);
}

/**
 * NAN-4152: a shared demo link `/t/<segment>/d/<token>`. The segment may be
 * the path alias; the returned slug is always the CANONICAL one (what the
 * claim body carries). The token is held to the url-safe claim alphabet.
 */
export function sharedDemoClaimFromPath(pathname: string): { tenantSlug: string; token: string } {
  const match = pathname.match(/^\/t\/([^/]+)\/d\/([A-Za-z0-9_-]{1,128})\/?$/);
  if (!match) throw new TenantAuthContractError('Demo link path is not canonical');
  return { tenantSlug: slugForPathSegment(match[1]), token: match[2] };
}

export function tenantSlugFromMfaSetupPath(pathname: string): string {
  const match = pathname.match(/^\/t\/([^/]+)\/mfa-setup$/);
  if (!match) throw new TenantAuthContractError('Tenant MFA path is not canonical');
  return slugForPathSegment(match[1]);
}

/** Exact audited shared SOC paths; encoded aliases and unsupported operations stay closed. */
export function tenantSlugFromSocPath(pathname: string): string {
  const match = pathname.match(/^\/t\/([^/]+)\/(?:rules|alerts(?:\/[A-Za-z0-9][A-Za-z0-9_-]{0,127})?)$/);
  if (!match) throw new TenantAuthContractError('Tenant SOC path is not canonical');
  return slugForPathSegment(match[1]);
}

export function tenantSocPath(slug: string, surface: 'rules' | 'alerts', id?: string): string {
  const path = `/t/${tenantPathSegment(slug)}/${surface}${id === undefined ? '' : `/${id}`}`;
  tenantSlugFromSocPath(path);
  return path;
}

export function tenantLoginPath(slug: string): string {
  return `/t/${tenantPathSegment(slug)}/login`;
}

export function tenantShellPath(slug: string): string {
  return `/t/${tenantPathSegment(slug)}`;
}

export function tenantSearchPath(slug: string): string {
  return `/t/${tenantPathSegment(slug)}/search`;
}

export function tenantMfaSetupPath(slug: string): string {
  return `/t/${tenantPathSegment(slug)}/mfa-setup`;
}

/**
 * The tenant selector carried by ANY product path under `/t/<slug>/…`.
 *
 * The whole product now lives under the tenant prefix (the router's basename
 * is `/t/<slug>`), so the selector is present on every page rather than on a
 * handful of audited shell shapes. The slug is still held to the canonical
 * expression; percent escapes, lookalikes and uppercase aliases refuse. A path
 * outside the prefix yields no selector, and the server refuses an
 * enterprise-shared refresh without one.
 */
export function tenantSlugFromScopedPath(pathname: string): string {
  const match = pathname.match(/^\/t\/([^/]+)(?:\/|$)/);
  if (!match) throw new TenantAuthContractError('Path is not tenant-scoped');
  return slugForPathSegment(match[1]);
}

/**
 * `/t/<segment>` when the browser path is tenant-scoped, else undefined. The
 * RAW segment: under a path alias the router stays mounted on `/t/<alias>`.
 */
export function tenantBasename(pathname: string): string | undefined {
  const segment = tenantPathSegmentOf(pathname);
  return segment === undefined ? undefined : `/t/${segment}`;
}

/** API docs stay under the current tenant prefix on pooled hosts (the server routes the canonical slug). */
export function swaggerUiPath(pathname: string): string {
  if (pathname.startsWith('/t/')) {
    return `/t/${tenantSlugFromScopedPath(pathname)}/swagger-ui/`;
  }
  return '/swagger-ui/';
}

/**
 * Per-tab hand-off for a continuation that crosses the tenant prefix.
 *
 * Activation (`/auth/shared/activate`, outside any tenant basename) and the
 * OIDC callback finish with a FULL page load into `/t/<slug>/…`, because a
 * router mounted without a basename cannot navigate into one. Router state
 * does not survive that load; this does, for exactly one read.
 */
const MFA_CONTINUATION_KEY = 'nano.mfa-continuation';
export interface MfaContinuation { tenantSlug: string; sharedActivation?: boolean; challengeToken?: string; from?: string }
export function stashMfaContinuation(value: MfaContinuation): void {
  try { window.sessionStorage.setItem(MFA_CONTINUATION_KEY, JSON.stringify(value)); } catch { /* storage unavailable: the page falls back to state */ }
}
export function takeMfaContinuation(): MfaContinuation | null {
  try {
    const raw = window.sessionStorage.getItem(MFA_CONTINUATION_KEY);
    if (raw === null) return null;
    window.sessionStorage.removeItem(MFA_CONTINUATION_KEY);
    const parsed = JSON.parse(raw) as MfaContinuation;
    return typeof parsed?.tenantSlug === 'string' ? { ...parsed, tenantSlug: canonicalTenantSlug(parsed.tenantSlug) } : null;
  } catch { return null; }
}

/**
 * Resolve the browser path allowed to continue a shared credential: any
 * tenant-scoped product path. Outside the prefix there is deliberately no
 * selector, so the server rejects an enterprise-shared refresh.
 */
export function tenantSlugForAuthContinuation(pathname: string): string | undefined {
  try {
    return tenantSlugFromScopedPath(pathname);
  } catch {
    return undefined;
  }
}

export function tenantContinuationBody(
  tenantSlug?: string,
): { tenant_slug?: string } {
  return tenantSlug === undefined
    ? {}
    : { tenant_slug: canonicalTenantSlug(tenantSlug) };
}

export function loginRequestBody(
  email: string,
  password: string,
  tenantSlug?: string,
): { email: string; password: string; tenant_slug?: string } {
  return {
    email,
    password,
    ...(tenantSlug === undefined ? {} : { tenant_slug: canonicalTenantSlug(tenantSlug) }),
  };
}

export function safeReturnPath(path: unknown, fallback = '/'): string {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) {
    return fallback;
  }
  // Validate the navigation path; search values may contain ISO timestamps or URLs.
  const pathname = path.split(/[?#]/, 1)[0];
  if (/[\u0000-\u0020\u007f]/.test(pathname)) return fallback;
  if (pathname.includes(':') || pathname.includes('\\')) return fallback;
  const lower = pathname.toLowerCase();
  if (lower.includes('%2f') || lower.includes('%5c') || lower.includes('%3a')) return fallback;
  return path;
}

export interface ServerAuthIdentity {
  id: string;
  roles: string[];
  deployment_mode?: unknown;
  active_tenant?: unknown;
}

export interface VerifiedServerAuthIdentity {
  deploymentMode: DeploymentMode;
  activeTenant: ActiveTenant | null;
}

/**
 * Validates the server-owned mode and tenant together. A route selector is
 * never authority: it must exactly match the tenant returned by `/api/auth/me`.
 */
export function verifyServerAuthIdentity(
  user: ServerAuthIdentity,
  expectedTenantSlug?: string,
): VerifiedServerAuthIdentity {
  if (
    typeof user.deployment_mode !== 'string'
    || !DEPLOYMENT_MODES.has(user.deployment_mode as DeploymentMode)
  ) {
    throw new TenantAuthContractError('Authenticated response is missing deployment_mode');
  }
  const deploymentMode = user.deployment_mode as DeploymentMode;
  const activeTenant = exactActiveTenant(user.active_tenant);

  if (deploymentMode === 'enterprise_shared') {
    if (!activeTenant) {
      throw new TenantAuthContractError(
        'enterprise_shared authentication is missing an exact active_tenant',
      );
    }
    if (
      expectedTenantSlug !== undefined
      && activeTenant.slug !== canonicalTenantSlug(expectedTenantSlug)
    ) {
      throw new TenantAuthContractError('Returned tenant does not match the login selector');
    }
    return { deploymentMode, activeTenant };
  }

  if (expectedTenantSlug !== undefined) {
    throw new TenantAuthContractError('Tenant login selector resolved a non-shared deployment');
  }
  if (activeTenant) {
    throw new TenantAuthContractError('Dedicated authentication returned an unexpected tenant');
  }
  return { deploymentMode, activeTenant: null };
}
