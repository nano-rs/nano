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

/** Parses only the exact, unencoded canonical shared-login path. */
export function tenantSlugFromLoginPath(pathname: string): string {
  const match = pathname.match(/^\/t\/([^/]+)\/login$/);
  if (!match) throw new TenantAuthContractError('Tenant login path is not canonical');
  // Percent escapes, Unicode lookalikes, uppercase aliases and decoded slashes
  // all fail the canonical slug expression instead of being normalized.
  return canonicalTenantSlug(match[1]);
}

export function tenantSlugFromShellPath(pathname: string): string {
  const match = pathname.match(/^\/t\/([^/]+)$/);
  if (!match) throw new TenantAuthContractError('Tenant shell path is not canonical');
  return canonicalTenantSlug(match[1]);
}

export function tenantSlugFromSearchPath(pathname: string): string {
  const match = pathname.match(/^\/t\/([^/]+)\/search$/);
  if (!match) throw new TenantAuthContractError('Tenant Search path is not canonical');
  return canonicalTenantSlug(match[1]);
}

export function tenantSlugFromMfaSetupPath(pathname: string): string {
  const match = pathname.match(/^\/t\/([^/]+)\/mfa-setup$/);
  if (!match) throw new TenantAuthContractError('Tenant MFA path is not canonical');
  return canonicalTenantSlug(match[1]);
}

/** Exact audited shared SOC paths; encoded aliases and unsupported operations stay closed. */
export function tenantSlugFromSocPath(pathname: string): string {
  const match = pathname.match(/^\/t\/([^/]+)\/(?:rules|alerts(?:\/[A-Za-z0-9][A-Za-z0-9_-]{0,127})?)$/);
  if (!match) throw new TenantAuthContractError('Tenant SOC path is not canonical');
  return canonicalTenantSlug(match[1]);
}

export function tenantSocPath(slug: string, surface: 'rules' | 'alerts', id?: string): string {
  const path = `/t/${canonicalTenantSlug(slug)}/${surface}${id === undefined ? '' : `/${id}`}`;
  tenantSlugFromSocPath(path);
  return path;
}

export function tenantLoginPath(slug: string): string {
  return `/t/${canonicalTenantSlug(slug)}/login`;
}

export function tenantShellPath(slug: string): string {
  return `/t/${canonicalTenantSlug(slug)}`;
}

export function tenantSearchPath(slug: string): string {
  return `/t/${canonicalTenantSlug(slug)}/search`;
}

export function tenantMfaSetupPath(slug: string): string {
  return `/t/${canonicalTenantSlug(slug)}/mfa-setup`;
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
  return canonicalTenantSlug(match[1]);
}

/** `/t/<slug>` when the browser path is tenant-scoped, else undefined. */
export function tenantBasename(pathname: string): string | undefined {
  try {
    return `/t/${tenantSlugFromScopedPath(pathname)}`;
  } catch {
    return undefined;
  }
}

/** API docs stay under the current tenant prefix on pooled hosts. */
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
  if (path.includes(':') || path.includes('\\')) return fallback;
  const lower = path.toLowerCase();
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
