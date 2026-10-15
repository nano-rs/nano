// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  tenantShellPath,
  canonicalTenantSlug,
  verifyServerAuthIdentity,
  type ServerAuthIdentity,
} from './tenant-auth-shell.ts';
import {
  validateTenantCapabilitySnapshot,
  type TenantCapabilitySnapshot,
} from './tenant-capabilities.ts';
import {
  exactActiveTenant,
  type BrowserStorageLike,
  type TenantRuntimeAuthority,
} from './tenant-runtime.ts';

const PENDING_KEY = 'nano:enterprise-shared:oidc-pending';
const CALLBACK_PATH = '/auth/shared/oidc/callback';
const SELECTOR_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_CALLBACK_VALUE_BYTES = 8192;

export class SharedOidcBrowserError extends Error {
  constructor() {
    // Keep all pre-auth failures uniform. Provider/tenant existence and
    // upstream details must never become a browser enumeration oracle.
    super('Single sign-on failed. Please try again.');
    this.name = 'SharedOidcBrowserError';
  }
}

/** Exact nonsecret authority returned only after the server consumes an entry. */
export interface SharedOidcEntryDocument {
  deploymentMode: 'enterprise_shared';
  tenant: { tenantId: string; slug: string };
  providerSlug: string;
  authorityRevision: number;
  url: string;
}

interface PendingSharedOidcFlow {
  tenantId: string;
  tenantSlug: string;
  providerSlug: string;
  authorityRevision: number;
  runtimeEpoch: number;
  runtimeKey: string;
}

interface SharedOidcCallbackResponse {
  user: Record<string, unknown>;
  tenant_id: string;
  tenant_slug: string;
  authority_revision: number;
  assignment_revision: number;
}

export interface SharedOidcBrowserResult {
  user: ServerAuthIdentity & Record<string, unknown>;
  tenant: TenantCapabilitySnapshot;
  destination: string;
}

export interface SharedOidcLoginProvider {
  slug: string;
  name: string;
}

export interface SharedOidcBrowserDependencies {
  fetch: typeof globalThis.fetch;
  sessionStorage: BrowserStorageLike;
  runtime: TenantRuntimeAuthority;
  /** Replaces the URL before any network request, removing entry/code/state. */
  replaceUrl: (path: string) => void;
  /**
   * Runs as soon as the callback endpoint has accepted the exchange. Browsers
   * apply Set-Cookie before response JSON is parsed, so callers must remember
   * that the origin-wide cookie changed even when later proof fails.
   */
  onCookieMutation?: () => void;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function canonicalProviderSlug(value: unknown): string {
  if (typeof value !== 'string' || !SELECTOR_PATTERN.test(value)) {
    throw new SharedOidcBrowserError();
  }
  return value;
}

function exactPositiveRevision(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new SharedOidcBrowserError();
  }
  return Number(value);
}

function parseEntry(value: unknown): SharedOidcEntryDocument {
  if (
    !isRecord(value)
    || Object.keys(value).sort().join(',')
      !== 'authorityRevision,deploymentMode,providerSlug,tenant,url'
    || value.deploymentMode !== 'enterprise_shared'
    || !isRecord(value.tenant)
    || Object.keys(value.tenant).sort().join(',') !== 'slug,tenantId'
  ) {
    throw new SharedOidcBrowserError();
  }
  const tenant = exactActiveTenant({ id: value.tenant.tenantId, slug: value.tenant.slug });
  if (!tenant) throw new SharedOidcBrowserError();
  return {
    deploymentMode: 'enterprise_shared',
    tenant: { tenantId: tenant.id, slug: tenant.slug },
    providerSlug: canonicalProviderSlug(value.providerSlug),
    authorityRevision: exactPositiveRevision(value.authorityRevision),
    url: exactAuthorizeUrl({ url: value.url }),
  };
}

/**
 * What `/t/<slug>/login` may offer (NAN-2361 wave 8): the enabled provider
 * labels and whether the tenant still accepts local password credentials
 * (its NAN-2181 setting). The dedicated page learns the latter from
 * `GET /api/auth/methods`; the tenant page learns it from the same discovery
 * call, so an SSO-only tenant never renders a password prompt.
 */
export interface SharedLoginMethods {
  providers: SharedOidcLoginProvider[];
  localPasswordEnabled: boolean;
}

function parseLoginMethods(value: unknown): SharedLoginMethods {
  // `localPasswordEnabled` is optional only so a page deployed ahead of the
  // API still parses; absent means enabled, the dedicated default.
  const keys = isRecord(value) ? Object.keys(value).sort().join(',') : '';
  if (keys !== 'providers' && keys !== 'localPasswordEnabled,providers') {
    throw new SharedOidcBrowserError();
  }
  const record = value as Record<string, unknown>;
  if ('localPasswordEnabled' in record && typeof record.localPasswordEnabled !== 'boolean') {
    throw new SharedOidcBrowserError();
  }
  // The flag is stripped before the credential-field scan in `parseProviders`,
  // which rejects any key containing "password"; a boolean policy flag is
  // not a credential.
  return {
    providers: parseProviders({ providers: record.providers }),
    localPasswordEnabled: record.localPasswordEnabled !== false,
  };
}

function parseProviders(value: unknown): SharedOidcLoginProvider[] {
  assertNoCredentialFields(value);
  if (!isRecord(value) || Object.keys(value).join(',') !== 'providers' || !Array.isArray(value.providers)) {
    throw new SharedOidcBrowserError();
  }
  if (value.providers.length === 0 || value.providers.length > 8) {
    throw new SharedOidcBrowserError();
  }
  const providers = value.providers.map((provider) => {
    if (
      !isRecord(provider)
      || Object.keys(provider).sort().join(',') !== 'name,slug'
      || typeof provider.name !== 'string'
      || provider.name.trim().length === 0
      || provider.name.length > 255
    ) {
      throw new SharedOidcBrowserError();
    }
    return { slug: canonicalProviderSlug(provider.slug), name: provider.name };
  });
  if (new Set(providers.map((provider) => provider.slug)).size !== providers.length) {
    throw new SharedOidcBrowserError();
  }
  return providers;
}

function serializePending(value: PendingSharedOidcFlow): string {
  return JSON.stringify(value);
}

function readPending(storage: BrowserStorageLike): PendingSharedOidcFlow {
  let value: unknown;
  try {
    const raw = storage.getItem(PENDING_KEY);
    value = raw === null ? null : JSON.parse(raw);
  } catch {
    throw new SharedOidcBrowserError();
  }
  if (!isRecord(value)) throw new SharedOidcBrowserError();
  const keys = Object.keys(value).sort();
  if (
    keys.join(',')
      !== 'authorityRevision,providerSlug,runtimeEpoch,runtimeKey,tenantId,tenantSlug'
  ) {
    throw new SharedOidcBrowserError();
  }
  if (!Number.isSafeInteger(value.runtimeEpoch) || Number(value.runtimeEpoch) < 0) {
    throw new SharedOidcBrowserError();
  }
  if (typeof value.runtimeKey !== 'string' || value.runtimeKey.length === 0) {
    throw new SharedOidcBrowserError();
  }
  const tenant = exactActiveTenant({ id: value.tenantId, slug: value.tenantSlug });
  if (!tenant) throw new SharedOidcBrowserError();
  return {
    tenantId: tenant.id,
    tenantSlug: tenant.slug,
    providerSlug: canonicalProviderSlug(value.providerSlug),
    authorityRevision: exactPositiveRevision(value.authorityRevision),
    runtimeEpoch: Number(value.runtimeEpoch),
    runtimeKey: value.runtimeKey,
  };
}

function assertNoCredentialFields(value: unknown): void {
  if (Array.isArray(value)) {
    value.forEach(assertNoCredentialFields);
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.toLowerCase();
    if (
      normalized.includes('token')
      || normalized.includes('secret')
      || normalized.includes('password')
      || normalized.includes('verifier')
      || normalized === 'state'
      || normalized === 'nonce'
    ) {
      throw new SharedOidcBrowserError();
    }
    assertNoCredentialFields(child);
  }
}

async function uniformJson(response: Response): Promise<unknown> {
  if (!response.ok) throw new SharedOidcBrowserError();
  try {
    return await response.json();
  } catch {
    throw new SharedOidcBrowserError();
  }
}

function exactAuthorizeUrl(value: unknown): string {
  if (!isRecord(value) || Object.keys(value).join(',') !== 'url' || typeof value.url !== 'string') {
    throw new SharedOidcBrowserError();
  }
  let url: URL;
  try {
    url = new URL(value.url);
  } catch {
    throw new SharedOidcBrowserError();
  }
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '') {
    throw new SharedOidcBrowserError();
  }
  return url.toString();
}

function exactCallbackResponse(value: unknown): SharedOidcCallbackResponse {
  assertNoCredentialFields(value);
  if (!isRecord(value)) throw new SharedOidcBrowserError();
  const expected = [
    'assignment_revision',
    'authority_revision',
    'tenant_id',
    'tenant_slug',
    'user',
  ];
  if (Object.keys(value).sort().join(',') !== expected.join(',')) {
    throw new SharedOidcBrowserError();
  }
  if (
    !isRecord(value.user)
    || typeof value.tenant_id !== 'string'
    || typeof value.tenant_slug !== 'string'
  ) {
    throw new SharedOidcBrowserError();
  }
  return {
    user: value.user,
    tenant_id: value.tenant_id,
    tenant_slug: canonicalTenantSlug(value.tenant_slug),
    authority_revision: exactPositiveRevision(value.authority_revision),
    assignment_revision: exactPositiveRevision(value.assignment_revision),
  };
}

function exactCallbackParameters(search: URLSearchParams): { code: string; state: string } {
  const error = search.getAll('error');
  const codes = search.getAll('code');
  const states = search.getAll('state');
  if (
    error.length !== 0
    || codes.length !== 1
    || states.length !== 1
    || codes[0].length === 0
    || states[0].length === 0
    || codes[0].length > MAX_CALLBACK_VALUE_BYTES
    || states[0].length > MAX_CALLBACK_VALUE_BYTES
  ) {
    throw new SharedOidcBrowserError();
  }
  return { code: codes[0], state: states[0] };
}

function assertPendingRuntime(
  pending: PendingSharedOidcFlow,
  runtime: TenantRuntimeAuthority,
): void {
  const current = runtime.current();
  if (
    current.epoch !== pending.runtimeEpoch
    || current.key !== pending.runtimeKey
    || current.scope.kind !== 'anonymous'
  ) {
    throw new SharedOidcBrowserError();
  }
}

/**
 * Consumes an owner-plane-delivered opaque URL fragment through the exact
 * shared entry endpoint. The server response—not the fragment—supplies the
 * tenant/provider/mode authority. Nothing bearer-capable is written to
 * browser storage.
 */
export async function beginEnterpriseSharedOidc(
  tokenFragment: string,
  dependencies: SharedOidcBrowserDependencies,
): Promise<string> {
  // The fragment is stripped synchronously before parsing or network I/O so a
  // screenshot, navigation, exception, or retry cannot retain the bearer.
  dependencies.replaceUrl('/auth/shared/oidc/entry');
  dependencies.sessionStorage.removeItem(PENDING_KEY);
  try {
    const entryToken = tokenFragment.startsWith('#') ? tokenFragment.slice(1) : '';
    if (
      entryToken.length < 43
      || entryToken.length > 512
      || !/^[A-Za-z0-9_-]+$/.test(entryToken)
    ) {
      throw new SharedOidcBrowserError();
    }
    const current = dependencies.runtime.current();
    if (current.scope.kind !== 'anonymous') throw new SharedOidcBrowserError();
    const response = await dependencies.fetch(
      '/api/auth/shared/oidc/entry',
      {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entry_token: entryToken }),
      },
    );
    const entry = parseEntry(await uniformJson(response));
    dependencies.runtime.assertCurrent(current);
    dependencies.sessionStorage.setItem(PENDING_KEY, serializePending({
      tenantId: entry.tenant.tenantId,
      tenantSlug: entry.tenant.slug,
      providerSlug: entry.providerSlug,
      authorityRevision: entry.authorityRevision,
      runtimeEpoch: current.epoch,
      runtimeKey: current.key,
    }));
    return entry.url;
  } catch {
    dependencies.sessionStorage.removeItem(PENDING_KEY);
    throw new SharedOidcBrowserError();
  }
}

/**
 * Discover only the login labels for one canonical shared tenant selector.
 *
 * The server answers a uniform 401 for an unknown tenant AND for a known
 * tenant with no SSO provider (anti-enumeration by design). From the login
 * page's point of view both mean "no SSO here": resolve to an empty list so
 * the page offers local credentials without logging or retrying. Any other
 * failure is still a `SharedOidcBrowserError`.
 */
export async function discoverEnterpriseSharedOidcProviders(
  tenantSlug: string,
  dependencies: SharedOidcBrowserDependencies,
): Promise<SharedOidcLoginProvider[]> {
  return (await discoverEnterpriseSharedLoginMethods(tenantSlug, dependencies)).providers;
}

/**
 * Tenant-local login discovery: enabled provider labels plus the tenant's
 * password sign-in flag, from the one uniform discovery call.
 */
export async function discoverEnterpriseSharedLoginMethods(
  tenantSlug: string,
  dependencies: SharedOidcBrowserDependencies,
): Promise<SharedLoginMethods> {
  try {
    const tenant = canonicalTenantSlug(tenantSlug);
    const response = await dependencies.fetch('/api/auth/shared/oidc/providers', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenant_slug: tenant }),
    });
    // Anti-enumeration: the server answers 401 for an unknown tenant and for a
    // known tenant with no provider alike. Treat it as "no SSO, password
    // sign-in on" — not a failure (no error state, no retry storm).
    if (response.status === 401) return { providers: [], localPasswordEnabled: true };
    return parseLoginMethods(await uniformJson(response));
  } catch {
    throw new SharedOidcBrowserError();
  }
}

/**
 * Start a normal repeat-login transaction from non-authoritative selectors.
 * The server response supplies exact tenant/provider authority and only then
 * is the pending browser epoch recorded for callback verification.
 */
export async function startEnterpriseSharedOidcLogin(
  tenantSlug: string,
  providerSlug: string,
  dependencies: SharedOidcBrowserDependencies,
): Promise<string> {
  dependencies.sessionStorage.removeItem(PENDING_KEY);
  try {
    const tenant = canonicalTenantSlug(tenantSlug);
    const provider = canonicalProviderSlug(providerSlug);
    const current = dependencies.runtime.current();
    if (current.scope.kind !== 'anonymous') throw new SharedOidcBrowserError();
    const response = await dependencies.fetch('/api/auth/shared/oidc/start', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenant_slug: tenant, provider_slug: provider }),
    });
    const entry = parseEntry(await uniformJson(response));
    if (entry.tenant.slug !== tenant || entry.providerSlug !== provider) {
      throw new SharedOidcBrowserError();
    }
    dependencies.runtime.assertCurrent(current);
    dependencies.sessionStorage.setItem(PENDING_KEY, serializePending({
      tenantId: entry.tenant.tenantId,
      tenantSlug: entry.tenant.slug,
      providerSlug: entry.providerSlug,
      authorityRevision: entry.authorityRevision,
      runtimeEpoch: current.epoch,
      runtimeKey: current.key,
    }));
    return entry.url;
  } catch {
    dependencies.sessionStorage.removeItem(PENDING_KEY);
    throw new SharedOidcBrowserError();
  }
}

/**
 * Completes the shared callback using only code + opaque state. The callback
 * response is cookies-only; this function never reads a token field. It then
 * proves `/auth/me` and the authenticated tenant bootstrap agree before
 * returning an exact tenant-shell destination.
 */
export async function completeEnterpriseSharedOidc(
  search: URLSearchParams,
  dependencies: SharedOidcBrowserDependencies,
): Promise<SharedOidcBrowserResult> {
  dependencies.replaceUrl(CALLBACK_PATH);
  let pending: PendingSharedOidcFlow;
  try {
    pending = readPending(dependencies.sessionStorage);
    assertPendingRuntime(pending, dependencies.runtime);
  } catch {
    dependencies.sessionStorage.removeItem(PENDING_KEY);
    throw new SharedOidcBrowserError();
  }

  // Consume browser-side intent before the network exchange. Server state is
  // one-time too, so a refresh/replay can never reuse this flow.
  dependencies.sessionStorage.removeItem(PENDING_KEY);
  const capturedRuntime = dependencies.runtime.current();
  try {
    const callback = exactCallbackParameters(search);
    const callbackHttpResponse = await dependencies.fetch('/api/auth/shared/oidc/callback', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(callback),
    });
    if (callbackHttpResponse.ok) dependencies.onCookieMutation?.();
    const callbackResponse = exactCallbackResponse(await uniformJson(callbackHttpResponse));
    if (
      callbackResponse.tenant_id.toLowerCase() !== pending.tenantId
      || callbackResponse.tenant_slug !== pending.tenantSlug
      || callbackResponse.authority_revision < pending.authorityRevision
    ) {
      throw new SharedOidcBrowserError();
    }

    const currentUserValue = await uniformJson(await dependencies.fetch('/api/auth/me', {
      method: 'GET',
      credentials: 'include',
    }));
    assertNoCredentialFields(currentUserValue);
    if (!isRecord(currentUserValue)) throw new SharedOidcBrowserError();
    const currentUser = currentUserValue as ServerAuthIdentity & Record<string, unknown>;
    const verified = verifyServerAuthIdentity(currentUser, pending.tenantSlug);
    if (
      verified.activeTenant === null
      || verified.activeTenant.id !== callbackResponse.tenant_id.toLowerCase()
      || verified.activeTenant.slug !== callbackResponse.tenant_slug
    ) {
      throw new SharedOidcBrowserError();
    }

    const bootstrapValue = await uniformJson(await dependencies.fetch(
      '/api/auth/tenant-bootstrap',
      { method: 'GET', credentials: 'include' },
    ));
    assertNoCredentialFields(bootstrapValue);
    const tenant = validateTenantCapabilitySnapshot(bootstrapValue, {
      userId: currentUser.id,
      tenant: verified.activeTenant,
      roles: currentUser.roles,
      permissions: Array.isArray(currentUser.permissions)
        ? currentUser.permissions.filter((value): value is string => typeof value === 'string')
        : [],
    });
    if (
      tenant.identity.authorizationRevision !== callbackResponse.authority_revision
      || tenant.plan.assignmentRevision !== callbackResponse.assignment_revision
    ) {
      throw new SharedOidcBrowserError();
    }
    dependencies.runtime.assertCurrent(capturedRuntime);
    return {
      user: currentUser,
      tenant,
      // The tenant's product root, reached by a full load (see the callback
      // page): the router that ran the callback has no tenant basename.
      destination: tenantShellPath(verified.activeTenant.slug),
    };
  } catch {
    throw new SharedOidcBrowserError();
  }
}

export const enterpriseSharedOidcContract = {
  callbackPath: CALLBACK_PATH,
  pendingStorageKey: PENDING_KEY,
} as const;
