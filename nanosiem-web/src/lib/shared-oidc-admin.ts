// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Hosted-shared SSO provider administration adapter (NAN-2361 wave 5).
 *
 * The settings page was written against the dedicated `/api/settings/oidc`
 * family. On a hosted-shared tenant that family is READ-only; every change
 * goes through the step-up admin API (`/api/auth/shared/oidc/admin/...`):
 * fresh MFA within five minutes, exact Origin, an idempotency key per
 * request and an immutable revision ledger. This module maps the page's
 * dedicated request shapes onto that API so the page keeps one code path:
 *
 *   create           -> POST providers (+ disable when `enabled: false`)
 *   update           -> PUT providers/{id}; client_secret -> rotate-secret;
 *                       enabled change -> enable | disable
 *   delete           -> DELETE providers/{id} (retire: disabled, hidden,
 *                       slug released; identities and revisions kept)
 *   enable / disable -> POST providers/{id}/enable | disable
 *
 * Stale MFA answers 403 `oidc_provider_admin_denied`; the page wraps every
 * call in `useStepUpMfa().run(...)` which prompts for a code and retries.
 */

import { api } from '@/lib/api';
import type {
  CreateOidcProviderRequest,
  OidcProviderSummary,
  SharedOidcAdminProvider,
  UpdateOidcProviderRequest,
} from '@/lib/api/types';

function idempotencyKey(): string {
  return globalThis.crypto.randomUUID().toLowerCase();
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TYPEID_ALPHABET = '0123456789abcdefghjkmnpqrstvwxyz';

/**
 * NAN-3905: the settings list (`/api/settings/oidc`, what the page draws)
 * names a provider by its `oidc_<base32>` TypeID, while the step-up admin
 * API (`/api/auth/shared/oidc/admin/providers/{provider_id}`) takes the raw
 * UUID. Passing the TypeID through made enable / update / delete answer 404
 * `route_not_available` on hosted tenants. Every admin call normalizes here.
 */
export function adminProviderId(id: string): string {
  if (UUID_PATTERN.test(id)) return id.toLowerCase();
  const match = /^oidc_([0-9a-z]{26})$/.exec(id);
  if (!match || match[1][0] > '7') throw new Error('Unrecognized SSO provider id');
  let n = 0n;
  for (const char of match[1]) {
    const value = TYPEID_ALPHABET.indexOf(char);
    if (value < 0) throw new Error('Unrecognized SSO provider id');
    n = (n << 5n) | BigInt(value);
  }
  const hex = n.toString(16).padStart(32, '0');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Render a step-up admin provider in the dedicated summary shape the page draws. */
export function sharedAdminProviderToSummary(p: SharedOidcAdminProvider, previous?: OidcProviderSummary): OidcProviderSummary {
  return {
    id: p.id,
    name: p.name,
    slug: p.slug,
    issuer: p.issuer,
    enabled: p.enabled,
    scopes: p.scopes,
    group_claim: p.groupClaim ?? undefined,
    access_policy: p.accessPolicy,
    google_service_account_configured: p.googleServiceAccountConfigured,
    created_at: previous?.created_at ?? new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
}

export async function sharedCreateOidcProvider(request: CreateOidcProviderRequest): Promise<OidcProviderSummary> {
  const created = await api.createSharedOidcAdminProvider({
    idempotency_key: idempotencyKey(),
    name: request.name,
    slug: request.slug,
    issuer: request.issuer,
    client_id: request.client_id,
    client_secret: request.client_secret,
    scopes: request.scopes && request.scopes.length > 0 ? request.scopes : ['openid', 'email', 'profile'],
    group_claim: request.group_claim ?? null,
    access_policy: request.access_policy,
    google_service_account: request.google_service_account,
    clear_google_service_account: request.clear_google_service_account,
  });
  let provider = created.provider;
  if (request.enabled === true && !provider.enabled) {
    provider = (await api.setSharedOidcAdminProviderEnabled(provider.id, idempotencyKey(), true)).provider;
  }
  if (request.enabled === false && provider.enabled) {
    provider = (await api.setSharedOidcAdminProviderEnabled(provider.id, idempotencyKey(), false)).provider;
  }
  return sharedAdminProviderToSummary(provider);
}

export async function sharedUpdateOidcProvider(
  current: OidcProviderSummary,
  currentClientId: string | undefined,
  request: UpdateOidcProviderRequest,
): Promise<OidcProviderSummary> {
  // The step-up API replaces the whole configuration; fill unchanged fields
  // from the current row. `client_id` is never returned by the settings
  // read, so the admin API's own view supplies it when the form left it blank.
  const id = adminProviderId(current.id);
  const clientId = request.client_id
    ?? currentClientId
    ?? (await api.listSharedOidcAdminProviders()).providers.find(p => p.id.toLowerCase() === id)?.clientId;
  if (!clientId) throw new Error('The provider could not be read from the SSO admin ledger.');
  let provider = (await api.updateSharedOidcAdminProvider(id, {
    idempotency_key: idempotencyKey(),
    name: request.name ?? current.name,
    issuer: request.issuer ?? current.issuer,
    client_id: clientId,
    scopes: request.scopes && request.scopes.length > 0 ? request.scopes : current.scopes,
    group_claim: request.group_claim ?? current.group_claim ?? null,
    access_policy: request.access_policy,
    google_service_account: request.google_service_account,
    clear_google_service_account: request.clear_google_service_account,
  })).provider;
  if (request.client_secret) {
    provider = (await api.rotateSharedOidcAdminProviderSecret(id, idempotencyKey(), request.client_secret)).provider;
  }
  if (request.enabled !== undefined && request.enabled !== provider.enabled) {
    provider = (await api.setSharedOidcAdminProviderEnabled(id, idempotencyKey(), request.enabled)).provider;
  }
  return sharedAdminProviderToSummary(provider, current);
}

export async function sharedDeleteOidcProvider(id: string): Promise<void> {
  await api.deleteSharedOidcAdminProvider(adminProviderId(id), idempotencyKey());
}

export async function sharedSetOidcProviderEnabled(current: OidcProviderSummary, enabled: boolean): Promise<OidcProviderSummary> {
  const result = await api.setSharedOidcAdminProviderEnabled(adminProviderId(current.id), idempotencyKey(), enabled);
  return sharedAdminProviderToSummary(result.provider, current);
}
