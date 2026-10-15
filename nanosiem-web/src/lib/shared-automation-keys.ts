// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * API-key wire adapter for hosted-shared tenants (NAN-2361).
 *
 * In hosted shared deployments `/api/api-keys` is served by the tenant
 * automation-key registry (`enterprise/src/handlers/
 * shared_automation_keys.rs`), whose contract is camelCase and lifecycle-
 * shaped (`status: active | revoked`, terminal revoke via DELETE, rotate via
 * `POST …/rotate`) while the Access Control page was written against the
 * dedicated snake_case shapes (`api_keys`, `key_prefix`, `enabled`,
 * `rate_limit`, `POST …/reset`). Everything here is a pure mapping so the
 * page keeps one set of types and `AccessControlApi` branches once per call.
 *
 * Shared-only semantics the page must honour:
 *   - `status` is `active | revoked | expired`; there is no enable / disable.
 *     `enabled` is derived (`status !== 'revoked'`) so the existing pills work.
 *   - Revoke (`DELETE`) is terminal; the row stays listed as `revoked`.
 *   - Rotate returns a new secret exactly once, like create.
 *   - The create / update bodies are `deny_unknown_fields`: a snake_case key
 *     is a 400, so the request mappers never spread the caller's object.
 */
import type {
  ApiKeyCreatedResponse,
  ApiKeyListResponse,
  ApiKeySummary,
  CreateApiKeyRequest,
  UpdateApiKeyRequest,
} from './api/types';

/** `TenantAutomationKeySummary` (`#[serde(rename_all = "camelCase")]`). */
export interface SharedAutomationKeySummary {
  id: string;
  name: string;
  description: string | null;
  keyPrefix: string;
  permissions: string[];
  rateLimitPerMinute: number;
  status: 'active' | 'revoked';
  keyRevision: number;
  expiresAt: string | null;
  lastUsedAt: string | null;
  createdAt: string;
  revokedAt: string | null;
}

/** `SharedAutomationKeyList`. */
export interface SharedAutomationKeyList {
  apiKeys: SharedAutomationKeySummary[];
  total: number;
}

/** `CreatedTenantAutomationKey`: the summary flattened plus the one-time secret. */
export interface CreatedSharedAutomationKey extends SharedAutomationKeySummary {
  secret: string;
}

/** `CreateTenantAutomationKey` (`deny_unknown_fields`). */
export interface CreateSharedAutomationKey {
  name: string;
  description?: string;
  permissions: string[];
  rateLimitPerMinute?: number;
  expiresAt?: string;
}

/** `UpdateTenantAutomationKey` (`deny_unknown_fields`, tri-state). */
export interface UpdateSharedAutomationKey {
  name?: string;
  description?: string | null;
  permissions?: string[];
  rateLimitPerMinute?: number | null;
  expiresAt?: string | null;
}

export type SharedApiKeyStatus = 'active' | 'revoked' | 'expired';

/** Lifecycle status the page shows; expiry is derived because the registry
 * keeps `status = active` on an expired key (authentication already denies it). */
export function sharedKeyStatus(key: Pick<SharedAutomationKeySummary, 'status' | 'expiresAt'>, now = Date.now()): SharedApiKeyStatus {
  if (key.status === 'revoked') return 'revoked';
  if (key.expiresAt && new Date(key.expiresAt).getTime() <= now) return 'expired';
  return 'active';
}

export function apiKeySummaryFromShared(key: SharedAutomationKeySummary, now = Date.now()): ApiKeySummary {
  const status = sharedKeyStatus(key, now);
  return {
    id: key.id,
    name: key.name,
    description: key.description ?? undefined,
    key_prefix: key.keyPrefix,
    permissions: key.permissions,
    enabled: status !== 'revoked',
    status,
    expires_at: key.expiresAt ?? undefined,
    rate_limit: key.rateLimitPerMinute,
    last_used_at: key.lastUsedAt ?? undefined,
    created_at: key.createdAt,
    revoked_at: key.revokedAt ?? undefined,
    key_revision: key.keyRevision,
  };
}

export function apiKeyListFromShared(list: SharedAutomationKeyList, now = Date.now()): ApiKeyListResponse {
  const keys = Array.isArray(list?.apiKeys) ? list.apiKeys : [];
  return {
    api_keys: keys.map(key => apiKeySummaryFromShared(key, now)),
    total: typeof list?.total === 'number' ? list.total : keys.length,
  };
}

/** Create and rotate both answer the flattened summary plus `secret`. */
export function apiKeyCreatedFromShared(created: CreatedSharedAutomationKey): ApiKeyCreatedResponse {
  return {
    id: created.id,
    key: created.secret,
    name: created.name,
    created_at: created.createdAt,
  };
}

export function sharedCreateRequest(request: CreateApiKeyRequest): CreateSharedAutomationKey {
  const body: CreateSharedAutomationKey = {
    name: request.name,
    permissions: request.permissions,
  };
  if (request.description !== undefined) body.description = request.description;
  if (request.rate_limit !== undefined) body.rateLimitPerMinute = request.rate_limit;
  if (request.expires_at !== undefined) body.expiresAt = request.expires_at;
  return body;
}

/** Omitted stays omitted, `null` stays `null` (clear), values pass through. */
export function sharedUpdateRequest(request: UpdateApiKeyRequest): UpdateSharedAutomationKey {
  const body: UpdateSharedAutomationKey = {};
  if (request.name !== undefined) body.name = request.name;
  if (request.description !== undefined) body.description = request.description;
  if (request.permissions !== undefined) body.permissions = request.permissions;
  if (request.rate_limit !== undefined) body.rateLimitPerMinute = request.rate_limit;
  if (request.expires_at !== undefined) body.expiresAt = request.expires_at;
  return body;
}

/**
 * Mirrors the registry's `valid_permission`: a tenant key never carries the
 * wildcard or an ambient platform (`operator:` / `support:` / `tenants:`)
 * permission. The page also intersects with the signed-in member's own
 * permissions because the registry only issues scopes the owner holds.
 */
export function isSharedKeyScope(permission: string): boolean {
  return permission.length > 0
    && permission.length <= 128
    && permission !== '*'
    && !permission.startsWith('operator:')
    && !permission.startsWith('support:')
    && !permission.startsWith('tenants:')
    && /^[a-z0-9:_-]+$/.test(permission);
}

/** Thrown for dedicated-only lifecycle verbs a shared tenant does not have. */
export class SharedApiKeyUnsupportedError extends Error {
  readonly verb: 'enable' | 'disable';

  constructor(verb: 'enable' | 'disable') {
    super(
      verb === 'enable'
        ? 'A revoked key cannot be re-enabled on a hosted-shared tenant; create a new key instead.'
        : 'Hosted-shared tenants revoke keys permanently; use Revoke instead of disable.',
    );
    this.name = 'SharedApiKeyUnsupportedError';
    this.verb = verb;
  }
}
