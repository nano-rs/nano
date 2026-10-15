// SPDX-License-Identifier: AGPL-3.0-or-later

import { tenantLoginPath } from './tenant-auth-shell.ts';
import { exactActiveTenant, type TenantRuntimeAuthority } from './tenant-runtime.ts';

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,512}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class SharedMembershipAcceptanceBrowserError extends Error {
  constructor() {
    super('Membership acceptance failed. Sign in again and request a fresh invitation.');
    this.name = 'SharedMembershipAcceptanceBrowserError';
  }
}

export interface SharedMembershipAcceptanceBrowserDependencies {
  fetch: typeof globalThis.fetch;
  runtime: TenantRuntimeAuthority;
  replaceUrl: (path: string) => void;
  randomUuid: () => string;
  /** The tab's in-memory bearer. The pooled host keeps one HttpOnly access
   * cookie PER TENANT, so a cookie-authenticated POST is refused as soon as
   * the browser holds two (NAN-3788); the SPA's API calls always send the
   * bearer with `credentials: 'omit'`. */
  bearer: () => string | null;
  /** The page's own path without the fragment, tenant prefix included
   * (`/t/<slug>/auth/shared/memberships/accept`). */
  acceptancePath: string;
}

const ACCEPTANCE_PATH_PATTERN = /^(?:\/t\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)?\/auth\/shared\/memberships\/accept$/;

export interface SharedMembershipAcceptanceBrowserResult {
  targetTenantId: string;
  targetTenantSlug: string;
  targetLogin: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function positiveRevision(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new SharedMembershipAcceptanceBrowserError();
  }
  return Number(value);
}

function assertNoCredentialFields(value: unknown): void {
  if (Array.isArray(value)) {
    value.forEach(assertNoCredentialFields);
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (/token|secret|password|verifier|nonce|state/i.test(key)) {
      throw new SharedMembershipAcceptanceBrowserError();
    }
    assertNoCredentialFields(child);
  }
}

async function postWithSingleNetworkRetry(
  body: string,
  bearer: string,
  dependencies: SharedMembershipAcceptanceBrowserDependencies,
): Promise<Response> {
  let lastNetworkError: unknown;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      return await dependencies.fetch('/api/auth/shared/memberships/accept', {
        method: 'POST',
        credentials: 'omit',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` },
        body,
      });
    } catch (error) {
      lastNetworkError = error;
    }
  }
  throw lastNetworkError;
}

export async function acceptEnterpriseSharedMembership(
  fragment: string,
  dependencies: SharedMembershipAcceptanceBrowserDependencies,
): Promise<SharedMembershipAcceptanceBrowserResult> {
  if (!ACCEPTANCE_PATH_PATTERN.test(dependencies.acceptancePath)) {
    throw new SharedMembershipAcceptanceBrowserError();
  }
  dependencies.replaceUrl(dependencies.acceptancePath);
  const invitationToken = fragment.startsWith('#') ? fragment.slice(1) : '';
  const captured = dependencies.runtime.current();
  const bearer = dependencies.bearer();
  if (
    captured.scope.kind !== 'enterprise_shared'
    || !TOKEN_PATTERN.test(invitationToken)
    || !bearer
    || !/^\S+$/.test(bearer)
  ) {
    throw new SharedMembershipAcceptanceBrowserError();
  }
  const idempotencyKey = dependencies.randomUuid().toLowerCase();
  if (!UUID_PATTERN.test(idempotencyKey)) {
    throw new SharedMembershipAcceptanceBrowserError();
  }

  let response: Response;
  try {
    response = await postWithSingleNetworkRetry(JSON.stringify({
      invitation_token: invitationToken,
      idempotency_key: idempotencyKey,
    }), bearer, dependencies);
  } catch {
    throw new SharedMembershipAcceptanceBrowserError();
  }
  if (!response.ok) throw new SharedMembershipAcceptanceBrowserError();

  let document: unknown;
  try {
    document = await response.json();
  } catch {
    throw new SharedMembershipAcceptanceBrowserError();
  }
  assertNoCredentialFields(document);
  if (
    !isRecord(document)
    || Object.keys(document).sort().join(',')
      !== 'assignmentRevision,authorityRevision,deploymentMode,idempotentReplay,planCode,planRevision,sourceTenantId,targetMembershipId,targetTenant'
    || document.deploymentMode !== 'enterprise_shared'
    || typeof document.sourceTenantId !== 'string'
    || document.sourceTenantId.toLowerCase() !== captured.scope.tenant.id
    || typeof document.targetMembershipId !== 'string'
    || !UUID_PATTERN.test(document.targetMembershipId)
    || typeof document.planCode !== 'string'
    || document.planCode.length === 0
    || typeof document.idempotentReplay !== 'boolean'
  ) {
    throw new SharedMembershipAcceptanceBrowserError();
  }
  positiveRevision(document.planRevision);
  positiveRevision(document.assignmentRevision);
  positiveRevision(document.authorityRevision);
  if (!isRecord(document.targetTenant)) {
    throw new SharedMembershipAcceptanceBrowserError();
  }
  const target = exactActiveTenant({
    id: document.targetTenant.tenantId,
    slug: document.targetTenant.slug,
  });
  if (!target || target.id === captured.scope.tenant.id) {
    throw new SharedMembershipAcceptanceBrowserError();
  }
  try {
    dependencies.runtime.assertCurrent(captured);
  } catch {
    throw new SharedMembershipAcceptanceBrowserError();
  }
  return {
    targetTenantId: target.id,
    targetTenantSlug: target.slug,
    targetLogin: tenantLoginPath(target.slug),
  };
}
