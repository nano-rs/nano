// SPDX-License-Identifier: AGPL-3.0-or-later

export type DeploymentMode = 'managed' | 'enterprise_shared' | 'self-hosted' | 'demo';

export interface ActiveTenant {
  id: string;
  slug: string;
}

export type TenantRuntimeScope =
  | { kind: 'anonymous' }
  | { kind: 'dedicated'; userId: string }
  | { kind: 'demo'; userId: string }
  | { kind: 'enterprise_shared'; userId: string; tenant: ActiveTenant };

export interface TenantRuntimeSnapshot {
  epoch: number;
  key: string;
  scope: TenantRuntimeScope;
}

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TENANT_SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export class TenantRuntimeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TenantRuntimeError';
  }
}

export class StaleTenantRuntimeError extends TenantRuntimeError {
  constructor() {
    super('Response belongs to an inactive tenant runtime');
    this.name = 'StaleTenantRuntimeError';
  }
}

export function exactActiveTenant(value: unknown): ActiveTenant | null {
  if (!value || typeof value !== 'object') return null;
  const candidate = value as Record<string, unknown>;
  if (typeof candidate.id !== 'string' || !UUID_PATTERN.test(candidate.id)) return null;
  if (typeof candidate.slug !== 'string' || !TENANT_SLUG_PATTERN.test(candidate.slug)) return null;
  return { id: candidate.id.toLowerCase(), slug: candidate.slug };
}

export function authenticatedRuntimeScope(input: {
  userId: string;
  roles?: readonly string[];
  activeTenant?: unknown;
  deploymentMode: DeploymentMode;
}): TenantRuntimeScope {
  const tenant = exactActiveTenant(input.activeTenant);
  if (input.deploymentMode === 'enterprise_shared' && tenant === null) {
    throw new TenantRuntimeError(
      'enterprise_shared authentication requires an exact active_tenant',
    );
  }
  if (tenant) {
    if (input.deploymentMode !== 'enterprise_shared') {
      throw new TenantRuntimeError('A dedicated authentication response cannot carry active_tenant');
    }
    return { kind: 'enterprise_shared', userId: input.userId, tenant };
  }
  if (input.deploymentMode === 'demo' || input.roles?.includes('demo_analyst')) {
    return { kind: 'demo', userId: input.userId };
  }
  return { kind: 'dedicated', userId: input.userId };
}

function scopeIdentity(scope: TenantRuntimeScope): string {
  switch (scope.kind) {
    case 'anonymous':
      return 'anonymous';
    case 'dedicated':
      return `dedicated:${scope.userId}`;
    case 'demo':
      return `demo:${scope.userId}`;
    case 'enterprise_shared':
      return `enterprise_shared:${scope.tenant.id}:${scope.userId}`;
  }
}

export class TenantRuntimeAuthority {
  private snapshot: TenantRuntimeSnapshot = {
    epoch: 0,
    key: 'anonymous:0',
    scope: { kind: 'anonymous' },
  };

  current(): TenantRuntimeSnapshot {
    return this.snapshot;
  }

  activate(scope: TenantRuntimeScope): TenantRuntimeSnapshot {
    const identity = scopeIdentity(scope);
    if (scopeIdentity(this.snapshot.scope) === identity) return this.snapshot;
    const epoch = this.snapshot.epoch + 1;
    this.snapshot = { epoch, key: `${identity}:${epoch}`, scope };
    return this.snapshot;
  }

  assertCurrent(captured: TenantRuntimeSnapshot): void {
    if (captured.epoch !== this.snapshot.epoch || captured.key !== this.snapshot.key) {
      throw new StaleTenantRuntimeError();
    }
  }

  isCurrent(captured: TenantRuntimeSnapshot): boolean {
    return captured.epoch === this.snapshot.epoch && captured.key === this.snapshot.key;
  }

  runIfCurrent(captured: TenantRuntimeSnapshot, callback: () => void): boolean {
    if (!this.isCurrent(captured)) return false;
    callback();
    return true;
  }

  async guard<T>(captured: TenantRuntimeSnapshot, operation: Promise<T>): Promise<T> {
    const result = await operation;
    this.assertCurrent(captured);
    return result;
  }
}

export const browserTenantRuntime = new TenantRuntimeAuthority();

/**
 * A refresh may replace the origin-wide cookie session and active tenant while
 * the original request is suspended. Reassert the captured runtime before the
 * caller reads the refreshed bearer or retries any side-effecting request.
 */
export async function refreshForCapturedRuntime(
  authority: TenantRuntimeAuthority,
  captured: TenantRuntimeSnapshot,
  refresh: () => Promise<boolean>,
): Promise<boolean> {
  const refreshed = await refresh();
  authority.assertCurrent(captured);
  return refreshed;
}

/**
 * Product keys are tenant-namespaced only in shared mode. Dedicated, demo and
 * open-core callers retain their existing byte-for-byte keys.
 */
export function tenantStorageKey(scope: TenantRuntimeScope, key: string): string {
  if (scope.kind !== 'enterprise_shared') return key;
  return `nano:tenant:${scope.tenant.id}:${key}`;
}

export function tenantQueryKey(
  scope: TenantRuntimeScope,
  key: readonly unknown[],
): readonly unknown[] {
  if (scope.kind !== 'enterprise_shared') return key;
  return ['tenant', scope.tenant.id, ...key];
}

export function tenantModuleCacheKey(
  snapshot: TenantRuntimeSnapshot,
  key: string,
): string {
  return `${snapshot.key}:${key}`;
}

export interface BrowserStorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export function tenantStorage(storage: BrowserStorageLike, scope: TenantRuntimeScope) {
  return {
    getItem: (key: string) => storage.getItem(tenantStorageKey(scope, key)),
    setItem: (key: string, value: string) =>
      storage.setItem(tenantStorageKey(scope, key), value),
    removeItem: (key: string) => storage.removeItem(tenantStorageKey(scope, key)),
  };
}
