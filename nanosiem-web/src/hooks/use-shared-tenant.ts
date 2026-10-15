// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Whether the signed-in session belongs to a hosted-shared tenant
 * (the hosted shared deployment mode, NAN-2361). Pages use this only where
 * the WIRE CONTRACT genuinely differs from a dedicated deployment — members
 * are invited (no password) and carry roles on the membership (plus tenant
 * groups since wave 5), automation keys rotate/revoke instead of
 * reset/enable/disable, OIDC admin lives under `/api/auth/shared/oidc/admin`,
 * and MFA policy / AI providers / ClickHouse tiers are platform-owned.
 *
 * It is NOT a feature switch. Whether a surface is available comes from
 * `useCapabilities()` (plan components, platform AI availability) and from
 * `tenantSearchSurface()`; wave 8 removed every "hide on shared" gate that
 * had a tenant-scoped route behind it.
 */

import { useAuth } from '@/contexts/AuthContext';

export function useSharedTenant(): boolean {
  const { user } = useAuth();
  return user?.deployment_mode === 'enterprise_shared';
}
