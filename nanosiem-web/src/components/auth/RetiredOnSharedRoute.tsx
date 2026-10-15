// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useSharedTenant } from '@/hooks/use-shared-tenant';

/**
 * A surface retired on hosted-shared tenants (NAN-3620). Shared sessions are
 * redirected to `to`; open core and dedicated render `children` unchanged.
 */
export function RetiredOnSharedRoute({ to, children }: { to: string; children: ReactNode }) {
  const shared = useSharedTenant();
  if (shared) return <Navigate to={to} replace />;
  return <>{children}</>;
}
