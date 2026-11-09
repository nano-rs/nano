// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3378 — gate the SSO provider routes (`/settings/oidc`, `/settings/sso`)
 * on `capabilities.sso`.
 *
 * The OIDC admin API (`/api/settings/oidc`) only exists in builds that ship
 * the SSO surface. Without this gate a deep link mounts the providers page
 * against an API that 404s. A notice is rendered instead of a redirect so a
 * shared-tenant deep link survives the brief fail-closed window before the
 * entitlement loads.
 */

import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { KeyRound } from 'lucide-react';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useTierContext } from '@/hooks/use-tier';

/**
 * Fail closed on both build capability and live edition. Every licensed v2
 * deployment receives SSO; open builds do not ship the handlers.
 */
export function SsoRouteGate({ children }: { children: ReactNode }) {
  const { capabilities } = useCapabilities();
  const { status, loading } = useTierContext();
  if (!capabilities.sso) return <SsoUnavailable reason="build" />;
  if (status?.limits?.sso_enabled === true) return <>{children}</>;
  if (loading && !status) return null;
  return <SsoUnavailable reason="edition" />;
}

function SsoUnavailable({ reason }: { reason: 'build' | 'edition' }) {
  return (
    <div className="flex h-full flex-col items-center justify-center px-8 text-center">
      <KeyRound className="mb-3 h-5 w-5 text-muted-foreground" strokeWidth={1.5} />
      <h1 className="mb-1 text-[13px] font-semibold text-foreground">Single sign-on is not available</h1>
      <p className="mb-4 max-w-md text-[12px] text-muted-foreground">
        {reason === 'build'
          ? 'This deployment does not include SAML / OIDC providers. Local accounts and MFA are unaffected.'
          : 'This edition does not include SAML / OIDC providers. Local accounts and MFA are unaffected.'}
      </p>
      <Link
        to="/settings"
        className="inline-flex h-7 items-center rounded-md border border-border px-3 text-[12px] text-foreground hover:bg-muted"
      >
        Back to Settings
      </Link>
    </div>
  );
}
