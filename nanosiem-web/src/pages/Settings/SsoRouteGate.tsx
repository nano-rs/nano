// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3378 — gate the SSO provider routes (`/settings/oidc`, `/settings/sso`)
 * on `capabilities.sso`.
 *
 * The OIDC admin API (`/api/settings/oidc`) only exists in builds that ship
 * the SSO surface. Without this gate a deep link mounts the providers page
 * against an API that 404s. A notice is rendered instead of a redirect so a
 * shared-tenant deep link survives the brief fail-closed window before the
 * tenant plan loads.
 */

import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { KeyRound } from 'lucide-react';
import { useCapabilities } from '@/hooks/use-capabilities';

export function SsoRouteGate({ children }: { children: ReactNode }) {
  const { capabilities } = useCapabilities();
  if (capabilities.sso) return <>{children}</>;
  return <SsoUnavailable />;
}

function SsoUnavailable() {
  return (
    <div className="flex h-full flex-col items-center justify-center px-8 text-center">
      <KeyRound className="mb-3 h-5 w-5 text-muted-foreground" strokeWidth={1.5} />
      <h1 className="mb-1 text-[13px] font-semibold text-foreground">Single sign-on is not available</h1>
      <p className="mb-4 max-w-md text-[12px] text-muted-foreground">
        This deployment does not include SAML / OIDC providers. Local accounts and MFA are unaffected.
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
