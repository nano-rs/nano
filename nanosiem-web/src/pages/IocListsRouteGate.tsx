// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3467 — gate `/rules/ioc-lists` on `capabilities.iocLists`.
 *
 * The code-free IOC list API (`/api/ioc-lists`, NAN-3038) is mounted only on
 * hosted-shared tenants. Open-core and dedicated builds 404 it, so a deep link
 * renders an explicit notice instead of a page whose every request fails.
 */

import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { useCapabilities } from '@/hooks/use-capabilities';

export function IocListsRouteGate({ children }: { children: ReactNode }) {
  const { capabilities } = useCapabilities();
  if (capabilities.iocLists) return <>{children}</>;
  return <IocListsUnavailable />;
}

function IocListsUnavailable() {
  return (
    <div className="flex h-full flex-col items-center justify-center px-8 text-center">
      <Shield className="mb-3 h-5 w-5 text-muted-foreground" strokeWidth={1.5} />
      <h1 className="mb-1 text-[13px] font-semibold text-foreground">IOC lists are not available</h1>
      <p className="mb-4 max-w-md text-[12px] text-muted-foreground">
        This deployment does not include code-free IOC lists. Upload indicators as a lookup table and
        match them with <span className="font-mono">| lookup</span> in searches and detections.
      </p>
      <Link
        to="/rules/lookup-tables"
        className="inline-flex h-7 items-center rounded-md border border-border px-3 text-[12px] text-foreground hover:bg-muted"
      >
        Go to Lookup Tables
      </Link>
    </div>
  );
}
