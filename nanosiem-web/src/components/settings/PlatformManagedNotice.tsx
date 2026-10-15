// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * "Managed by the platform" notice for hosted-shared tenants (NAN-2361).
 *
 * Shared-mode settings routes answer with a typed `managed_by_platform`
 * verdict (`PlatformManagedSetting`) next to the platform defaults instead of
 * the pre-port 503. Pages render this notice in place of their editor when
 * the verdict is present; the values shown around it are read-only.
 */

import { Building2 } from 'lucide-react';
import type { PlatformManagedSetting } from '@/lib/api';

export function PlatformManagedNotice({ verdict, title }: { verdict: PlatformManagedSetting; title?: string }) {
  return (
    <div className="rounded-md border border-border bg-card/40 p-3 flex items-start gap-2.5" role="note">
      <Building2 className="w-4 h-4 text-primary mt-0.5 shrink-0" />
      <div className="min-w-0">
        <p className="text-[12.5px] font-medium text-foreground">
          {title ?? 'Managed by the platform'}
          {verdict.plan_code && (
            <span className="ml-2 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">plan {verdict.plan_code}</span>
          )}
        </p>
        <p className="text-[11.5px] text-muted-foreground mt-0.5 leading-relaxed">{verdict.detail}</p>
      </div>
    </div>
  );
}
