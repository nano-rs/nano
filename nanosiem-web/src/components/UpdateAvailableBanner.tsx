// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5114: "Update available" for admins of a Self-run deployment.
 *
 * Driven by the last online license check-in (`GET /api/license/update`),
 * which carries only public release facts. Enterprise-only: the open edition
 * has no license check-in, so it never polls and never renders. Air-gapped
 * installs make no check-in, so the endpoint reports nothing and the banner
 * stays hidden. Dismissal is per version: a newer release shows again.
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ArrowUpCircle, ShieldAlert, X } from 'lucide-react';
import { api } from '../lib/api';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useAuth } from '@/contexts/AuthContext';
import { readDismissedUpdate, shouldShowUpdateBanner, writeDismissedUpdate } from '@/lib/update-banner';

export function UpdateAvailableBanner() {
  const { edition } = useCapabilities();
  const { hasPermission } = useAuth();
  const enabled = edition === 'enterprise' && hasPermission('settings:system');
  const [dismissed, setDismissed] = useState<string | null>(() => readDismissedUpdate());

  const { data: status } = useQuery({
    queryKey: ['license', 'update-status'],
    queryFn: () => api.getUpdateStatus(),
    enabled,
    staleTime: 30 * 60_000,
    refetchInterval: 60 * 60_000,
    retry: false,
  });

  if (!enabled || !shouldShowUpdateBanner(status, dismissed) || !status) return null;
  const version = status.latest_version!;
  const security = status.security_release;
  const Icon = security ? ShieldAlert : ArrowUpCircle;

  return (
    <div
      role="status"
      className={`mx-6 mt-3 flex items-center justify-between gap-3 rounded-md border px-3 py-2 text-[12px] ${security
        ? 'border-amber-200 bg-amber-50/80 dark:border-amber-500/30 dark:bg-amber-500/10'
        : 'border-border bg-muted/40'}`}
    >
      <div className="flex min-w-0 items-center gap-2.5">
        <Icon className={`h-4 w-4 shrink-0 ${security ? 'text-amber-600 dark:text-amber-400' : 'text-primary'}`} strokeWidth={1.5} />
        <span className="font-medium">
          Update available: <span className="font-mono">v{version}</span>
        </span>
        <span className="truncate text-muted-foreground">
          {security
            ? 'Includes security fixes, upgrade recommended.'
            : <>You run <span className="font-mono">v{status.current_version}</span>.</>}
        </span>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <a href={status.release_notes_url!} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          Release notes
        </a>
        <a href={status.upgrade_url!} target="_blank" rel="noopener noreferrer" className="font-medium text-primary hover:underline">
          How to upgrade
        </a>
        <button
          onClick={() => { writeDismissedUpdate(version); setDismissed(version); }}
          className="rounded p-1 text-muted-foreground hover:bg-muted"
          aria-label={`Dismiss update v${version}`}
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}
