// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5170: daily ingest vs contracted capacity, for admins.
 *
 * Driven by the `daily_volume` warning from `GET /api/settings/tier`, which
 * starts at 80% and reports the true (uncapped) percentage, e.g. 3,846%.
 * Informational only: ingest is never blocked or slowed over capacity.
 */

import { useQuery } from '@tanstack/react-query';
import { Gauge } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '@/contexts/AuthContext';

function formatPercent(value: number): string {
  return `${value.toLocaleString('en-US')}%`;
}

export function CapacityWarningBanner() {
  const { hasPermission } = useAuth();
  const enabled = hasPermission('settings:system');
  const { data } = useQuery({
    queryKey: ['tier', 'status', 'capacity-warning'],
    queryFn: () => api.tier.getStatus(),
    enabled,
    staleTime: 10 * 60_000,
    refetchInterval: 15 * 60_000,
    retry: false,
  });
  const warning = data?.warnings?.find((w) => w.resource === 'daily_volume');
  if (!enabled || !warning) return null;
  const over = warning.percent_used >= 100;

  return (
    <div
      role="status"
      className={`mx-6 mt-3 flex items-center justify-between gap-3 rounded-md border px-3 py-2 text-[12px] ${over
        ? 'border-amber-200 bg-amber-50/80 dark:border-amber-500/30 dark:bg-amber-500/10'
        : 'border-border bg-muted/40'}`}
    >
      <div className="flex min-w-0 items-center gap-2.5">
        <Gauge className={`h-4 w-4 shrink-0 ${over ? 'text-amber-600 dark:text-amber-400' : 'text-primary'}`} strokeWidth={1.5} />
        <span className="font-medium">
          <span className="font-mono">{formatPercent(warning.percent_used)}</span> of contracted capacity
        </span>
        <span className="truncate text-muted-foreground">{warning.message}</span>
      </div>
    </div>
  );
}
