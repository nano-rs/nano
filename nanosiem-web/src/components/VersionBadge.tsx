// SPDX-License-Identifier: AGPL-3.0-or-later

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

/**
 * Displays the current NanoSIEM version in a compact format.
 * Fetches from /health/detailed (authenticated). Designed to sit
 * in the user dropdown at the bottom of the sidebar.
 */
export function VersionBadge() {
  const { data } = useQuery({
    queryKey: ['version'],
    queryFn: () => api.getVersion(),
    staleTime: 5 * 60 * 1000, // cache for 5 minutes
    retry: false,
  });

  if (!data?.version) return null;

  return (
    <div className="px-2 py-1 text-[10.5px] font-mono text-muted-foreground/80 flex items-center justify-between">
      <span>nano v{data.version}</span>
    </div>
  );
}
