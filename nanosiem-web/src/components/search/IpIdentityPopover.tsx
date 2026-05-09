// SPDX-License-Identifier: AGPL-3.0-or-later

import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Monitor, Loader2 } from 'lucide-react';
import { api } from '@/lib/api';
import type { IdentityResolveResponse } from '@/lib/api/types';

const CONFIDENCE_COLORS: Record<string, string> = {
  high: 'bg-green-500/15 text-green-400 border-green-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  stale: 'bg-muted text-muted-foreground border-border',
  none: 'bg-muted text-muted-foreground border-border',
};

interface IpIdentityPopoverProps {
  ip: string;
}

export function IpIdentityPopover({ ip }: IpIdentityPopoverProps) {
  const [open, setOpen] = React.useState(false);

  const { data, isLoading, isError } = useQuery<IdentityResolveResponse>({
    queryKey: ['identity-resolve', ip],
    queryFn: () => api.resolveIpIdentity(ip),
    enabled: open,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  const match = data?.match;

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          onClick={(e) => e.stopPropagation()}
          className="inline-flex items-center justify-center w-4 h-4 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors opacity-0 group-hover:opacity-100 shrink-0"
          title="Resolve IP identity"
        >
          <Monitor className="w-3 h-3" />
        </button>
      </PopoverTrigger>
      <PopoverContent
        className="w-64 p-0 overflow-hidden"
        side="top"
        align="start"
        onClick={(e) => e.stopPropagation()}
      >
        {isLoading && (
          <div className="flex items-center gap-2 p-3 text-muted-foreground text-xs">
            <Loader2 className="w-3 h-3 animate-spin" />
            <span>Resolving identity...</span>
          </div>
        )}

        {isError && (
          <p className="p-3 text-xs text-destructive">Failed to resolve identity</p>
        )}

        {data && !match && (
          <div className="p-3 text-center">
            <p className="search-console-section-header justify-center"><Monitor />Identity Resolve</p>
            <p className="mt-3 text-xs text-foreground">No identity mapping returned</p>
          </div>
        )}

        {match && (
          <div>
            <div className="border-b border-border px-3 py-2">
              <div className="search-console-section-header"><Monitor />Identity Resolve</div>
              <div className="search-console-section-meta mt-1 font-mono">{ip}</div>
            </div>
            <div className="space-y-2 p-3">
            {/* Hostname */}
            {match.hostname && (
              <div>
                <p className="search-console-section-meta mb-1">Hostname</p>
                <p className="text-sm font-mono text-foreground truncate">{match.hostname}</p>
              </div>
            )}

            {/* User */}
            {match.user && (
              <div>
                <p className="search-console-section-meta mb-1">User</p>
                <p className="text-sm font-mono text-foreground truncate">{match.user}</p>
                {(match.department || match.title) && (
                  <p className="text-xs text-muted-foreground truncate">
                    {[match.title, match.department].filter(Boolean).join(' - ')}
                  </p>
                )}
              </div>
            )}

            {/* Confidence + Source row */}
            <div className="flex items-center gap-2 pt-1">
              <span
                className={`inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] font-medium ${CONFIDENCE_COLORS[match.confidence] ?? CONFIDENCE_COLORS.none}`}
              >
                {match.confidence}
              </span>
              {match.source && (
                <span className="text-[10px] text-muted-foreground truncate">{match.source}</span>
              )}
            </div>

            {/* Last seen */}
            {match.last_seen && (
              <p className="text-[10px] font-mono text-muted-foreground">
                Last seen {new Date(match.last_seen).toLocaleString()}
              </p>
            )}
          </div>
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
}
