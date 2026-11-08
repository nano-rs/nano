// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-4948 — data wiring for {@link PlatformFeedsCard}: status query (polled
 * while a check runs), "Check now" and the air-gap file import. Gated on
 * `enrichments:view`; the actions on `enrichments:configure`.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import { importPlatformFeedBundle } from '@/lib/api/enrichment';
import { PlatformFeedsCard } from './PlatformFeedsCard';

const PLATFORM_FEEDS_QUERY_KEY = ['enrichment', 'platform-feeds'] as const;

export function PlatformFeedsPanel({ className }: { className?: string }) {
  const { hasAllPermissions } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const canView = hasAllPermissions(['enrichments:view']);
  const canConfigure = hasAllPermissions(['enrichments:configure']);
  const query = useQuery({
    queryKey: PLATFORM_FEEDS_QUERY_KEY,
    queryFn: () => api.getPlatformFeeds(),
    enabled: canView,
    staleTime: 60_000,
    retry: false,
    refetchOnWindowFocus: false,
    refetchInterval: q => (q.state.data?.last_check_status === 'checking' ? 3_000 : false),
  });
  const refresh = () => queryClient.invalidateQueries({ queryKey: PLATFORM_FEEDS_QUERY_KEY });
  const check = useMutation({
    mutationFn: () => api.checkPlatformFeeds(),
    onSuccess: refresh,
    onError: (e: Error) => toast({ title: 'Feed check failed', description: e.message, variant: 'destructive' }),
  });
  const importFile = useMutation({
    mutationFn: (file: File) => importPlatformFeedBundle(file),
    onSuccess: response => {
      queryClient.setQueryData(PLATFORM_FEEDS_QUERY_KEY, response.status);
      toast({
        title: response.result.outcome === 'installed' ? 'Feed bundle installed' : 'Feed bundle already current',
        description: `Sequence ${response.result.sequence}`,
      });
    },
    onError: (e: Error) => {
      refresh();
      toast({ title: 'Feed bundle refused', description: e.message, variant: 'destructive' });
    },
  });
  if (!canView || !query.data?.available) return null;
  return (
    <div className={className}>
      <PlatformFeedsCard
        status={query.data}
        onCheck={canConfigure ? () => check.mutate() : undefined}
        onImport={canConfigure ? file => importFile.mutate(file) : undefined}
        busy={check.isPending || importFile.isPending}
      />
    </div>
  );
}
