// SPDX-License-Identifier: AGPL-3.0-or-later
// Marketplace state for the cloud pull card (NAN-3596, re-backed NAN-4946).
// Main read the hosted pull broker (`/api/pull-sources`); here cloud queues
// are read by Vector through source configurations, the same list Log
// Sources → Cloud pull shows. Shared query key, so the two never disagree.
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import { isPullConfigType } from '@/lib/cloud-pull';

const SEARCH_TEXT = 'cloud pull (aws s3 + sqs, gcp pub/sub, azure event hubs, kafka) cloud_pull aws s3 sqs queue bucket cloudtrail gcp pubsub subscription azure event hub eventhub kafka topic entra activity sign-in';

/** Same key as Log Sources → Cloud pull. */
export const CLOUD_PULL_QUERY_KEY = ['source-configs', 'cloud-pull'] as const;

export function useCloudPullEntry() {
  const { hasAllPermissions } = useAuth();
  const canView = hasAllPermissions(['log_sources:view']);
  const list = useQuery({
    queryKey: CLOUD_PULL_QUERY_KEY,
    queryFn: () => api.listSourceConfigs(),
    enabled: canView,
    staleTime: 30_000,
  });
  const sources = (list.data ?? []).filter(c => isPullConfigType(c.config_type));
  return { available: canView && list.isSuccess, sources };
}

export function cloudPullMatches(query: string): boolean {
  const q = query.toLowerCase().trim();
  return !q || SEARCH_TEXT.includes(q);
}
