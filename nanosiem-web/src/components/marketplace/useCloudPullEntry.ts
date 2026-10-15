// SPDX-License-Identifier: AGPL-3.0-or-later
// Marketplace state for the cloud pull card (NAN-3596): shown only to tenants
// the API admits (`GET /api/pull-sources` succeeds). No polling here.
import { useAuth } from '@/contexts/AuthContext';
import { usePullSources } from '@/hooks/use-pull-sources';

const SEARCH_TEXT = 'cloud pull (aws s3 + sqs, gcp pub/sub, azure event hubs) cloud_pull aws s3 sqs queue bucket cloudtrail gcp pubsub subscription azure event hub eventhub entra activity sign-in';

export function useCloudPullEntry() {
  const { hasAllPermissions } = useAuth();
  const canView = hasAllPermissions(['log_sources:view']);
  const list = usePullSources({ enabled: canView });
  return { available: canView && list.isSuccess, sources: list.data ?? [] };
}

export function cloudPullMatches(query: string): boolean {
  const q = query.toLowerCase().trim();
  return !q || SEARCH_TEXT.includes(q);
}
