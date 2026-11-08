// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Marketplace entry for cloud pull (NAN-3596, re-backed NAN-4946). Sources are
 * managed on Log Sources → Cloud pull; this card only links there. Visibility
 * comes from `useCloudPullEntry`.
 */

import { useNavigate } from 'react-router-dom';
import type { SourceConfiguration } from '@/lib/api/types';
import { CLOUD_PULL_PATH, pullState } from '@/lib/cloud-pull';
import { CatalogCard, MetaBadge } from './InventoryCard';

const CLOUD_PULL_NAME = 'Cloud pull (AWS S3 + SQS, GCP Pub/Sub, Azure Event Hubs, Kafka)';

function health(sources: Pick<SourceConfiguration, 'enabled' | 'deployed'>[]): string {
  if (sources.length === 0) return 'not set up';
  const states = sources.map(pullState);
  if (states.includes('pending')) return 'pending';
  return states.includes('active') ? 'healthy' : 'paused';
}

export function CloudPullCard({ sources }: { sources: Pick<SourceConfiguration, 'enabled' | 'deployed'>[] }) {
  const navigate = useNavigate();
  return (
    <CatalogCard
      id="cloud-pull"
      name={CLOUD_PULL_NAME}
      meta={<><MetaBadge>pull</MetaBadge> · {health(sources)}</>}
      body="Read events from your S3 bucket notifications, SQS queue, Pub/Sub subscription, Azure event hub or Kafka topic. Vector pulls with a role, service account or credential you grant."
      footerLabel="sqs · pub/sub · event hubs · kafka → vector"
      footerAction={<span className="text-primary">{sources.length > 0 ? `${sources.length} source${sources.length === 1 ? '' : 's'} · Manage` : 'Set up'}</span>}
      onOpen={() => navigate(CLOUD_PULL_PATH)}
    />
  );
}
