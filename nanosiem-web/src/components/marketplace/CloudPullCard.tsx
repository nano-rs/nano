// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Marketplace entry for cloud pull (NAN-3596). Sources are managed on
 * Log Sources → Cloud pull; this card only links there. Visibility comes from
 * `useCloudPullEntry`.
 */

import { useNavigate } from 'react-router-dom';
import type { PullSource } from '@/lib/api/pull-sources';
import { CLOUD_PULL_PATH } from '@/lib/cloud-pull';
import { CatalogCard, MetaBadge } from './InventoryCard';

const CLOUD_PULL_NAME = 'Cloud pull (AWS S3 + SQS, GCP Pub/Sub, Azure Event Hubs)';

function health(sources: PullSource[]): string {
  if (sources.length === 0) return 'not set up';
  if (sources.some((s) => s.state === 'failed')) return 'error';
  if (sources.some((s) => s.state === 'pending_verification' || s.state === 'pending_bundle')) return 'pending';
  return sources.some((s) => s.state === 'active') ? 'healthy' : 'paused';
}

export function CloudPullCard({ sources }: { sources: PullSource[] }) {
  const navigate = useNavigate();
  return (
    <CatalogCard
      id="cloud-pull:aws"
      name={CLOUD_PULL_NAME}
      meta={<><MetaBadge>pull</MetaBadge> · {health(sources)}</>}
      body="Read events from your SQS queue, Pub/Sub subscription or Azure event hub. nano signs in with a role, service account or federated credential you grant; no keys leave your account."
      footerLabel="sqs · pub/sub · event hubs → pull container"
      footerAction={sources.length > 0 ? `${sources.length} source${sources.length === 1 ? '' : 's'} · Manage` : 'Set up'}
      onOpen={() => navigate(CLOUD_PULL_PATH)}
    />
  );
}
