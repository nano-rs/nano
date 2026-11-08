// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Log Sources → Cloud pull on the ClickHouse product (NAN-4922). Main's page
 * ran the hosted keyless pull broker (`/api/pull-sources`); here cloud queues
 * are read by Vector through source configurations, so the tab lists those.
 */

import type { SourceConfigType } from '@/lib/api/types';

export const CLOUD_PULL_PATH = '/ingestion/log-sources/cloud-pull';

/** Source configuration types that pull from a cloud queue or broker. */
export const PULL_CONFIG_TYPES: readonly SourceConfigType[] = ['aws_s3', 'aws_sqs', 'gcp_pubsub', 'azure_event_hubs', 'kafka'] as SourceConfigType[];

export const PROVIDER_LABEL: Record<string, string> = {
  aws_s3: 'AWS S3 + SQS',
  aws_sqs: 'AWS SQS',
  gcp_pubsub: 'GCP Pub/Sub',
  azure_event_hubs: 'Azure Event Hubs',
  kafka: 'Kafka',
};

export function isPullConfigType(type: string): boolean {
  return (PULL_CONFIG_TYPES as readonly string[]).includes(type);
}

export type PullState = 'active' | 'pending' | 'paused';

/** Running = enabled and deployed; pending = enabled, not deployed yet; paused = disabled. */
export function pullState(config: { enabled: boolean; deployed: boolean }): PullState {
  if (!config.enabled) return 'paused';
  return config.deployed ? 'active' : 'pending';
}
