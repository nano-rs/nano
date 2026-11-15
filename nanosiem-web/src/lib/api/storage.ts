// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  IngestionPauseStatus,
  StorageOverview,
  UpdateClickHouseRetentionResponse,
  TierStats,
  TieringConfig,
  TieringConnectionTestResult,
} from './types';

export class StorageApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async getStorageOverview(): Promise<StorageOverview> {
    return this.request('/api/settings/storage/overview');
  }

  /** NAN-5449: set the event retention (the ClickHouse TTL), 1-3650 days. */
  async updateClickHouseRetention(retentionDays: number): Promise<UpdateClickHouseRetentionResponse> {
    return this.request('/api/settings/storage/clickhouse/retention', {
      method: 'PUT',
      body: JSON.stringify({ retention_days: retentionDays }),
    });
  }

  /** NAN-5445: storage tiering status (read-only, deployment-managed). */
  async getTieringStatus(): Promise<TieringConfig> {
    return this.request('/api/settings/tiering');
  }

  async getTierStats(): Promise<TierStats> {
    return this.request('/api/settings/tiering/stats');
  }

  /** Reads one cold part with the ClickHouse filesystem cache bypassed. */
  async testColdTier(): Promise<TieringConnectionTestResult> {
    return this.request('/api/settings/tiering/test', { method: 'POST' });
  }

  /** NAN-5217: pause ingestion cluster-wide (manual). */
  async pauseIngestion(reason?: string): Promise<IngestionPauseStatus> {
    return this.request('/api/settings/ingestion/pause', {
      method: 'POST',
      body: JSON.stringify({ reason: reason || null }),
    });
  }

  /** NAN-5217: resume ingestion (lifts a manual or a disk-pressure pause). */
  async resumeIngestion(): Promise<IngestionPauseStatus> {
    return this.request('/api/settings/ingestion/resume', { method: 'POST' });
  }
}
