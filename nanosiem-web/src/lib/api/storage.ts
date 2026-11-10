// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  IngestionPauseStatus,
  StorageOverview,
} from './types';

export class StorageApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async getStorageOverview(): Promise<StorageOverview> {
    return this.request('/api/settings/storage/overview');
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
