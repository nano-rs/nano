// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  StorageOverview,
} from './types';

export class StorageApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async getStorageOverview(): Promise<StorageOverview> {
    return this.request('/api/settings/storage/overview');
  }
}
