// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  TierStatus,
  TierLimits,
  SetTierRequest,
  UpdateTierLimitsRequest,
  DailyUsage,
} from './types';

export class TierApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  /** Get current tier status (limits + usage + warnings) */
  async getStatus(): Promise<TierStatus> {
    return this.request('/api/settings/tier');
  }

  /** Set the organization tier */
  async setTier(tier: string): Promise<TierLimits> {
    return this.request('/api/settings/tier', {
      method: 'PUT',
      body: JSON.stringify({ tier } satisfies SetTierRequest),
    });
  }

  /** Update specific tier limit overrides (Enterprise) */
  async updateLimits(limits: UpdateTierLimitsRequest): Promise<TierLimits> {
    return this.request('/api/settings/tier/limits', {
      method: 'PUT',
      body: JSON.stringify(limits),
    });
  }

  /** Get daily usage history */
  async getUsageHistory(from?: string, to?: string): Promise<DailyUsage[]> {
    const params = new URLSearchParams();
    if (from) params.set('from', from);
    if (to) params.set('to', to);
    const qs = params.toString();
    return this.request(`/api/settings/tier/usage${qs ? `?${qs}` : ''}`);
  }
}
