// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  TierStatus,
  TierLimits,
  SetTierRequest,
  UpdateTierLimitsRequest,
  DailyUsage,
  AiUsageDetail,
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

  /**
   * Get detailed AI usage (NAN-1519): billed credits plus per-agent, daily, and
   * recent-call breakdowns from the AI usage ledger. Dates are YYYY-MM-DD (UTC);
   * defaults to the current month.
   */
  async getAiUsage(opts?: {
    from?: string;
    to?: string;
    limit?: number;
  }): Promise<AiUsageDetail> {
    const params = new URLSearchParams();
    if (opts?.from) params.set('from', opts.from);
    if (opts?.to) params.set('to', opts.to);
    if (opts?.limit != null) params.set('limit', String(opts.limit));
    const qs = params.toString();
    return this.request(`/api/settings/ai-usage${qs ? `?${qs}` : ''}`);
  }
}
