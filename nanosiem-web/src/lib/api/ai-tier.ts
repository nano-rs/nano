// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Hosted-shared tenant AI tier (NAN-3191) — `/api/melod/settings/ai-tier`.
 *
 * A shared tenant never picks a model; it picks a cost/quality tier and the
 * server resolves it to the platform model. `standard` = best reasoning
 * (default), `economy` = lower cost (fewer AI credits per call).
 */

export type AiTier = 'standard' | 'economy';

export interface AiTierSettings {
  ai_tier: AiTier;
  /** Share of the standard per-call credit cost an economy call is charged. */
  economy_credit_percent: number;
  updated_by: string | null;
  updated_at: string | null;
}

export class AiTierApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}

  async get(): Promise<AiTierSettings> {
    return this.request('/api/melod/settings/ai-tier');
  }

  async update(aiTier: AiTier): Promise<AiTierSettings> {
    return this.request('/api/melod/settings/ai-tier', {
      method: 'PUT',
      body: JSON.stringify({ ai_tier: aiTier }),
    });
  }
}
