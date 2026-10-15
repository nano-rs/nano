// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Tenant-wide AI tuning mode (NAN-3219) — `/api/melod/settings/ai-tuning`
 * (dedicated and hosted-shared, same wire shape).
 *
 * - `on`: automatic proposals + the Tune wizard (default).
 * - `manual`: no automatic proposals or notifications; Tune / `@tune` work.
 * - `off`: no AI tuning; Tune / `@tune` are refused.
 *
 * ANDed with each rule's own `auto_tuning_enabled`.
 */

export type AiTuningMode = 'on' | 'manual' | 'off';

export interface AiTuningSettings {
  ai_tuning_mode: AiTuningMode;
  updated_by?: string | null;
  updated_at?: string | null;
}

export class AiTuningApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}

  async get(): Promise<AiTuningSettings> {
    return this.request('/api/melod/settings/ai-tuning');
  }

  async update(mode: AiTuningMode): Promise<AiTuningSettings> {
    return this.request('/api/melod/settings/ai-tuning', {
      method: 'PUT',
      body: JSON.stringify({ ai_tuning_mode: mode }),
    });
  }
}
