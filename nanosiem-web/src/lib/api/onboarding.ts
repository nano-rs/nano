// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Onboarding Wizard API client
 */

export type OnboardingStep =
  | 'ai_setup'
  | 'org_context'
  | 'team_setup'
  | 'sso_setup'
  | 'first_feed'
  | 'create_parser'
  | 'first_searches';

export interface OnboardingProgress {
  user_id: string;
  current_step: OnboardingStep;
  completed_steps: OnboardingStep[];
  skipped_steps: OnboardingStep[];
  step_data: Record<string, unknown>;
  dismissed: boolean;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface OnboardingStatus {
  has_ai_provider: boolean;
  has_org_context: boolean;
  has_users: boolean;
  has_sso: boolean;
  has_log_sources: boolean;
  has_parsers: boolean;
  has_search_history: boolean;
}

export interface UpdateProgressRequest {
  current_step: OnboardingStep;
}

export interface StepActionRequest {
  step: OnboardingStep;
  data?: unknown;
}

export class OnboardingApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
  ) {}

  async getProgress(): Promise<OnboardingProgress | null> {
    return this.request('/api/onboarding/progress');
  }

  async updateProgress(req: UpdateProgressRequest): Promise<OnboardingProgress> {
    return this.request('/api/onboarding/progress', {
      method: 'PUT',
      body: JSON.stringify(req),
    });
  }

  async completeStep(req: StepActionRequest): Promise<OnboardingProgress> {
    return this.request('/api/onboarding/complete-step', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async skipStep(req: StepActionRequest): Promise<OnboardingProgress> {
    return this.request('/api/onboarding/skip-step', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async dismiss(): Promise<OnboardingProgress> {
    return this.request('/api/onboarding/dismiss', {
      method: 'POST',
    });
  }

  async reset(): Promise<OnboardingProgress> {
    return this.request('/api/onboarding/reset', {
      method: 'POST',
    });
  }

  async getStatus(): Promise<OnboardingStatus> {
    return this.request('/api/onboarding/status');
  }
}
