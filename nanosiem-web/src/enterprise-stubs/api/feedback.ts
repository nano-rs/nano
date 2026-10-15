// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for FeedbackApi. In-product feedback is enterprise-only.

import type {
  Feedback,
  CreateFeedbackRequest,
} from '@/lib/api/types';

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('FeedbackApi is enterprise-only'));

export class FeedbackApi {
  constructor(
    _request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
  ) {
    void _request;
  }

  createFeedback(_request: CreateFeedbackRequest): Promise<Feedback> {
    return ENTERPRISE_ONLY();
  }
}
