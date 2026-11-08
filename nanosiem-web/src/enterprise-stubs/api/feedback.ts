// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for FeedbackApi. In-product feedback is enterprise-only.

import type {
  Feedback,
  CreateFeedbackRequest,
  UpdateFeedbackRequest,
  FeedbackListResponse,
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
  updateFeedback(_id: string, _request: UpdateFeedbackRequest): Promise<Feedback> {
    return ENTERPRISE_ONLY();
  }
  deleteFeedback(_id: string): Promise<{ success: boolean }> {
    return ENTERPRISE_ONLY();
  }
  listFeedback(_options?: {
    category?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }): Promise<FeedbackListResponse> {
    return ENTERPRISE_ONLY();
  }
}
