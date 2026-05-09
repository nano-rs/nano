// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Demo session API
 * Handles demo session creation and status checking
 */

export interface DemoSessionResponse {
  session_id: string;
  user_id: string;
  token: string;
  expires_at: string;
  remaining_hours: number;
  auth: {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    user: {
      id: string;
      name: string;
      roles: string[];
      permissions: string[];
    };
  };
}

export interface DemoSessionStatus {
  session_id: string;
  expires_at: string;
  remaining_hours: number;
  resource_counts: {
    rules: number;
    cases: number;
    dashboards: number;
    notebooks: number;
    saved_searches: number;
  };
}

export class DemoApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async createSession(displayName?: string): Promise<DemoSessionResponse> {
    return this.request('/api/demo/session', {
      method: 'POST',
      body: JSON.stringify({ display_name: displayName }),
    });
  }

  async claimToken(token: string): Promise<DemoSessionResponse> {
    return this.request(`/api/demo/session/${encodeURIComponent(token)}/claim`, {
      method: 'POST',
    });
  }

  async getSessionStatus(): Promise<DemoSessionStatus> {
    return this.request('/api/demo/session/status');
  }
}
