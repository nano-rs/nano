// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Detection-as-Code Push Targets API (NAN-1745)
 *
 * A push-only destination for AI-tuned rules: when nano's AI tuning produces a
 * change, it opens a Pull Request in the customer's OWN detection-as-code
 * GitHub repo for review instead of mutating the rule in nano's DB. Git is the
 * source of truth — after the customer merges, their own pipeline redeploys the
 * rule to nano.
 *
 * This is NOT a rule source. Pull-only rule repositories live in
 * `rule-repositories.ts`; keep the two surfaces distinct.
 *
 * NOTE: `id` is a plain UUID string (NOT a typeid), so it is used verbatim in
 * URLs.
 */

// =============================================================================
// Types
// =============================================================================

export interface DetectionCodeTarget {
  id: string;
  name: string;
  repo_url: string;
  base_branch: string;
  path_template: string;
  pr_branch_prefix: string;
  rule_format: string;
  enabled: boolean;
  /** Whether a write-only PAT is configured. The token itself is never returned. */
  has_token: boolean;
  last_pr_url: string | null;
  last_pr_at: string | null;
  last_used_at: string | null;
  created_at: string;
  updated_at: string;
  created_by: string | null;
}

export interface CreateDetectionCodeTargetRequest {
  name: string;
  repo_url: string;
  base_branch?: string;
  path_template?: string;
  pr_branch_prefix?: string;
  rule_format?: string;
  enabled?: boolean;
  /** Write-only PAT stored server-side; never returned on reads. */
  token?: string;
}

export interface UpdateDetectionCodeTargetRequest {
  name?: string;
  repo_url?: string;
  base_branch?: string;
  path_template?: string;
  pr_branch_prefix?: string;
  enabled?: boolean;
}

/** Result of probing the target repo with its configured PAT. */
export interface TestConnectionResult {
  success: boolean;
  can_read: boolean;
  can_write: boolean;
  default_branch: string | null;
  message: string;
}

// =============================================================================
// API Client
// =============================================================================

export class DetectionCodeTargetsApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async listTargets(): Promise<{ targets: DetectionCodeTarget[] }> {
    return this.request('/api/detection-code-targets');
  }

  async getTarget(id: string): Promise<DetectionCodeTarget> {
    return this.request(`/api/detection-code-targets/${id}`);
  }

  async createTarget(req: CreateDetectionCodeTargetRequest): Promise<DetectionCodeTarget> {
    return this.request('/api/detection-code-targets', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async updateTarget(
    id: string,
    req: UpdateDetectionCodeTargetRequest,
  ): Promise<DetectionCodeTarget> {
    return this.request(`/api/detection-code-targets/${id}`, {
      method: 'PUT',
      body: JSON.stringify(req),
    });
  }

  async deleteTarget(id: string): Promise<void> {
    return this.request(`/api/detection-code-targets/${id}`, {
      method: 'DELETE',
    });
  }

  /** Set (or replace) the write-only PAT. The token is never returned. */
  async setToken(id: string, token: string): Promise<DetectionCodeTarget> {
    return this.request(`/api/detection-code-targets/${id}/token`, {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  /** Probe read/write access to the repo with the stored PAT. Requires a saved token. */
  async testConnection(id: string): Promise<TestConnectionResult> {
    return this.request(`/api/detection-code-targets/${id}/test`, {
      method: 'POST',
    });
  }
}
