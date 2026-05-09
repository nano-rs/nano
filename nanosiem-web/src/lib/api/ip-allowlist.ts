// SPDX-License-Identifier: AGPL-3.0-or-later

export interface IpAllowlistEntry {
  id: string;
  scope: 'global' | 'api' | 'search' | 'frontend';
  cidr: string;
  description?: string;
  enabled: boolean;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateIpAllowlistEntry {
  scope: 'global' | 'api' | 'search' | 'frontend';
  cidr: string;
  description?: string;
  enabled?: boolean;
}

export interface UpdateIpAllowlistEntry {
  scope?: 'global' | 'api' | 'search' | 'frontend';
  cidr?: string;
  description?: string;
  enabled?: boolean;
}

export interface TestIpRequest {
  ip: string;
  scope?: 'global' | 'api' | 'search' | 'frontend';
}

export interface TestIpResponse {
  ip: string;
  allowed: boolean;
  matched_rules: MatchedRule[];
  allowlist_active: boolean;
}

export interface MatchedRule {
  id: string;
  scope: 'global' | 'api' | 'search' | 'frontend';
  cidr: string;
  description?: string;
}

export interface IpAllowlistStatus {
  active: boolean;
  total_rules: number;
  enabled_rules: number;
  rules_by_scope: Record<string, number>;
}

export class IpAllowlistApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async list(scope?: string): Promise<IpAllowlistEntry[]> {
    const params = scope ? `?scope=${scope}` : '';
    return this.request(`/api/settings/ip-allowlist${params}`);
  }

  async getStatus(): Promise<IpAllowlistStatus> {
    return this.request('/api/settings/ip-allowlist/status');
  }

  async create(entry: CreateIpAllowlistEntry): Promise<IpAllowlistEntry> {
    return this.request('/api/settings/ip-allowlist', {
      method: 'POST',
      body: JSON.stringify(entry),
    });
  }

  async update(id: string, entry: UpdateIpAllowlistEntry): Promise<IpAllowlistEntry> {
    return this.request(`/api/settings/ip-allowlist/${id}`, {
      method: 'PUT',
      body: JSON.stringify(entry),
    });
  }

  async delete(id: string): Promise<void> {
    return this.request(`/api/settings/ip-allowlist/${id}`, {
      method: 'DELETE',
    });
  }

  async testIp(request: TestIpRequest): Promise<TestIpResponse> {
    return this.request('/api/settings/ip-allowlist/test', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }
}
