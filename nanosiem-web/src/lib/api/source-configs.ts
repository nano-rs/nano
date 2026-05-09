// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  SourceConfiguration,
  SourceConfigurationWithRules,
  SourceConfigTypeInfo,
  NewSourceConfiguration,
  UpdateSourceConfiguration,
  RoutingRule,
  NewRoutingRule,
  UpdateRoutingRule,
  SourceConfigDeployment,
  SourceConfigDeploymentResult,
  RoutingRuleReachability,
  RoutingRuleReachabilityRequest,
} from './types';

export class SourceConfigsApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  // =========================================================================
  // Source Configurations CRUD
  // =========================================================================

  /**
   * NAN-649: per-driver source-config type metadata (label, description,
   * requires_credentials, is_pull_source, default_match_field,
   * match_field_presets). The UI uses `is_pull_source` to switch between
   * the push-style (HTTP/Vector) and pull-style (Pub/Sub/Kafka/S3/HEC)
   * routing UIs.
   */
  async listSourceConfigTypes(): Promise<SourceConfigTypeInfo[]> {
    return this.request<SourceConfigTypeInfo[]>('/api/source-configurations/types');
  }

  async listSourceConfigs(params?: {
    config_type?: string;
    enabled?: boolean;
    deployed?: boolean;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<SourceConfiguration[]> {
    const searchParams = new URLSearchParams();
    if (params?.config_type) searchParams.append('config_type', params.config_type);
    if (params?.enabled !== undefined) searchParams.append('enabled', String(params.enabled));
    if (params?.deployed !== undefined) searchParams.append('deployed', String(params.deployed));
    if (params?.search) searchParams.append('search', params.search);
    if (params?.limit) searchParams.append('limit', String(params.limit));
    if (params?.offset) searchParams.append('offset', String(params.offset));

    const query = searchParams.toString();
    return this.request<SourceConfiguration[]>(
      `/api/source-configurations${query ? `?${query}` : ''}`
    );
  }

  async getSourceConfig(id: string): Promise<SourceConfiguration> {
    return this.request<SourceConfiguration>(`/api/source-configurations/${id}`);
  }

  async getSourceConfigWithRules(id: string): Promise<SourceConfigurationWithRules> {
    return this.request<SourceConfigurationWithRules>(`/api/source-configurations/${id}/full`);
  }

  async createSourceConfig(request: NewSourceConfiguration): Promise<SourceConfiguration> {
    return this.request<SourceConfiguration>('/api/source-configurations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
  }

  async updateSourceConfig(
    id: string,
    request: UpdateSourceConfiguration
  ): Promise<SourceConfiguration> {
    return this.request<SourceConfiguration>(`/api/source-configurations/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
  }

  async deleteSourceConfig(id: string): Promise<{ deleted: boolean }> {
    return this.request<{ deleted: boolean }>(`/api/source-configurations/${id}`, {
      method: 'DELETE',
    });
  }

  async toggleSourceConfig(
    id: string,
    enabled: boolean
  ): Promise<SourceConfiguration> {
    return this.request<SourceConfiguration>(`/api/source-configurations/${id}/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });
  }

  // =========================================================================
  // Deployment
  // =========================================================================

  async deploySourceConfig(id: string): Promise<SourceConfigDeploymentResult> {
    return this.request<SourceConfigDeploymentResult>(
      `/api/source-configurations/${id}/deploy`,
      { method: 'POST' }
    );
  }

  async undeploySourceConfig(id: string): Promise<SourceConfigDeploymentResult> {
    return this.request<SourceConfigDeploymentResult>(
      `/api/source-configurations/${id}/undeploy`,
      { method: 'POST' }
    );
  }

  async deployAllSourceConfigs(): Promise<SourceConfigDeploymentResult[]> {
    return this.request<SourceConfigDeploymentResult[]>(
      '/api/source-configurations/deploy-all',
      { method: 'POST' }
    );
  }

  async getSourceConfigDeployments(id: string): Promise<SourceConfigDeployment[]> {
    return this.request<SourceConfigDeployment[]>(
      `/api/source-configurations/${id}/deployments`
    );
  }

  // =========================================================================
  // Routing Rules
  // =========================================================================

  async listRoutingRules(sourceConfigId: string): Promise<RoutingRule[]> {
    return this.request<RoutingRule[]>(
      `/api/source-configurations/${sourceConfigId}/rules`
    );
  }

  async createRoutingRule(
    sourceConfigId: string,
    request: NewRoutingRule
  ): Promise<RoutingRule> {
    return this.request<RoutingRule>(
      `/api/source-configurations/${sourceConfigId}/rules`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      }
    );
  }

  async updateRoutingRule(
    sourceConfigId: string,
    ruleId: string,
    request: UpdateRoutingRule
  ): Promise<RoutingRule> {
    return this.request<RoutingRule>(
      `/api/source-configurations/${sourceConfigId}/rules/${ruleId}`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      }
    );
  }

  async deleteRoutingRule(
    sourceConfigId: string,
    ruleId: string
  ): Promise<{ deleted: boolean }> {
    return this.request<{ deleted: boolean }>(
      `/api/source-configurations/${sourceConfigId}/rules/${ruleId}`,
      { method: 'DELETE' }
    );
  }

  async reorderRoutingRules(
    sourceConfigId: string,
    ruleOrder: string[]
  ): Promise<RoutingRule[]> {
    return this.request<RoutingRule[]>(
      `/api/source-configurations/${sourceConfigId}/rules/reorder`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule_order: ruleOrder }),
      }
    );
  }

  /**
   * NAN-522: Check whether a planned routing rule would actually deliver
   * events to its target log source. Reports source-config + target
   * existence and any human-readable warnings (config disabled, target
   * missing, etc.) so the wizard's deploy gate can warn the user.
   */
  async checkRoutingRuleReachability(
    sourceConfigId: string,
    request: RoutingRuleReachabilityRequest
  ): Promise<RoutingRuleReachability> {
    return this.request<RoutingRuleReachability>(
      `/api/source-configurations/${sourceConfigId}/rules/check-reachability`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      }
    );
  }
}
