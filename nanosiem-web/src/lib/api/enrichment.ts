// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  EnrichmentSource,
  IpinfoConfig,
  AutoSyncConfig,
  IpLookupResult,
  IocLookupResult,
  IocStats,
  ThreatFoxConfig,
  TorExitNodesConfig,
  AgentEnrichmentProvider,
  ListAgentEnrichmentProvidersResponse,
  CreateAgentEnrichmentProviderRequest,
  UpdateAgentEnrichmentProviderRequest,
  AsyncSyncResponse,
} from './types';

/** Result of starting an async sync operation */
export interface SyncStartResult {
  /** Whether this was a new sync (202) or already in progress (409) */
  started: boolean;
  /** Response from the server */
  response: AsyncSyncResponse;
}

/** Sleep utility for polling */
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export class EnrichmentApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  /**
   * Start an async sync operation
   * Returns SyncStartResult with started=true for 202, started=false for 409
   */
  private async startAsyncSync(endpoint: string): Promise<SyncStartResult> {
    try {
      // Request will return the JSON body for 202 (success)
      const response = await this.request<AsyncSyncResponse>(endpoint, {
        method: 'POST',
      });
      return { started: true, response };
    } catch (error: unknown) {
      // Check if it's a 409 Conflict (sync already in progress)
      // The error message from the API will contain the response body
      if (error instanceof Error && error.message.includes('already in progress')) {
        // Parse the response from the error if possible
        return {
          started: false,
          response: {
            source_id: '',
            status: 'in_progress',
            message: error.message,
          },
        };
      }
      throw error;
    }
  }

  /**
   * Wait for an enrichment source sync to complete
   * @param sourceId The source ID to wait for
   * @param maxWaitMs Maximum time to wait (default: 30 minutes)
   * @param pollIntervalMs Time between polls (default: 5 seconds)
   * @returns The final EnrichmentSource state, or null if timeout
   */
  async waitForSync(
    sourceId: string,
    maxWaitMs: number = 1800000,
    pollIntervalMs: number = 5000,
  ): Promise<EnrichmentSource | null> {
    const startTime = Date.now();

    while (Date.now() - startTime < maxWaitMs) {
      const sources = await this.listEnrichmentSources();
      const source = sources.find(s => s.id === sourceId);

      if (!source) {
        throw new Error(`Source not found: ${sourceId}`);
      }

      // Check if sync is complete (not in_progress)
      if (source.last_sync_status !== 'in_progress') {
        return source;
      }

      // Wait before next poll
      await sleep(pollIntervalMs);
    }

    // Timeout - return null
    return null;
  }

  // Basic Enrichment Sources

  async listEnrichmentSources(): Promise<EnrichmentSource[]> {
    const response = await this.request<{ sources: EnrichmentSource[] }>('/api/enrichment/sources');
    return response.sources;
  }

  async configureIpinfo(config: IpinfoConfig): Promise<{ success: boolean; message: string }> {
    return this.request('/api/enrichment/ipinfo/configure', {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  /**
   * Start an async IPinfo sync
   * Returns immediately with 202 Accepted or 409 Conflict
   */
  async syncIpinfo(): Promise<SyncStartResult> {
    return this.startAsyncSync('/api/enrichment/ipinfo/sync');
  }

  /**
   * Start IPinfo sync and wait for completion (convenience method)
   * @param maxWaitMs Maximum time to wait (default: 30 minutes)
   * @returns The final EnrichmentSource state
   */
  async syncIpinfoAndWait(maxWaitMs: number = 1800000): Promise<EnrichmentSource | null> {
    await this.startAsyncSync('/api/enrichment/ipinfo/sync');
    return this.waitForSync('ipinfo_lite', maxWaitMs);
  }

  async enableEnrichmentSource(sourceId: string): Promise<{ success: boolean; message: string }> {
    return this.request(`/api/enrichment/sources/${sourceId}/enable`, {
      method: 'POST',
    });
  }

  async disableEnrichmentSource(sourceId: string): Promise<{ success: boolean; message: string }> {
    return this.request(`/api/enrichment/sources/${sourceId}/disable`, {
      method: 'POST',
    });
  }

  async getEnrichmentStats(): Promise<Record<string, { total: number; last_updated?: string }>> {
    return this.request('/api/enrichment/stats');
  }

  async lookupIp(ip: string): Promise<IpLookupResult> {
    return this.request(`/api/enrichment/lookup/ip/${encodeURIComponent(ip)}`);
  }

  async getAutoSyncConfig(sourceId: string = 'ipinfo_lite'): Promise<AutoSyncConfig> {
    return this.request(`/api/enrichment/sources/${encodeURIComponent(sourceId)}/auto-sync`);
  }

  async configureAutoSync(config: { enabled: boolean; interval_hours?: number }, sourceId: string = 'ipinfo_lite'): Promise<AutoSyncConfig> {
    return this.request(`/api/enrichment/sources/${encodeURIComponent(sourceId)}/auto-sync`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  // ThreatFox IOC Enrichment

  async configureThreatFox(config: ThreatFoxConfig): Promise<{ success: boolean; message: string }> {
    return this.request('/api/enrichment/threatfox/configure', {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  /**
   * Start an async ThreatFox sync
   * Returns immediately with 202 Accepted or 409 Conflict
   */
  async syncThreatFox(): Promise<SyncStartResult> {
    return this.startAsyncSync('/api/enrichment/threatfox/sync');
  }

  /**
   * Start ThreatFox sync and wait for completion (convenience method)
   * @param maxWaitMs Maximum time to wait (default: 30 minutes)
   * @returns The final EnrichmentSource state
   */
  async syncThreatFoxAndWait(maxWaitMs: number = 1800000): Promise<EnrichmentSource | null> {
    await this.startAsyncSync('/api/enrichment/threatfox/sync');
    return this.waitForSync('threatfox', maxWaitMs);
  }

  // TOR Exit Nodes Enrichment

  async configureTorExitNodes(config: TorExitNodesConfig): Promise<{ success: boolean; message: string }> {
    return this.request('/api/enrichment/tor/configure', {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  /**
   * Start an async TOR Exit Nodes sync
   * Returns immediately with 202 Accepted or 409 Conflict
   */
  async syncTorExitNodes(): Promise<SyncStartResult> {
    return this.startAsyncSync('/api/enrichment/tor/sync');
  }

  /**
   * Start TOR Exit Nodes sync and wait for completion (convenience method)
   * @param maxWaitMs Maximum time to wait (default: 30 minutes)
   * @returns The final EnrichmentSource state
   */
  async syncTorExitNodesAndWait(maxWaitMs: number = 1800000): Promise<EnrichmentSource | null> {
    await this.startAsyncSync('/api/enrichment/tor/sync');
    return this.waitForSync('tor_exit_nodes', maxWaitMs);
  }

  async lookupIoc(value: string): Promise<IocLookupResult> {
    return this.request(`/api/enrichment/ioc/lookup/${encodeURIComponent(value)}`);
  }

  async getIocStats(sourceId: string): Promise<IocStats> {
    return this.request(`/api/enrichment/ioc/stats/${encodeURIComponent(sourceId)}`);
  }

  // Agent Enrichment Providers (AI-powered)

  async listAgentEnrichmentProviders(): Promise<ListAgentEnrichmentProvidersResponse> {
    return this.request('/api/settings/agent-enrichments');
  }

  async getAgentEnrichmentProvider(providerId: string): Promise<AgentEnrichmentProvider> {
    return this.request(`/api/settings/agent-enrichments/${providerId}`);
  }

  async createAgentEnrichmentProvider(request: CreateAgentEnrichmentProviderRequest): Promise<AgentEnrichmentProvider> {
    return this.request('/api/settings/agent-enrichments', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async updateAgentEnrichmentProvider(providerId: string, request: UpdateAgentEnrichmentProviderRequest): Promise<AgentEnrichmentProvider> {
    return this.request(`/api/settings/agent-enrichments/${providerId}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async deleteAgentEnrichmentProvider(providerId: string): Promise<{ success: boolean; message: string; cache_entries_cleared: number }> {
    return this.request(`/api/settings/agent-enrichments/${providerId}`, {
      method: 'DELETE',
    });
  }

  async updateAgentEnrichmentCredentials(providerId: string, credentials: Record<string, string>): Promise<{ success: boolean; message: string }> {
    return this.request(`/api/settings/agent-enrichments/${providerId}/credentials`, {
      method: 'PUT',
      body: JSON.stringify({ credentials }),
    });
  }

  async testAgentEnrichmentConnection(providerId: string): Promise<{ success: boolean; message: string; response_time_ms?: number; error?: string }> {
    return this.request(`/api/settings/agent-enrichments/${providerId}/test`, {
      method: 'POST',
    });
  }

  async getAgentEnrichmentUsage(): Promise<Record<string, { requests_today: number; requests_this_month: number }>> {
    return this.request('/api/settings/agent-enrichments/usage');
  }
}
