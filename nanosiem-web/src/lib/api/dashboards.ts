// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  Dashboard,
  DashboardSummary,
  CreateDashboardRequest,
  UpdateDashboardRequest,
  ShareDashboardRequest,
  DashboardShareResult,
  PanelQueryRequest,
  PanelQueryResponse,
  DashboardExport,
  ImportDashboardRequest,
  ValidateCronRequest,
  ValidateCronResponse,
} from './types';

export class DashboardsApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async listDashboards(filter: 'my' | 'all' = 'my'): Promise<DashboardSummary[]> {
    return this.request(`/api/dashboards?filter=${filter}`);
  }

  async getDashboard(id: string): Promise<Dashboard> {
    return this.request(`/api/dashboards/${id}`);
  }

  async createDashboard(request: CreateDashboardRequest): Promise<Dashboard> {
    return this.request('/api/dashboards', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async updateDashboard(id: string, request: UpdateDashboardRequest): Promise<Dashboard> {
    return this.request(`/api/dashboards/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async deleteDashboard(id: string): Promise<{ success: boolean }> {
    return this.request(`/api/dashboards/${id}`, {
      method: 'DELETE',
    });
  }

  async shareDashboard(id: string, request: ShareDashboardRequest): Promise<DashboardShareResult> {
    return this.request(`/api/dashboards/${id}/share`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async panelQuery(request: PanelQueryRequest): Promise<PanelQueryResponse> {
    return this.request('/api/dashboards/panel/query', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async exportDashboard(id: string): Promise<DashboardExport> {
    return this.request(`/api/dashboards/export/${id}`, {
      method: 'POST',
    });
  }

  async importDashboard(request: ImportDashboardRequest): Promise<Dashboard> {
    return this.request('/api/dashboards/import', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async validateCron(request: ValidateCronRequest): Promise<ValidateCronResponse> {
    return this.request('/api/lookup-tables/validate-cron', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }
}
