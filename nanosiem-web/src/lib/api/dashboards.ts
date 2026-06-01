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

// Retry panel queries that the search admission controller sheds (HTTP 429
// TOO_MANY_REQUESTS / AdmissionDenied). The backend caps concurrent queries per
// user (per_user_limit), so a burst — e.g. a dashboard's panels loading — can be
// briefly denied. Scoped to panelQuery only: it is read-only and idempotent, so
// this can never retry a mutation.
const PANEL_MAX_ATTEMPTS = 3;
const PANEL_BASE_DELAY_MS = 400;
const PANEL_MAX_DELAY_MS = 4000;

function isAdmissionDenied(err: unknown): boolean {
  const e = err as { status?: number; code?: string } | null;
  return !!e && (e.status === 429 || e.code === 'TOO_MANY_REQUESTS' || e.code === 'ADMISSION_DENIED');
}

const sleep = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));

async function retryOn429<T>(fn: () => Promise<T>): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (attempt >= PANEL_MAX_ATTEMPTS || !isAdmissionDenied(err)) throw err;
      // Exponential backoff with full jitter, so panels denied simultaneously
      // don't retry in lockstep and re-collide on the same admission slots.
      const ceil = Math.min(PANEL_BASE_DELAY_MS * 2 ** (attempt - 1), PANEL_MAX_DELAY_MS);
      await sleep(Math.random() * ceil);
    }
  }
}

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
    return retryOn429(() =>
      this.request<PanelQueryResponse>('/api/dashboards/panel/query', {
        method: 'POST',
        body: JSON.stringify(request),
      })
    );
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
