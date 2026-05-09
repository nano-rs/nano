// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for IncidentsApi. Incidents (case grouping into campaigns) are enterprise-only.

import type {
  AddCaseToIncidentRequest,
  CreateIncidentRequest,
  Incident,
  IncidentListResponse,
  IncidentWithCases,
} from '@/lib/api/types';

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('IncidentsApi is enterprise-only'));

export class IncidentsApi {
  constructor(
    _request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
  ) {
    void _request;
  }

  createIncident(_body: CreateIncidentRequest): Promise<Incident> {
    return ENTERPRISE_ONLY();
  }
  listIncidents(_params?: {
    status?: string;
    limit?: number;
    offset?: number;
  }): Promise<IncidentListResponse> {
    return ENTERPRISE_ONLY();
  }
  getIncident(_id: string): Promise<IncidentWithCases> {
    return ENTERPRISE_ONLY();
  }
  addCaseToIncident(
    _incidentId: string,
    _body: AddCaseToIncidentRequest,
  ): Promise<void> {
    return ENTERPRISE_ONLY();
  }
  removeCaseFromIncident(_incidentId: string, _caseId: string): Promise<void> {
    return ENTERPRISE_ONLY();
  }
}
