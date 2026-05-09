// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for RiskApi. Risk scoring + entity context are enterprise-only.

import type {
  RiskConfig,
  UpdateRiskConfigRequest,
  RiskDecayConfig,
  UpdateRiskDecayConfigRequest,
  RiskEntitiesQuery,
  RiskEntitiesResponse,
  RiskOverviewResponse,
  TimeWindowedRiskQuery,
  TimeWindowedRiskResponse,
  ClearEntityRiskRequest,
  ClearRiskResponse,
  EntityContextResponse,
  EntityActivityResponse,
} from '@/lib/api/types';

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('RiskApi is enterprise-only'));

export class RiskApi {
  constructor(
    _request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
  ) {
    void _request;
  }

  getRiskConfig(): Promise<RiskConfig> {
    return ENTERPRISE_ONLY();
  }
  updateRiskConfig(_request: UpdateRiskConfigRequest): Promise<RiskConfig> {
    return ENTERPRISE_ONLY();
  }
  getRiskDecayConfig(): Promise<RiskDecayConfig> {
    return ENTERPRISE_ONLY();
  }
  updateRiskDecayConfig(_request: UpdateRiskDecayConfigRequest): Promise<RiskDecayConfig> {
    return ENTERPRISE_ONLY();
  }
  getRiskyEntities(_params?: RiskEntitiesQuery): Promise<RiskEntitiesResponse> {
    return ENTERPRISE_ONLY();
  }
  getRiskOverview(): Promise<RiskOverviewResponse> {
    return ENTERPRISE_ONLY();
  }
  getTimeWindowedRiskScores(
    _params?: TimeWindowedRiskQuery,
  ): Promise<TimeWindowedRiskResponse> {
    return ENTERPRISE_ONLY();
  }
  clearEntityRisk(_request: ClearEntityRiskRequest): Promise<ClearRiskResponse> {
    return ENTERPRISE_ONLY();
  }
  clearAllRiskScores(): Promise<ClearRiskResponse> {
    return ENTERPRISE_ONLY();
  }
  getEntityRiskActivity(
    _entities: { entity: string; entity_type: string }[],
  ): Promise<EntityActivityResponse> {
    return ENTERPRISE_ONLY();
  }
  getEntityContext(
    _entityType: string,
    _entityValue: string,
    _identities?: string[],
  ): Promise<EntityContextResponse> {
    return ENTERPRISE_ONLY();
  }
}
