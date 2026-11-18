// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for HuntsApi. Hunts are enterprise-only: `/api/hunts/*`
// does not exist on open builds, and no nav entry or route leads to it there
// (the rail entry is capability-gated and the routes render the paid-plan
// placeholder).

const ENTERPRISE_ONLY = (): Promise<never> => Promise.reject(new Error('Hunts are enterprise-only'));

export function leadsQueryString(): string {
  return '';
}

export function unwrapList<T>(): T[] {
  return [];
}

export class HuntsApi {
  constructor(_request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {
    void _request;
  }

  update(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  funnel(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  sweepTasks(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  templates(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  instantiateTemplate(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  summary(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  list(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  get(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  toggle(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  setSchedule(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  sweeps(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  triggerSweep(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  sweep(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  leads(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  lead(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  promote(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  dismiss(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  suppressions(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  revokeSuppression(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  knowledge(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  revokeKnowledge(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  profile(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  bindings(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  ruleIdeas(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  sendRuleIdea(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  rejectRuleIdea(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  agentDetections(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  setAgentDetectionsEnabled(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  agentDetectionTrips(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  pauseAgentDetection(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  resumeAgentDetection(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  retireAgentDetection(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  runners(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  setAgyWaiver(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
}
