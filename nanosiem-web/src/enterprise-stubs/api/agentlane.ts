// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for AgentLaneApi. Agent Lane is enterprise-only
// (NAN-5360); `/api/settings/agentlane*` does not exist on open builds and the
// only caller (its Settings page) is enterprise-only too.

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('Agent Lane is enterprise-only'));

export class AgentLaneApi {
  constructor(_request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {
    void _request;
  }

  status(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  setEnabled(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  tokens(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  createToken(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  usage(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  schema(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  setLimits(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  revokeToken(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
}
