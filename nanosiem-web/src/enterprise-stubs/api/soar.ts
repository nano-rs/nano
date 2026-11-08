// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for SoarApi. SOAR is enterprise-only: `/api/soar/*` does
// not exist on open builds and every Automation affordance is hidden by the
// `soar` capability.

const ENTERPRISE_ONLY = (): Promise<never> => Promise.reject(new Error('SOAR is enterprise-only'));

export class SoarApi {
  constructor(_request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {
    void _request;
  }

  settings(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
}
