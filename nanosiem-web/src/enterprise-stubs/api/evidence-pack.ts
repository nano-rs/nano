// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for EvidencePackApi. The Evidence Pack is enterprise-only;
// `/api/compliance/*` does not exist on open builds and no nav entry, section
// or route leads to it there.

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('Evidence Pack is enterprise-only'));

export class EvidencePackApi {
  constructor(
    _request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
    _requestRaw: (endpoint: string, options?: RequestInit) => Promise<Response>,
  ) {
    void _request;
    void _requestRaw;
  }

  listFrameworks(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  list(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  get(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  create(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  remove(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  downloadArtifact(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
}
