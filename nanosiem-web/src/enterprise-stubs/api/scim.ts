// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for ScimApi. SCIM provisioning is enterprise-only
// (NAN-5274); `/api/settings/oidc/*/scim` does not exist on open builds and
// the only caller (the SSO provider sheet) is enterprise-only too.

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('SCIM provisioning is enterprise-only'));

export interface ScimGroupSource {
  group_id: string;
  provider_id: string;
  provider_name: string;
  idp_group: string;
}

export class ScimApi {
  constructor(_request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {
    void _request;
  }

  status(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  issueToken(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  revokeToken(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  groupSources(): Promise<ScimGroupSource[]> {
    return Promise.resolve([]);
  }
}
