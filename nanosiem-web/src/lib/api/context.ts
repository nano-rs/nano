// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  OrganizationalContext,
  UpdateOrganizationalContextRequest,
} from './types';

export class ContextApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async getOrganizationalContext(): Promise<OrganizationalContext> {
    return this.request('/api/settings/organizational-context');
  }

  async updateOrganizationalContext(request: UpdateOrganizationalContextRequest): Promise<OrganizationalContext> {
    return this.request('/api/settings/organizational-context', {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }
}
