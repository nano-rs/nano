// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for IocListsApi. Code-free IOC lists are enterprise-only;
// `/api/ioc-lists` does not exist on open builds, and the nav item is hidden
// by the `iocLists` capability.

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('IOC lists are enterprise-only'));

export class IocListsApi {
  constructor(_request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {
    void _request;
  }

  list(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  indicators(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  create(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  update(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  publications(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  remove(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
  publish(): Promise<never> {
    return ENTERPRISE_ONLY();
  }
}
