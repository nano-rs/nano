// SPDX-License-Identifier: AGPL-3.0-or-later
export interface LookupUrlEntry { host: string; note: string; created_by: string; created_at: string }
export class LookupUrlAllowlistApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}
  get(): Promise<{ entries: LookupUrlEntry[] }> {
    return this.request('/api/settings/inputlookup-storage');
  }
  add(host: string, note: string): Promise<unknown> {
    return this.request('/api/settings/inputlookup-storage', { method: 'POST', body: JSON.stringify({ host, note }) });
  }
  remove(host: string): Promise<unknown> {
    return this.request(`/api/settings/inputlookup-storage/${encodeURIComponent(host)}`, { method: 'DELETE' });
  }
}
