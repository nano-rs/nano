// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Code-free tenant IOC lists (NAN-3038) — `/api/ioc-lists/*`.
 *
 * Static indicator lists validated and normalized server-side, then
 * published to the tenant's IOC snapshot. No enrichment code runs.
 */

export type IocType = 'ip' | 'domain' | 'hash' | 'url' | 'email';
export type IocUploadFormat = 'csv' | 'json' | 'text';

export interface IocIndicatorInput {
  value: string;
  ioc_type?: IocType;
  risk_score?: number;
  tags?: string[];
  expires_at?: string;
  note?: string;
}

export interface IocIndicator {
  value: string;
  ioc_type: IocType;
  risk_score: number;
  tags: string[];
  expires_at: string | null;
  note: string | null;
}

export interface IocListSummary {
  id: string;
  name: string;
  description: string | null;
  indicator_count: number;
  counts: Partial<Record<IocType, number>>;
  /** Indicators carrying an expiry (null for lists stored before it was tracked). */
  with_expiry?: number | null;
  /** Indicators already past their expiry (kept, but no longer matched). */
  expired_count?: number | null;
  next_expiry_at?: string | null;
  created_at: string;
  updated_at: string;
  last_published_at: string | null;
  last_published_count: number | null;
  publish_pending: boolean;
  /** NAN-3882: publication runs in the background; poll while `publishing`. */
  publish_state: IocPublishState;
  publish_started_at: string | null;
  publish_error: string | null;
}

export type IocPublishState = 'never' | 'publishing' | 'published' | 'failed';
export type IocMatchMode = 'prefix' | 'contains';

export interface IocIndicatorEntry extends IocIndicator {
  added_at: string;
  /** Past its expiry: kept for history, no longer published or matched. */
  expired: boolean;
}

export interface IocIndicatorPage {
  indicators: IocIndicatorEntry[];
  next_cursor: string | null;
  scanned: number;
  scan_limited: boolean;
}

export interface IocIndicatorQuery {
  q?: string;
  match?: IocMatchMode;
  type?: IocType;
  after?: string | null;
  limit?: number;
  /** Server default is true. */
  hide_expired?: boolean;
}

export interface IocIndicatorsPayload {
  indicators?: IocIndicatorInput[];
  content?: string;
  format?: IocUploadFormat;
  default_risk_score?: number;
  default_tags?: string[];
  /** Expiry for indicators without their own `expires_at` (must be in the future). */
  default_expires_at?: string;
  /** Free-text context (incident or case ref) for indicators without a note. */
  default_note?: string;
}

/** Whole-list expiry change. */
export type IocExpiryChange = { action: 'set'; expires_at: string } | { action: 'clear' };

export interface CreateIocListRequest extends IocIndicatorsPayload {
  name: string;
  description?: string;
}

export interface UpdateIocListRequest extends IocIndicatorsPayload {
  description?: string;
  mode?: 'replace' | 'append';
  remove?: string[];
  expiry?: IocExpiryChange;
  /** Delete indicators already past their expiry. */
  purge_expired?: boolean;
}

export interface IocListDetail {
  list: IocListSummary;
  indicators: IocIndicator[];
  total: number;
  page: number;
  page_size: number;
}

/** `202`: the publication started (or was already running when `started` is false). */
export interface IocListPublishResult {
  list: IocListSummary;
  started: boolean;
}

/** Infer the upload format from a file name (CSV when unknown). */
export function uploadFormatFor(fileName: string): IocUploadFormat {
  const lower = fileName.toLowerCase();
  if (lower.endsWith('.json')) return 'json';
  if (lower.endsWith('.txt') || lower.endsWith('.list')) return 'text';
  return 'csv';
}

export interface IocLimits {
  indicators_per_list: number;
  indicators_per_tenant: number;
  list_count: number;
  upload_bytes: number;
}
export interface IocListOverview {
  lists: IocListSummary[];
  limits: IocLimits;
  usage: { list_count: number; indicators: number };
}

export class IocListsApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}

  async list(): Promise<IocListOverview> {
    return this.request('/api/ioc-lists');
  }

  async get(id: string, page = 1, pageSize = 100): Promise<IocListDetail> {
    return this.request(`/api/ioc-lists/${encodeURIComponent(id)}?page=${page}&page_size=${pageSize}`);
  }

  /** Keyset page of a list's indicators (server-side search, never the whole list). */
  async indicators(id: string, query: IocIndicatorQuery = {}): Promise<IocIndicatorPage> {
    const params = new URLSearchParams();
    if (query.q?.trim()) params.set('q', query.q.trim());
    if (query.match) params.set('match', query.match);
    if (query.type) params.set('type', query.type);
    if (query.after) params.set('after', query.after);
    if (query.limit) params.set('limit', String(query.limit));
    if (query.hide_expired === false) params.set('hide_expired', 'false');
    const qs = params.toString();
    return this.request(`/api/ioc-lists/${encodeURIComponent(id)}/indicators${qs ? `?${qs}` : ''}`);
  }

  async create(request: CreateIocListRequest, file?: File): Promise<IocListSummary> {
    if (file || (request.content !== undefined && !request.indicators?.length)) return this.upload('/api/ioc-lists/upload', 'POST', request, file);
    return this.request('/api/ioc-lists', { method: 'POST', body: JSON.stringify(request) });
  }

  async update(id: string, request: UpdateIocListRequest, file?: File): Promise<IocListSummary> {
    const path = `/api/ioc-lists/${encodeURIComponent(id)}`;
    if (file || (request.content !== undefined && !request.indicators?.length)) return this.upload(`${path}/upload`, 'PUT', request, file);
    return this.request(path, { method: 'PUT', body: JSON.stringify(request) });
  }

  private upload(path: string, method: string, request: CreateIocListRequest | UpdateIocListRequest, file?: File): Promise<IocListSummary> {
    const { content, format, ...options } = request;
    const query = new URLSearchParams({ format: format ?? 'csv' });
    // Headers are ASCII; JSON escapes preserve Unicode metadata without
    // putting notes/defaults in the URL or reading the entire file.
    const metadata = JSON.stringify(options).replace(/[\u007f-\uffff]/g, (character) =>
      `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);
    return this.request(`${path}?${query}`, { method, headers: { 'Content-Type': 'application/octet-stream', 'x-ioc-list-options': metadata },
      body: file ?? new Blob([content ?? '']) });
  }

  async remove(id: string): Promise<{ deleted: boolean; withdrawn: boolean }> {
    return this.request(`/api/ioc-lists/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  async publish(id: string): Promise<IocListPublishResult> {
    return this.request(`/api/ioc-lists/${encodeURIComponent(id)}/publish`, { method: 'POST' });
  }
}
