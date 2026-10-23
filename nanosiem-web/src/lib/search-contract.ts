// SPDX-License-Identifier: AGPL-3.0-or-later
import type { SearchApi } from './api/search';

/** Transport-independent lifecycle seam. Browser implements this with its auth
 * client; desktop implements it with Rust IPC. No credentials or URLs belong
 * to a run, and artifact coordinates never cross this interface. */
export type SearchTransport = Pick<SearchApi,
  'searchInteractive' | 'cancelSearch' | 'cancelSearchJob' | 'getSearchJob' | 'getSearchJobResultPage'>;

export type {
  SearchRequest, SearchResponse, SearchJobStatus, SearchJobResultPage,
  SearchJobProgress, FieldInfo, FieldValuesResponse,
} from './api/types';

/** Cache reuse requires the complete resolved request and authenticated scope.
 * Relative presets are resolved before this key is made; never key on a label. */
export function searchIdentity(scope: string, userId: string, request: {
  query: string; time_range: { start: string; end: string }; dataset?: string;
  table_view?: boolean;
}): string {
  return JSON.stringify([scope, userId, request.query, request.dataset ?? 'logs',
    request.table_view ?? false, request.time_range.start, request.time_range.end]);
}
