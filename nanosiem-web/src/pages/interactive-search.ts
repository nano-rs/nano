// SPDX-License-Identifier: AGPL-3.0-or-later
import type { SearchApi } from '@/lib/api/search';
import type { AsyncSearchResponse, SearchRequest, SearchResponse, SearchJobStatus } from '@/lib/api/types';
import type { AuthorityRetryOptions } from '@/lib/api/search-authority-retry';
import type { CacheMeta } from '@/lib/api';
import { AsyncSearchArtifact, pollSearchJob } from './async-search-artifact';

/** Keep admission, cancellation and artifact continuations on one request snapshot. */
export async function startInteractiveSearch(
  api: Pick<SearchApi, 'searchInteractive' | 'cancelSearch' | 'cancelSearchJob' | 'getSearchJob' | 'getSearchJobResultPage'>,
  request: Omit<SearchRequest, 'async_mode'>,
  chunkRows: number,
  signal: AbortSignal,
  isCurrent: () => boolean,
  retry: AuthorityRetryOptions,
  onStatus: (status: SearchJobStatus) => void,
  // NAN-3809: cache status of the first admission (a re-served settled job).
  onCacheMeta?: (meta: CacheMeta) => void,
): Promise<{ response: SearchResponse; pager?: never } | { pager: AsyncSearchArtifact; response?: never }> {
  const assertCurrent = () => {
    signal.throwIfAborted();
    if (!isCurrent()) throw new DOMException('Search superseded', 'AbortError');
  };
  const submit = async (offset: number, limit: number) => {
    assertCurrent();
    const cancel = () => { if (request.request_id) void api.cancelSearch(request.request_id).catch(() => {}); };
    signal.addEventListener('abort', cancel, { once: true });
    try {
      // A caller that asks for the timeline separately (NAN-3093) skips it on
      // every page; otherwise only page 1 carries it.
      const body = { ...request, offset, limit, skip_histogram: request.skip_histogram === true || offset > 0 };
      const onMeta = offset === initialOffset ? onCacheMeta : undefined;
      const response = onMeta
        ? await api.searchInteractive(body, retry, onMeta)
        : await api.searchInteractive(body, retry);
      if (signal.aborted || !isCurrent()) {
        if ('job_id' in response) await api.cancelSearchJob(response.job_id).catch(() => {});
        assertCurrent();
      }
      return response;
    } finally {
      signal.removeEventListener('abort', cancel);
    }
  };
  const initialOffset = request.offset ?? 0;
  const initialRows = request.limit ?? chunkRows;
  const initial = await submit(initialOffset, initialRows);
  if (!('job_id' in initial)) return { response: initial };

  const complete = async (response: SearchResponse | AsyncSearchResponse, offset: number): Promise<SearchJobStatus> => {
    if ((signal.aborted || !isCurrent()) && 'job_id' in response) {
      await api.cancelSearchJob(response.job_id).catch(() => {});
    }
    assertCurrent();
    if (!('job_id' in response)) return { job_id: '', status: 'completed', result: response };
    const cancel = () => { void api.cancelSearchJob(response.job_id).catch(() => {}); };
    signal.addEventListener('abort', cancel, { once: true });
    try {
      return await pollSearchJob(() => api.getSearchJob(response.job_id, retry), signal, status => {
        assertCurrent();
        if (offset === initialOffset) onStatus(status);
      });
    } finally {
      signal.removeEventListener('abort', cancel);
    }
  };
  const pager = new AsyncSearchArtifact(chunkRows,
    async (offset, limit) => complete(offset === initialOffset ? initial : await submit(offset, limit), offset),
    async (jobId, page) => {
      assertCurrent();
      const result = await api.getSearchJobResultPage(jobId, page);
      assertCurrent();
      return result;
    }, initialOffset, initialRows);
  return { pager };
}
