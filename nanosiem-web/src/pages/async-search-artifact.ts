// SPDX-License-Identifier: AGPL-3.0-or-later
import type { SearchJobResultPage, SearchJobStatus, SearchResponse } from '@/lib/api/types';
import { reserveAsyncSearchOffset } from './async-search-paging';

export function artifactRows(value: unknown, pageSize = 50): number {
  const rows = Number(value);
  return Number.isFinite(rows) && rows >= pageSize
    ? Math.min(50_000, Math.ceil(rows / pageSize) * pageSize) : 500;
}

export function asyncSearchPollDelay(poll: number): number {
  return [150, 300, 600][poll] ?? 1000;
}

export function shouldPrefetchArtifact(visibleEnd: number, loadedRows: number, artifactExhausted: boolean): boolean {
  return artifactExhausted && loadedRows > 0 && visibleEnd >= Math.ceil(loadedRows * 0.7);
}

export async function pollSearchJob(
  getStatus: () => Promise<SearchJobStatus>,
  signal: AbortSignal,
  onStatus: (status: SearchJobStatus) => void = () => {},
): Promise<SearchJobStatus> {
  const started = Date.now();
  for (let poll = 0; poll < 86_400 && Date.now() - started < 86_400_000; poll++) {
    signal.throwIfAborted();
    await new Promise<void>((resolve, reject) => {
      const abort = () => { clearTimeout(timer); reject(signal.reason); };
      const timer = setTimeout(() => { signal.removeEventListener('abort', abort); resolve(); }, asyncSearchPollDelay(poll));
      signal.addEventListener('abort', abort, { once: true });
    });
    signal.throwIfAborted();
    let status: SearchJobStatus;
    try {
      status = await getStatus();
    } catch (error) {
      signal.throwIfAborted();
      const httpStatus = (error as { status?: number })?.status;
      if ((error instanceof Error && error.name === 'AbortError')
        || (httpStatus && httpStatus >= 400 && httpStatus < 500 && httpStatus !== 429)) throw error;
      // Keep the same durable job across transient transport/service failures.
      continue;
    }
    signal.throwIfAborted();
    onStatus(status);
    if (status.status === 'completed') return status;
    if (status.status === 'failed' || status.status === 'cancelled') {
      throw new Error(status.error || `Search job ${status.status}`);
    }
  }
  throw new Error('Search job polling timed out after 24 hours');
}

interface Chunk {
  jobId: string;
  rows: number;
  pages: number;
  pageRows: number;
  cached: Map<number, Promise<SearchJobResultPage>>;
}

/** One immutable search snapshot. Chunk and page promises coalesce scroll,
 * table navigation and prefetch; a failed request can be retried on demand.
 * Escalation can start at a later UI page with a smaller initial request;
 * subsequent chunks retain the configured artifact batch size. */
export class AsyncSearchArtifact {
  private chunks = new Map<number, Promise<Chunk>>();
  private lastOffset = { current: null as number | null };
  private end = Infinity;
  private availableEnd = 0;
  readonly chunkRows: number;
  response?: SearchResponse;

  constructor(
    rows: number,
    private submit: (offset: number, limit: number) => Promise<SearchJobStatus>,
    private getPage: (jobId: string, page: number) => Promise<SearchJobResultPage>,
    private initialOffset = 0,
    private initialRows = rows,
  ) { this.chunkRows = rows; }

  private chunk(offset: number): Promise<Chunk> {
    const existing = this.chunks.get(offset);
    if (existing) return existing;
    if (!reserveAsyncSearchOffset(this.lastOffset, {
      append: offset > 0, offset, page: offset / this.chunkRows + 1, pageSize: this.chunkRows,
    }, offset >= this.end)) throw new Error('Search artifact is exhausted');
    const limit = offset === this.initialOffset ? this.initialRows : this.chunkRows;
    const pending = this.submit(offset, limit).then(status => {
      const summary = status.durable_result;
      const inline = status.result;
      if (!summary && !inline) throw new Error('Completed search has no result');
      const rows = summary?.rows ?? inline!.results.length;
      if (rows < limit || summary?.has_more === false) this.end = Math.min(this.end, offset + rows);
      this.availableEnd = Math.max(this.availableEnd, offset + rows);
      if (offset === this.initialOffset) this.response = inline;
      const chunk: Chunk = {
        jobId: status.job_id, rows,
        pages: summary?.pages ?? (rows ? 1 : 0),
        pageRows: summary?.page_rows ?? Math.max(1, rows),
        cached: new Map(),
      };
      if (inline && !summary) chunk.cached.set(0, Promise.resolve({
        page: 0, pages: chunk.pages, total_rows: rows, row_offset: 0, rows: inline.results,
      }));
      return chunk;
    }).catch(error => {
      this.chunks.delete(offset);
      if (this.lastOffset.current === offset) this.lastOffset.current = null;
      throw error;
    });
    this.chunks.set(offset, pending);
    return pending;
  }

  private page(chunk: Chunk, index: number): Promise<SearchJobResultPage> {
    const existing = chunk.cached.get(index);
    if (existing) return existing;
    const pending = this.getPage(chunk.jobId, index).catch(error => {
      chunk.cached.delete(index);
      throw error;
    });
    chunk.cached.set(index, pending);
    return pending;
  }

  get totalCount(): number {
    return this.response?.total_count ?? (Number.isFinite(this.end) ? this.end : this.availableEnd + 1);
  }

  hasMore(offset: number): boolean { return offset < this.end; }

  async read(offset: number, count: number): Promise<Record<string, unknown>[]> {
    const rows: Record<string, unknown>[] = [];
    let cursor = offset;
    while (rows.length < count && cursor < this.end) {
      const afterInitial = cursor - this.initialOffset - this.initialRows;
      const base = afterInitial < 0 ? this.initialOffset
        : this.initialOffset + this.initialRows + Math.floor(afterInitial / this.chunkRows) * this.chunkRows;
      const chunk = await this.chunk(base);
      if (cursor >= base + chunk.rows) break;
      const local = cursor - base;
      const index = Math.floor(local / chunk.pageRows);
      if (index >= chunk.pages) throw new Error('Search artifact page is missing');
      const page = await this.page(chunk, index);
      const start = local - page.row_offset;
      const slice = page.rows.slice(start, start + count - rows.length);
      if (!slice.length) throw new Error('Search artifact page is incomplete');
      rows.push(...slice);
      cursor += slice.length;
    }
    return rows;
  }

  async prefetch(visibleEnd: number, loadedRows: number): Promise<void> {
    const afterInitial = loadedRows - this.initialOffset - this.initialRows;
    const exhausted = afterInitial >= 0 && afterInitial % this.chunkRows === 0;
    if (!shouldPrefetchArtifact(visibleEnd, loadedRows, exhausted) || !this.hasMore(loadedRows)) return;
    await this.read(loadedRows, 1);
  }
}
