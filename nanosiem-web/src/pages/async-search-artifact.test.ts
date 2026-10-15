// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { SearchJobStatus } from '@/lib/api/types';
import { AsyncSearchArtifact, artifactRows, asyncSearchPollDelay, pollSearchJob, shouldPrefetchArtifact } from './async-search-artifact';

const rows = (offset: number, count: number) => Array.from({ length: count }, (_, i) => ({ uid: offset + i }));
function fixture(pageRows = 10_000, total = 1050) {
  const submit = vi.fn(async (offset: number, limit: number): Promise<SearchJobStatus> => ({
    job_id: String(offset), status: 'completed',
    durable_result: {
      rows: Math.min(limit, Math.max(0, total - offset)),
      pages: Math.ceil(Math.min(limit, Math.max(0, total - offset)) / pageRows), page_rows: pageRows,
      has_more: offset + limit < total,
    },
  }));
  const getPage = vi.fn(async (jobId: string, page: number) => {
    const chunkRows = Math.min(500, Math.max(0, total - Number(jobId)));
    return { page, pages: Math.ceil(chunkRows / pageRows), total_rows: chunkRows, row_offset: page * pageRows,
      rows: rows(Number(jobId) + page * pageRows, Math.min(pageRows, chunkRows - page * pageRows)) };
  });
  return { pager: new AsyncSearchArtifact(500, submit, getPage), submit, getPage };
}

describe('artifact-backed search', () => {
  it('validates the artifact size knob', () => {
    expect(artifactRows(undefined)).toBe(500);
    expect(artifactRows('0')).toBe(500);
    expect(artifactRows('501')).toBe(550);
    expect(artifactRows('100000')).toBe(50_000);
  });

  it.each([50, 10_000])('serves ten UI pages with one job and artifact pages of %i rows', async pageRows => {
    const { pager, submit, getPage } = fixture(pageRows);
    for (let i = 0; i < 10; i++) expect(await pager.read(i * 50, 50)).toEqual(rows(i * 50, 50));
    expect(submit).toHaveBeenCalledExactlyOnceWith(0, 500);
    expect(getPage).toHaveBeenCalledTimes(pageRows === 50 ? 10 : 1);
    expect(pager.hasMore(500)).toBe(true);
  });

  it('coalesces concurrent artifact reads and duplicate chunk offsets', async () => {
    const { pager, submit, getPage } = fixture();
    await Promise.all([pager.read(0, 50), pager.read(0, 50), pager.read(50, 50)]);
    expect(submit).toHaveBeenCalledOnce();
    expect(getPage).toHaveBeenCalledOnce();
  });

  it('prefetches only at 70% after the displayed rows exhaust the artifact', async () => {
    expect(shouldPrefetchArtifact(349, 500, true)).toBe(false);
    expect(shouldPrefetchArtifact(350, 500, true)).toBe(true);
    expect(shouldPrefetchArtifact(350, 500, false)).toBe(false);
    const { pager, submit, getPage } = fixture();
    await pager.read(0, 50);
    await pager.prefetch(35, 50);
    await pager.prefetch(349, 500);
    expect(submit).toHaveBeenCalledOnce();
    await Promise.all([pager.prefetch(350, 500), pager.prefetch(400, 500)]);
    expect(submit.mock.calls).toEqual([[0, 500], [500, 500]]);
    expect(getPage).toHaveBeenCalledTimes(2);
    expect(await pager.read(500, 50)).toEqual(rows(500, 50));
    expect(submit).toHaveBeenCalledTimes(2);
    expect(getPage).toHaveBeenCalledTimes(2);
  });

  it('reads table ranges across page and chunk boundaries and reuses earlier pages', async () => {
    const { pager, submit } = fixture(50);
    expect(await pager.read(450, 100)).toEqual(rows(450, 100));
    expect(await pager.read(475, 50)).toEqual(rows(475, 50));
    expect(submit.mock.calls).toEqual([[0, 500], [500, 500]]);
  });

  it.each([0, 517, 1000])('terminates at a short/empty chunk or has_more=false (%i rows)', async total => {
    const { pager, getPage } = fixture(50, total);
    expect(await pager.read(0, total + 100)).toEqual(rows(0, total));
    expect(pager.hasMore(total)).toBe(false);
    expect(await pager.read(total, 50)).toEqual([]);
    if (total === 0) expect(getPage).not.toHaveBeenCalled();
  });

  it('keeps the exact initial total and histogram when supplied with the artifact', async () => {
    const { submit, getPage } = fixture();
    const histogram = [{ time: '2026-09-21T00:00:00Z', count: 12345 }];
    const pager = new AsyncSearchArtifact(500, async (offset, limit) => ({
      ...await submit(offset, limit),
      ...(offset === 0 ? { result: { results: [], fields: [], total_count: 12345, execution_time_ms: 550, histogram } } : {}),
    }), getPage);
    await pager.read(0, 50);
    await pager.prefetch(350, 500);
    expect(pager.totalCount).toBe(12345);
    expect(pager.response?.histogram).toEqual(histogram);
  });

  it('retries failed speculative submissions and page fetches on demand', async () => {
    const { pager, submit, getPage } = fixture();
    await pager.read(0, 50);
    submit.mockRejectedValueOnce(new Error('unavailable'));
    await expect(pager.prefetch(350, 500)).rejects.toThrow('unavailable');
    getPage.mockRejectedValueOnce(new Error('page unavailable'));
    await expect(pager.read(500, 50)).rejects.toThrow('page unavailable');
    expect(await pager.read(500, 50)).toEqual(rows(500, 50));
    expect(submit.mock.calls).toEqual([[0, 500], [500, 500], [500, 500]]);
  });
});

describe('async search polling', () => {
  afterEach(() => vi.useRealTimers());
  it('backs off per job and never overlaps requests', async () => {
    vi.useFakeTimers();
    expect([0, 1, 2, 3, 100].map(asyncSearchPollDelay)).toEqual([150, 300, 600, 1000, 1000]);
    const getStatus = vi.fn(async (): Promise<SearchJobStatus> => ({ job_id: 'job', status: 'running' }));
    const signal = new AbortController().signal;
    const result = pollSearchJob(getStatus, signal);
    await vi.advanceTimersByTimeAsync(149);
    expect(getStatus).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(getStatus).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(300);
    expect(getStatus).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(600);
    expect(getStatus).toHaveBeenCalledTimes(3);
    getStatus.mockResolvedValueOnce({ job_id: 'job', status: 'completed' });
    await vi.advanceTimersByTimeAsync(1000);
    expect((await result).status).toBe('completed');
    getStatus.mockResolvedValueOnce({ job_id: 'next', status: 'completed' });
    const next = pollSearchJob(getStatus, signal);
    await vi.advanceTimersByTimeAsync(150);
    expect((await next).job_id).toBe('next');
    expect(vi.getTimerCount()).toBe(0);
  });

  it('keeps polling the same job across transport failures', async () => {
    vi.useFakeTimers();
    const getStatus = vi.fn()
      .mockRejectedValueOnce(new Error('network unavailable'))
      .mockResolvedValueOnce({ job_id: 'job', status: 'completed' });
    const result = pollSearchJob(getStatus, new AbortController().signal);
    await vi.advanceTimersByTimeAsync(450);
    expect((await result).job_id).toBe('job');
    expect(getStatus).toHaveBeenCalledTimes(2);
  });

  it('waits for an in-flight poll and discards its result after cancellation', async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    let complete!: (status: SearchJobStatus) => void;
    const getStatus = vi.fn(() => new Promise<SearchJobStatus>(resolve => { complete = resolve; }));
    const onStatus = vi.fn();
    const result = pollSearchJob(getStatus, controller.signal, onStatus);
    const rejection = expect(result).rejects.toMatchObject({ name: 'AbortError' });
    await vi.advanceTimersByTimeAsync(5000);
    expect(getStatus).toHaveBeenCalledOnce();
    controller.abort();
    complete({ job_id: 'stale', status: 'completed' });
    await rejection;
    expect(onStatus).not.toHaveBeenCalled();
  });

  it('retains the 24-hour wall-clock limit', async () => {
    vi.useFakeTimers();
    const getStatus = vi.fn(async (): Promise<SearchJobStatus> => {
      vi.setSystemTime(Date.now() + 86_400_000);
      return { job_id: 'long', status: 'running' };
    });
    const result = pollSearchJob(getStatus, new AbortController().signal);
    const rejection = expect(result).rejects.toThrow('24 hours');
    await vi.advanceTimersByTimeAsync(150);
    await rejection;
    expect(getStatus).toHaveBeenCalledOnce();
  });

  it('aborts the timer immediately and rejects stale responses', async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const getStatus = vi.fn();
    const result = pollSearchJob(getStatus, controller.signal);
    const rejection = expect(result).rejects.toMatchObject({ name: 'AbortError' });
    controller.abort();
    await rejection;
    expect(getStatus).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
});
