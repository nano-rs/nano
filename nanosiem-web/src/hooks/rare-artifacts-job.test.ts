// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-3088: a lean tenant's rare list is a durable cell job the client follows. */
import { afterEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ getRareArtifacts: vi.fn(), getSearchJob: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { getRareArtifacts: mocks.getRareArtifacts, getSearchJob: mocks.getSearchJob } }));

import { rareArtifactsFollowingJob } from './use-api';

const page = (extra: Record<string, unknown>) => ({ artifacts: [], total: 0, limit: 25, offset: 0, has_more: false, ...extra });

afterEach(() => {
  vi.clearAllMocks();
  vi.useRealTimers();
});

describe('rareArtifactsFollowingJob', () => {
  it('answers a dedicated (job-less) list directly', async () => {
    mocks.getRareArtifacts.mockResolvedValueOnce(page({ total: 3 }));
    expect((await rareArtifactsFollowingJob({ window: '24h' })).total).toBe(3);
    expect(mocks.getSearchJob).not.toHaveBeenCalled();
  });

  it('follows a pending job, then reads the page from that job', async () => {
    vi.useFakeTimers();
    mocks.getRareArtifacts
      .mockResolvedValueOnce(page({ job_id: 'job-1', job_status: 'queued' }))
      .mockResolvedValueOnce(page({ job_id: 'job-1', job_status: 'completed', total: 7 }));
    mocks.getSearchJob
      .mockResolvedValueOnce({ status: 'running', task_kind: 'prevalence_export_v1' })
      .mockResolvedValueOnce({ status: 'completed', task_kind: 'prevalence_export_v1' });
    const pending = rareArtifactsFollowingJob({ window: '24h', limit: 25 });
    await vi.runAllTimersAsync();
    const result = await pending;
    expect(result.total).toBe(7);
    expect(mocks.getRareArtifacts).toHaveBeenLastCalledWith({ window: '24h', limit: 25, job_id: 'job-1' });
  });

  it('surfaces a failed or retyped job instead of an empty list', async () => {
    mocks.getRareArtifacts.mockResolvedValue(page({ job_id: 'job-2', job_status: 'running' }));
    mocks.getSearchJob.mockResolvedValueOnce({ status: 'failed', error: 'cell refused', task_kind: 'prevalence_export_v1' });
    await expect(rareArtifactsFollowingJob({ window: '7d' })).rejects.toThrow('cell refused');
    mocks.getSearchJob.mockResolvedValueOnce({ status: 'running', task_kind: 'search_npl_v1' });
    await expect(rareArtifactsFollowingJob({ window: '7d' })).rejects.toThrow('changed type');
  });
});
