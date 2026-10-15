// SPDX-License-Identifier: AGPL-3.0-or-later
import { expect, it, vi } from 'vitest';
import { waitForDurableProductArtifact } from './durable-product-job';
const mocks = vi.hoisted(() => ({ job: vi.fn(), page: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { getSearchJob: mocks.job, getSearchJobResultPage: mocks.page } }));
it('forwards cancellation to both job status and artifact transport', async () => {
  const controller = new AbortController();
  mocks.job.mockResolvedValue({ status: 'completed', task_kind: 'asset_v1' });
  mocks.page.mockResolvedValue({ total_rows: 1, rows: [{ response: {} }] });
  await waitForDurableProductArtifact('job', 'asset_v1', undefined, () => true, controller.signal);
  expect(mocks.job.mock.calls.at(-1)?.[2]).toBe(controller.signal);
  expect(mocks.page.mock.calls.at(-1)?.[2]).toBe(controller.signal);
});
it('does not read an artifact or notify when an old status arrives', async () => {
  mocks.page.mockClear();
  const controller = new AbortController();
  mocks.job.mockImplementation(async () => { controller.abort(); return { status: 'completed' }; });
  const onJob = vi.fn();
  await expect(waitForDurableProductArtifact('old', 'asset_v1', onJob, () => true, controller.signal)).rejects.toThrow('superseded');
  expect(onJob).not.toHaveBeenCalled();
  expect(mocks.page).not.toHaveBeenCalled();
});
it('aborts a polling delay immediately without cancelling the durable job', async () => {
  vi.useFakeTimers();
  const controller = new AbortController();
  mocks.job.mockResolvedValue({ status: 'running' });
  const done = waitForDurableProductArtifact('job', 'asset_v1', () => controller.abort(), () => true, controller.signal);
  await expect(done).rejects.toMatchObject({ name: 'AbortError' });
  expect(vi.getTimerCount()).toBe(0);
  vi.useRealTimers();
});
