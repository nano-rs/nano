// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5132: the client starts log-source deploys as background jobs and
 * follows them to the end, handing callers the same final result (or error)
 * the synchronous call returned.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DeployJob } from '@/lib/api/types';
import { LogSourcesApi } from '@/lib/api/log-sources';
import {
  DeployJobPollTimeout,
  followDeployJob,
  latestDeployJob,
  phaseStep,
  resetDeployJobBus,
  stateLabel,
  subscribeDeployJobs,
} from './deploy-job';

afterEach(resetDeployJobBus);

const noSleep = () => Promise.resolve();

function job(overrides: Partial<DeployJob> = {}): DeployJob {
  return {
    id: 'djob_1',
    kind: 'deploy',
    log_source_id: 'lsrc_a',
    state: 'queued',
    phase: 'queued',
    message: null,
    result: null,
    error_status: null,
    created_at: '2026-11-11T10:00:00Z',
    started_at: null,
    finished_at: null,
    heartbeat_at: '2026-11-11T10:00:00Z',
    coalesced: false,
    status_path: '/api/log-sources/deploy-jobs/djob_1',
    ...overrides,
  };
}

const deployed = {
  success: true,
  parser_id: 'lsrc_a',
  action: 'deploy',
  message: "Log source 'a' deployed successfully",
  recent_deployments: [],
};

describe('followDeployJob', () => {
  it('polls until terminal and reports every phase on the bus and to onProgress', async () => {
    const updates = [
      job({ state: 'running', phase: 'rendering' }),
      job({ state: 'running', phase: 'reloading' }),
      job({ state: 'succeeded', phase: 'done', result: deployed, finished_at: '2026-11-11T10:00:09Z' }),
    ];
    const fetchJob = vi.fn(async () => updates.shift()!);
    const seen: string[] = [];
    const bus: string[] = [];
    const unsubscribe = subscribeDeployJobs((j) => bus.push(j.phase));
    const final = await followDeployJob(job(), fetchJob, {
      sleep: noSleep,
      onProgress: (j) => seen.push(`${j.state}:${j.phase}`),
    });
    unsubscribe();
    expect(final.state).toBe('succeeded');
    expect(fetchJob).toHaveBeenCalledTimes(3);
    expect(seen).toEqual(['queued:queued', 'running:rendering', 'running:reloading', 'succeeded:done']);
    expect(bus).toEqual(['queued', 'rendering', 'reloading', 'done']);
    expect(latestDeployJob('lsrc_a')?.state).toBe('succeeded');
  });

  it('retries a transient poll error, gives up after three in a row', async () => {
    const flaky = vi
      .fn()
      .mockRejectedValueOnce(new Error('502'))
      .mockResolvedValueOnce(job({ state: 'succeeded', phase: 'done' }));
    await expect(followDeployJob(job(), flaky, { sleep: noSleep })).resolves.toMatchObject({ state: 'succeeded' });

    const down = vi.fn().mockRejectedValue(new Error('down'));
    await expect(followDeployJob(job(), down, { sleep: noSleep })).rejects.toThrow('down');
    expect(down).toHaveBeenCalledTimes(3);
  });

  it('stops following after the wait limit without claiming failure', async () => {
    const stuck = vi.fn(async () => job({ state: 'running', phase: 'reloading' }));
    await expect(
      followDeployJob(job(), stuck, { sleep: noSleep, timeoutMs: -1 }),
    ).rejects.toBeInstanceOf(DeployJobPollTimeout);
  });
});

describe('LogSourcesApi deploy jobs', () => {
  function client(started: unknown, polls: DeployJob[]) {
    const request = vi.fn(async (endpoint: string) => {
      if (endpoint.startsWith('/api/log-sources/deploy-jobs/')) return polls.shift();
      return undefined;
    });
    const longRequest = vi.fn().mockImplementation(async () => started);
    const makeError = vi.fn((message: string, code: string, status?: number) =>
      Object.assign(new Error(message), { code, status }),
    );
    // @ts-expect-error — the test doubles are loosely typed
    return { request, longRequest, api: new LogSourcesApi(request, longRequest, makeError) };
  }

  it('starts with wait=false and resolves to the job result', async () => {
    const { api, longRequest, request } = client(job(), [
      job({ state: 'running', phase: 'reloading' }),
      job({ state: 'succeeded', phase: 'done', result: deployed }),
    ]);
    const result = await api.deployLogSource('lsrc_a', { sleep: noSleep });
    expect(result).toEqual(deployed);
    expect(longRequest.mock.calls[0][0]).toBe('/api/log-sources/lsrc_a/deploy?wait=false');
    expect(request).toHaveBeenCalledWith('/api/log-sources/deploy-jobs/djob_1');
  });

  it('returns a failed deploy result (success: false) as before, it does not throw', async () => {
    const failed = { ...deployed, success: false, message: 'Reload failed, rolled back: refused' };
    const { api } = client(job(), [job({ state: 'rolled_back', phase: 'done', result: failed })]);
    await expect(api.deployLogSource('lsrc_a', { sleep: noSleep })).resolves.toEqual(failed);
  });

  it('throws the status the synchronous call would have returned (409 on a stale publish)', async () => {
    const { api } = client(job({ kind: 'publish' }), [
      job({ kind: 'publish', state: 'failed', phase: 'done', error_status: 409, message: 'Conflict: modified' }),
    ]);
    await expect(api.publishLogSource('lsrc_a', '2026-11-11T09:00:00Z', { sleep: noSleep })).rejects.toMatchObject({
      message: 'Conflict: modified',
      code: 'CONFLICT',
      status: 409,
    });
  });

  it('reports an interrupted job as an error', async () => {
    const { api } = client(job(), [
      job({ state: 'interrupted', phase: 'done', error_status: 500, message: 'The API stopped' }),
    ]);
    await expect(api.undeployLogSource('lsrc_a', { sleep: noSleep })).rejects.toMatchObject({
      code: 'DEPLOY_INTERRUPTED',
      status: 500,
    });
  });

  it('deploy-all resolves to the legacy body', async () => {
    const { api } = client(job({ kind: 'deploy_all', log_source_id: null }), [
      job({ kind: 'deploy_all', log_source_id: null, state: 'succeeded', phase: 'done' }),
    ]);
    await expect(api.deployAllLogSources({ sleep: noSleep })).resolves.toEqual({ deployed: true });
  });

  it('passes a synchronous answer through (a server without deploy jobs)', async () => {
    const { api, request } = client(deployed, []);
    await expect(api.deployLogSource('lsrc_a')).resolves.toEqual(deployed);
    expect(request).not.toHaveBeenCalled();
  });
});

describe('labels', () => {
  it('names the final state, and a pending role-split delivery as in progress', () => {
    expect(stateLabel(job({ state: 'succeeded' }))).toBe('Deployed');
    expect(stateLabel(job({ state: 'succeeded', kind: 'publish' }))).toBe('Published');
    expect(stateLabel(job({ state: 'succeeded', kind: 'undeploy' }))).toBe('Undeployed');
    expect(stateLabel(job({ state: 'rolled_back' }))).toBe('Rolled back');
    expect(stateLabel(job({ state: 'interrupted' }))).toBe('Interrupted');
    expect(
      stateLabel(
        job({
          state: 'succeeded',
          result: {
            ...deployed,
            delivery: {
              state: 'pending',
              generation: 7,
              host_count: 2,
              pending_hosts: ['ingest-2'],
              sync_interval_secs: 5,
              status_path: '/api/log-sources/delivery-status?generation=7',
            },
          },
        }),
      ),
    ).toBe('Deploying: not yet confirmed');
  });

  it('maps phases onto the four steps', () => {
    expect(phaseStep('queued')).toBe(-1);
    expect(phaseStep('waiting_for_lock')).toBe(-1);
    expect(phaseStep('validating')).toBe(0);
    expect(phaseStep('validating_config')).toBe(1);
    expect(phaseStep('reloading')).toBe(3);
    expect(phaseStep('activating')).toBe(3);
    expect(phaseStep('rolling_back')).toBe(3);
    expect(phaseStep('done')).toBe(4);
  });
});
