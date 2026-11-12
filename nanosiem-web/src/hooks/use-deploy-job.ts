// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5132: the deploy job currently relevant to a log source.
 *
 * Follows the progress bus (jobs this tab started), and on mount asks the
 * server for the source's newest job so a deploy that is still running after
 * a page reload — or one another user or tab started — is shown and followed
 * too. A finished job stays visible: success for `SUCCESS_LINGER_MS`, a
 * failure, rollback or interruption until the next job replaces it.
 */
import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import type { DeployJob } from '@/lib/api/types';
import {
  followDeployJob,
  isTerminal,
  jobTarget,
  latestDeployJob,
  subscribeDeployJobs,
} from '@/lib/deploy-job';

export const SUCCESS_LINGER_MS = 15_000;

function relevant(job: DeployJob, logSourceId: string): boolean {
  const target = jobTarget(job);
  return target === logSourceId || target === '*';
}

/** Newer of two jobs (by creation time). */
function newer(a: DeployJob | undefined, b: DeployJob | undefined): DeployJob | undefined {
  if (!a) return b;
  if (!b) return a;
  return Date.parse(b.created_at) >= Date.parse(a.created_at) ? b : a;
}

export interface UseDeployJobOptions {
  /** Ask the server for the newest job on mount (default true). Off for table rows. */
  fetchOnMount?: boolean;
}

export function useDeployJob(
  logSourceId: string | undefined,
  { fetchOnMount = true }: UseDeployJobOptions = {},
): DeployJob | undefined {
  const [job, setJob] = useState<DeployJob | undefined>(() =>
    logSourceId ? newer(latestDeployJob(logSourceId), latestDeployJob('*')) : undefined,
  );

  // Jobs this tab is following.
  useEffect(() => {
    if (!logSourceId) return undefined;
    return subscribeDeployJobs((update) => {
      if (!relevant(update, logSourceId)) return;
      setJob((current) => (current && current.id !== update.id ? newer(current, update) : update));
    });
  }, [logSourceId]);

  // A job already on the server (page reload, another tab or user).
  useEffect(() => {
    if (!logSourceId || !fetchOnMount) return undefined;
    const controller = new AbortController();
    let cancelled = false;
    api
      .listLogSourceDeployJobs(logSourceId, 1)
      .then(async ([newest]) => {
        if (cancelled || !newest) return;
        setJob((current) => newer(current, newest));
        if (!isTerminal(newest)) {
          await followDeployJob(newest, (id) => api.getLogSourceDeployJob(id), {
            signal: controller.signal,
          });
        }
      })
      .catch(() => {
        /* best effort: the progress strip is informational */
      });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [logSourceId, fetchOnMount]);

  // Let a success fade; keep failures until something replaces them.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!job || job.state !== 'succeeded' || !job.finished_at) return undefined;
    const remaining = Date.parse(job.finished_at) + SUCCESS_LINGER_MS - Date.now();
    if (remaining <= 0) return undefined;
    const timer = setTimeout(() => setNow(Date.now()), remaining + 50);
    return () => clearTimeout(timer);
  }, [job]);

  if (job?.state === 'succeeded' && job.finished_at) {
    // A pending role-split delivery is "in progress", not done: keep it.
    const pending = job.result?.delivery?.state === 'pending';
    if (!pending && Date.parse(job.finished_at) + SUCCESS_LINGER_MS < Math.max(now, Date.now())) {
      return undefined;
    }
  }
  return job;
}
