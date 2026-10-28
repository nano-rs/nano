// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-4753: AI generation endpoints answer with a meloD job (`{ job_id }`)
 * so a slow model never holds a request past the 100 s edge timeout. This
 * resolves either shape to the result: a synchronous body passes through, a
 * job is polled at `/api/melod/jobs/{id}` until it finishes.
 */
import { safeErrorMessage } from './http-error';

const POLL_MS = 2000;
// Above the server ceiling for generation wizards (600 s).
const MAX_POLLS = 330;

type Fetcher = <R>(path: string) => Promise<R>;

interface JobStart {
  job_id: string;
}

interface JobState<T> {
  status: string;
  result?: T;
  error?: string;
}

function isJobStart(value: unknown): value is JobStart {
  return typeof value === 'object' && value !== null && typeof (value as JobStart).job_id === 'string';
}

export async function resolveJobResult<T>(
  started: T | JobStart,
  fetchJob: Fetcher,
  options: { signal?: AbortSignal; failure: string },
): Promise<T> {
  if (!isJobStart(started)) return started;
  for (let poll = 0; poll < MAX_POLLS; poll++) {
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
    if (options.signal?.aborted) throw new Error('Job cancelled');
    const job = await fetchJob<JobState<T>>(`/api/melod/jobs/${encodeURIComponent(started.job_id)}`);
    if (job.status === 'completed' && job.result !== undefined) return job.result;
    if (job.status === 'failed' || job.status === 'cancelled') {
      throw new Error(safeErrorMessage(job.error, options.failure));
    }
  }
  throw new Error('Generation timed out after 11 minutes. Retry in a moment.');
}
