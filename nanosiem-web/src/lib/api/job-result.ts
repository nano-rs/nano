// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-4753: AI generation endpoints answer with a meloD job (`{ job_id }`)
 * when asked with `Prefer: respond-async`, so a slow model never holds a
 * request past an edge timeout. This resolves either shape to the result: a
 * synchronous body passes through, a job is polled at `/api/melod/jobs/{id}`
 * until it finishes. `onProgress` receives the job's live progress line.
 */
import { safeErrorMessage } from './http-error';

const POLL_MS = 2000;
// Above the server ceiling for generation jobs (MELOD_JOB_TIMEOUT, 300 s).
const MAX_POLLS = 330;

type Fetcher = <R>(path: string) => Promise<R>;

interface JobStart {
  job_id: string;
}

interface JobState<T> {
  status: string;
  result?: T;
  error?: string;
  progress?: string | null;
}

export interface JobResultProgress {
  jobId: string;
  status: string;
  /** Server progress line, when the job has reported one. */
  message?: string;
  elapsedMs: number;
}

export function isJobStart(value: unknown): value is JobStart {
  return typeof value === 'object' && value !== null && typeof (value as JobStart).job_id === 'string';
}

export async function resolveJobResult<T>(
  started: T | JobStart,
  fetchJob: Fetcher,
  options: {
    signal?: AbortSignal;
    failure: string;
    onProgress?: (progress: JobResultProgress) => void;
  },
): Promise<T> {
  if (!isJobStart(started)) return started;
  const begun = Date.now();
  options.onProgress?.({ jobId: started.job_id, status: 'pending', elapsedMs: 0 });
  for (let poll = 0; poll < MAX_POLLS; poll++) {
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
    if (options.signal?.aborted) throw new Error('Job cancelled');
    const job = await fetchJob<JobState<T>>(`/api/melod/jobs/${encodeURIComponent(started.job_id)}`);
    if (job.status === 'completed' && job.result !== undefined) return job.result;
    if (job.status === 'failed' || job.status === 'cancelled') {
      throw new Error(safeErrorMessage(job.error, options.failure));
    }
    options.onProgress?.({
      jobId: started.job_id,
      status: job.status,
      message: job.progress ?? undefined,
      elapsedMs: Date.now() - begun,
    });
  }
  throw new Error('Generation timed out after 11 minutes. Retry in a moment.');
}
