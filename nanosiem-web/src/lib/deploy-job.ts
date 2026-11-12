// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5132: log-source deploy, undeploy, publish and deploy-all run as
 * background jobs. The client starts one with `?wait=false` (202 + job), polls
 * `GET /api/log-sources/deploy-jobs/{id}` until it is terminal, and hands the
 * caller the same final result the synchronous call returned. No request is
 * held open for the length of a deploy, so no edge or client timeout can cut
 * one short — and the server finishes or rolls back a deploy whether or not
 * anyone is still polling.
 *
 * Progress is published on a small in-memory bus so any mounted view
 * (LogSourceDetail, the LogSources table) can show the phase of a deploy that
 * another component started.
 */
import type { DeployJob, DeployJobPhase, DeployJobState } from '@/lib/api/types';

export const TERMINAL_STATES: ReadonlySet<DeployJobState> = new Set([
  'succeeded',
  'failed',
  'rolled_back',
  'interrupted',
]);

export function isTerminal(job: Pick<DeployJob, 'state'>): boolean {
  return TERMINAL_STATES.has(job.state);
}

/** Operator-facing label for a phase. */
export function phaseLabel(phase: DeployJobPhase): string {
  switch (phase) {
    case 'queued':
      return 'Queued';
    case 'waiting_for_lock':
      return 'Waiting for another deploy';
    case 'validating':
      return 'Validating';
    case 'rendering':
      return 'Rendering config';
    case 'validating_config':
      return 'Validating config';
    case 'promoting':
      return 'Promoting';
    case 'reloading':
      return 'Reloading Vector';
    case 'activating':
      return 'Activating';
    case 'rolling_back':
      return 'Rolling back';
    case 'done':
      return 'Done';
  }
}

/** Operator-facing label for a final state. */
export function stateLabel(job: Pick<DeployJob, 'state' | 'kind' | 'result'>): string {
  switch (job.state) {
    case 'queued':
      return 'Queued';
    case 'running':
      return 'Running';
    case 'succeeded':
      if (job.result?.delivery?.state === 'pending') return 'Deploying: not yet confirmed';
      if (job.kind === 'undeploy') return 'Undeployed';
      if (job.kind === 'publish') return 'Published';
      return 'Deployed';
    case 'failed':
      return 'Failed';
    case 'rolled_back':
      return 'Rolled back';
    case 'interrupted':
      return 'Interrupted';
  }
}

/** Ordered phases a deploy walks through, for a step indicator. */
export const PHASE_STEPS: readonly DeployJobPhase[] = [
  'validating',
  'rendering',
  'promoting',
  'reloading',
];

/** Index of `phase` in {@link PHASE_STEPS} (queued/waiting = -1, done = length). */
export function phaseStep(phase: DeployJobPhase): number {
  if (phase === 'done') return PHASE_STEPS.length;
  if (phase === 'validating_config') return PHASE_STEPS.indexOf('rendering');
  if (phase === 'rolling_back') return PHASE_STEPS.indexOf('reloading');
  // NAN-5132: the second reload of a two-phase activation.
  if (phase === 'activating') return PHASE_STEPS.indexOf('reloading');
  return PHASE_STEPS.indexOf(phase);
}

// ---------------------------------------------------------------------------
// Progress bus
// ---------------------------------------------------------------------------

type Listener = (job: DeployJob) => void;
const listeners = new Set<Listener>();
const latest = new Map<string, DeployJob>();

/** Key for a job's target: the log source id, or `*` for deploy-all. */
export function jobTarget(job: Pick<DeployJob, 'log_source_id'>): string {
  return job.log_source_id ?? '*';
}

export function publishDeployJob(job: DeployJob): void {
  latest.set(jobTarget(job), job);
  for (const listener of listeners) listener(job);
}

export function subscribeDeployJobs(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** The last job seen for a target (a log source id, or `*`). */
export function latestDeployJob(target: string): DeployJob | undefined {
  return latest.get(target);
}

/** Test hook. */
export function resetDeployJobBus(): void {
  listeners.clear();
  latest.clear();
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

export interface PollOptions {
  /** First poll delay; doubles up to `maxIntervalMs`. */
  intervalMs?: number;
  maxIntervalMs?: number;
  /** Give up after this long (the job keeps running on the server). */
  timeoutMs?: number;
  signal?: AbortSignal;
  sleep?: (ms: number) => Promise<void>;
  /** Every update of the job, including the first and the final one. */
  onProgress?: (job: DeployJob) => void;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** The job could not be followed to the end (poll timeout); it may still finish. */
export class DeployJobPollTimeout extends Error {
  constructor(public job: DeployJob) {
    super(
      `Still ${phaseLabel(job.phase).toLowerCase()} after the wait limit. The deploy keeps running on the server; check this log source again shortly.`,
    );
    this.name = 'DeployJobPollTimeout';
  }
}

/**
 * Poll `fetchJob` until the job is terminal, publishing every update on the
 * progress bus. A transient poll error is retried; three in a row are thrown.
 */
export async function followDeployJob(
  first: DeployJob,
  fetchJob: (id: string) => Promise<DeployJob>,
  options: PollOptions = {},
): Promise<DeployJob> {
  const sleep = options.sleep ?? defaultSleep;
  const maxInterval = options.maxIntervalMs ?? 3_000;
  const deadline = Date.now() + (options.timeoutMs ?? 15 * 60_000);
  let interval = options.intervalMs ?? 750;
  let job = first;
  let failures = 0;
  const report = (update: DeployJob) => {
    publishDeployJob(update);
    options.onProgress?.(update);
  };
  report(job);
  while (!isTerminal(job)) {
    if (options.signal?.aborted) throw new DOMException('Aborted', 'AbortError');
    if (Date.now() > deadline) throw new DeployJobPollTimeout(job);
    await sleep(interval);
    interval = Math.min(maxInterval, Math.round(interval * 1.5));
    try {
      job = await fetchJob(job.id);
      failures = 0;
    } catch (cause) {
      failures += 1;
      if (failures >= 3) throw cause;
      continue;
    }
    report(job);
  }
  return job;
}

/** Elapsed seconds of a job (to now while it runs). */
export function elapsedSeconds(job: Pick<DeployJob, 'created_at' | 'finished_at'>, now = Date.now()): number {
  const start = Date.parse(job.created_at);
  const end = job.finished_at ? Date.parse(job.finished_at) : now;
  if (Number.isNaN(start) || Number.isNaN(end)) return 0;
  return Math.max(0, Math.round((end - start) / 1000));
}
