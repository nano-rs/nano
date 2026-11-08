// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for use-melod-job. The meloD AI agent surface is
// enterprise-only; in open builds the job-poll path resolves to no-op
// implementations. Open consumers of `useMelodJob` (PanelEditor, the AI
// detection editor panels, etc.) are tracked for capability gating in
// Task #15 — until then the stub keeps the call sites compilable and
// renders the buttons as inert.

// Shared with the enterprise poller: core parser pages import these.
export {
  DEFAULT_JOB_MAX_WAIT_MS,
  PARSER_JOB_SERVER_TIMEOUT_MS,
  PARSER_JOB_MAX_WAIT_MS,
  formatElapsed,
  jobTimeoutMessage,
  useElapsedWhile,
} from '@/lib/melod-job-time';
export type { PollMelodJobOptions, StartMelodJobOptions } from '@/lib/melod-job-time';

export const JOB_CANCELLED_MESSAGE = 'Job cancelled';

// Same shape as src/enterprise/hooks/use-melod-job.ts so core callers
// type-check against the stub exactly as they do against the real hook.
export interface UseMelodJobReturn<TResult> {
  start: (
    fn: () => Promise<import('@/lib/api').MelodJobStartResponse>,
    options?: import('@/lib/melod-job-time').StartMelodJobOptions,
  ) => Promise<TResult>;
  /** Stop polling and cancel the job on the server (no-op here). */
  cancel: () => void;
  result: TResult | null;
  error: string | null;
  loading: boolean;
  progress: string | null;
  reset: () => void;
}

export async function pollMelodJob<TResult>(
  _fn: () => Promise<unknown>,
  _opts?: import('@/lib/melod-job-time').PollMelodJobOptions,
): Promise<TResult> {
  throw new Error(
    'pollMelodJob is unavailable in open-core builds. Gate callers with ' +
      'useCapabilities().capabilities.melod before invoking.',
  );
}

// `start()` returns a rejected Promise rather than throwing synchronously
// so consumers' existing `await + try/catch` paths handle it identically
// to a backend 404 (which is what they hit today before this lift). The
// console.warn surfaces the missed gate during development without taking
// down the React tree. Gate-the-caller cleanup is in Task #15.
function rejectedStart() {
  console.warn(
    '[NAN-745] useMelodJob.start() called in open-core build. ' +
      'Gate this caller with useCapabilities().capabilities.melod.',
  );
  return Promise.reject(
    new Error('meloD agents are unavailable in open-core builds.'),
  );
}

const STUB_RETURN: UseMelodJobReturn<never> = {
  start: rejectedStart,
  cancel: () => {},
  result: null,
  error: null,
  loading: false,
  progress: null,
  reset: () => {},
};

export function useMelodJob<TResult>(): UseMelodJobReturn<TResult> {
  return STUB_RETURN as unknown as UseMelodJobReturn<TResult>;
}
