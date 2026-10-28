// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for use-melod-job. The meloD AI agent surface is
// enterprise-only; in open builds the job-poll path resolves to no-op
// implementations. Open consumers of `useMelodJob` (PanelEditor, the AI
// detection editor panels, etc.) are tracked for capability gating in
// Task #15 — until then the stub keeps the call sites compilable and
// renders the buttons as inert.

import type { MelodJobStartResponse } from '@/lib/api/types';
import type { PollMelodJobOptions, StartMelodJobOptions } from '@/lib/melod-job-time';

export {
  DEFAULT_JOB_MAX_WAIT_MS,
  PARSER_JOB_SERVER_TIMEOUT_MS,
  PARSER_JOB_MAX_WAIT_MS,
  formatElapsed,
  jobTimeoutMessage,
  useElapsedWhile,
} from '@/lib/melod-job-time';

export interface UseMelodJobReturn<TResult> {
  isRunning: boolean;
  loading: boolean;
  progress: string | null;
  status: string | null;
  error: string | null;
  result: TResult | null;
  start: (fn: () => Promise<MelodJobStartResponse>, options?: StartMelodJobOptions) => Promise<TResult>;
  cancel: () => void;
  reset: () => void;
}

export async function pollMelodJob<TResult>(
  _fn: () => Promise<MelodJobStartResponse | TResult>,
  _opts?: PollMelodJobOptions,
): Promise<TResult> {
  void _fn;
  void _opts;
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
    '[open-core] useMelodJob.start() called in open-core build. ' +
      'Gate this caller with useCapabilities().capabilities.melod.',
  );
  return Promise.reject(
    new Error('meloD agents are unavailable in open-core builds.'),
  );
}

const STUB_RETURN = {
  isRunning: false,
  progress: null,
  loading: false,
  status: null,
  error: null,
  result: null,
  start: rejectedStart,
  cancel: () => {},
  reset: () => {},
};

export function useMelodJob<TResult>(): UseMelodJobReturn<TResult> {
  return STUB_RETURN as unknown as UseMelodJobReturn<TResult>;
}
