// SPDX-License-Identifier: AGPL-3.0-or-later

// Wall-clock limits for polled AI jobs, shared by the enterprise poller and
// the open-edition stub so core pages (Add data, parser editor) compile in
// both editions (NAN-4778, ported for NAN-4912 P3).

import { useEffect, useState } from 'react';

/** Other wizards: a minute above their five-minute server ceiling. */
export const DEFAULT_JOB_MAX_WAIT_MS = 6 * 60_000;
/** Parser create/edit jobs run up to 25 minutes on the server (NAN-4778). */
export const PARSER_JOB_SERVER_TIMEOUT_MS = 25 * 60_000;
/** The browser waits five minutes past the server ceiling. */
export const PARSER_JOB_MAX_WAIT_MS = PARSER_JOB_SERVER_TIMEOUT_MS + 5 * 60_000;

export interface StartMelodJobOptions {
  /** Absolute wall-clock limit for the whole job, polling included. */
  maxWaitMs?: number;
}

export interface PollMelodJobOptions extends StartMelodJobOptions {
  signal?: AbortSignal;
  onProgress?: (message: string | undefined, elapsedMs: number) => void;
  /** Called once the server has accepted the job. */
  onJobId?: (jobId: string) => void;
}

export function jobTimeoutMessage(maxWaitMs: number): string {
  const minutes = Math.ceil(maxWaitMs / 60_000);
  return `Job timed out after ${minutes} minute${minutes === 1 ? '' : 's'}`;
}

/** Elapsed time as "45s" / "3m 12s", for job liveness lines. */
export function formatElapsed(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(total / 60);
  const s = total % 60;
  return m > 0 ? `${m}m ${s.toString().padStart(2, '0')}s` : `${s}s`;
}

/** Milliseconds since `active` became true; ticks every second while active. */
export function useElapsedWhile(active: boolean): number {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (!active) {
      setElapsed(0);
      return;
    }
    const started = Date.now();
    setElapsed(0);
    const timer = setInterval(() => setElapsed(Date.now() - started), 1000);
    return () => clearInterval(timer);
  }, [active]);
  return elapsed;
}
