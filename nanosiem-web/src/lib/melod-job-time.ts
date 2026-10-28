// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from 'react';

/** Eleven minutes for other wizards, above their ten-minute server ceiling. */
export const DEFAULT_JOB_MAX_WAIT_MS = 11 * 60_000;
/** Parser create/edit run for 25 minutes; the browser allows five more. */
export const PARSER_JOB_SERVER_TIMEOUT_MS = 25 * 60_000;
export const PARSER_JOB_MAX_WAIT_MS = PARSER_JOB_SERVER_TIMEOUT_MS + 5 * 60_000;

export interface StartMelodJobOptions {
  maxWaitMs?: number;
}

export interface PollMelodJobOptions extends StartMelodJobOptions {
  signal?: AbortSignal;
  onProgress?: (message: string | undefined, elapsedMs: number) => void;
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
