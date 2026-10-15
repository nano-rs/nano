// SPDX-License-Identifier: AGPL-3.0-or-later

import type { SearchJobProgress } from './api/types';

/** NAN-3644: whether a stream `progress` event reports a lean-cell cold read. */
export function isColdScanProgress(progress: SearchJobProgress | null | undefined): boolean {
  return progress?.phase === 'cold_scan';
}

function gigabytes(bytes: number): string {
  const gb = bytes / 1_000_000_000;
  return gb >= 10 ? gb.toFixed(0) : gb.toFixed(1);
}

/**
 * NAN-3644: the status line for a cold read. A read the reader queues behind
 * another heavy cold read says so; one that is fetching shows bytes read of
 * the bytes its admitted leases will read.
 */
export function coldScanLabel(progress: SearchJobProgress): string {
  const read = progress.cold_bytes_read ?? 0;
  const total = progress.cold_bytes_total ?? 0;
  if (progress.queued && read === 0) {
    return 'Queued behind another cold-data scan…';
  }
  if (total <= 0) {
    return 'Scanning cold data…';
  }
  return `Scanning cold data… ${gigabytes(Math.min(read, total))} of ${gigabytes(total)} GB`;
}

/**
 * NAN-3883: whether a job's progress carries a real measure (rows of a known
 * total, cold bytes of a known total, or a percentage). A durable lean-cell
 * job reports only its phase until it publishes, so a 0% bar would read as a
 * hung search for minutes.
 */
export function hasMeasuredProgress(progress: SearchJobProgress | null | undefined): boolean {
  if (!progress) return false;
  if (progress.rows_total > 0 || progress.percent > 0) return true;
  return isColdScanProgress(progress) && (progress.cold_bytes_total ?? 0) > 0;
}

/** NAN-3883: the status line for a background job without a measure. */
export function backgroundJobPhaseLabel(progress: SearchJobProgress | null | undefined): string {
  const retry = progress?.attempt && progress.attempt > 1 ? ` (attempt ${progress.attempt})` : '';
  // The runner re-sends an attempt after a cold-data fetch timed out; what
  // it already fetched stays cached, so the retry resumes warm.
  const resend = /^retrying_(\d+)$/.exec(progress?.phase ?? '');
  if (resend) return `Cold data was slow to load; retrying (${resend[1]})…`;
  switch (progress?.phase) {
    case 'publishing_result':
      return 'Writing results…';
    case 'cell_dispatch':
    case 'scanning':
      return `Scanning in the background${retry}…`;
    default:
      return `Running in the background${retry}…`;
  }
}

/** NAN-3883: elapsed wall time of a job, e.g. `47s` or `2m 05s`. */
export function formatJobElapsed(elapsedMs: number): string {
  const total = Math.max(0, Math.floor(elapsedMs / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  if (minutes === 0) return `${seconds}s`;
  const hours = Math.floor(minutes / 60);
  if (hours === 0) return `${minutes}m ${String(seconds).padStart(2, '0')}s`;
  return `${hours}h ${String(minutes % 60).padStart(2, '0')}m`;
}
