// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-4915: client-side rules for durable background search jobs. Pure so the
 * contract is unit-testable (`npm run test:search-job`).
 */

/** Durable background jobs carry the `sjob_` typeid prefix; legacy jobs are bare UUIDs. */
export function isDurableJobId(jobId: string): boolean {
  return jobId.startsWith('sjob_');
}

/**
 * Polling cadence for an attached job. Durable jobs survive restarts and are
 * bounded server-side by the job time limit, so the page never gives up on
 * them; legacy in-memory jobs keep the old 5-minute cutoff.
 */
export function jobPollPolicy(jobId: string): { intervalMs: number; maxPolls: number } {
  return isDurableJobId(jobId)
    ? { intervalMs: 2000, maxPolls: Number.POSITIVE_INFINITY }
    : { intervalMs: 1000, maxPolls: 300 };
}

/** Error code for a failed job: parse errors first, then the server's typed kind. */
export function jobFailureCode(errorMessage: string, errorKind?: string | null): string {
  if (/^(Parse error|Query parse error|Unexpected|Expected)/.test(errorMessage)) return 'PARSE_ERROR';
  return errorKind ? `JOB_${errorKind.toUpperCase()}` : 'JOB_FAILED';
}

/**
 * Next continuation page of a completed job, or null when the stored rows are
 * exhausted. `rowCount` is what the job stored — never the (possibly larger)
 * total match count of a truncated job — so paging stops at the stored end
 * instead of requesting pages that do not exist.
 */
export function nextContinuationPage(
  loaded: number,
  rowCount: number,
  pageSize: number,
): { offset: number; limit: number } | null {
  if (pageSize <= 0 || loaded >= rowCount) return null;
  return { offset: loaded, limit: Math.min(pageSize, rowCount - loaded) };
}

/**
 * Count the paginator may offer for a completed durable job (Codex P2-7). A
 * truncated job stored fewer rows than matched; offering pages past the stored
 * rows would request ranges that do not exist. The match count is shown
 * separately.
 */
export function pageableRowCount(totalCount: number, rowCount: number, truncated: boolean): number {
  return truncated ? Math.min(totalCount, rowCount) : totalCount;
}

/** Whether a table page starting at `offset` exists in the job's stored rows. */
export function isPageInStoredRange(offset: number, rowCount: number): boolean {
  return offset === 0 || offset < rowCount;
}
