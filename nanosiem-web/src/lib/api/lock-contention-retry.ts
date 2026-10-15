// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-3761: retry reads the API deferred with `503 RESOURCE_LOCK_CONTENTION`.
 *
 * The server answers that code when a request's transaction waited out its
 * lock budget and rolled back (nothing was written), with `Retry-After: 1`.
 * A burst of page loads can hit it together (tenant-a, 10-13: one slow request
 * deferred every other request of the session), so retries back off
 * exponentially with full jitter instead of re-colliding in lockstep.
 *
 * Only safe methods (GET/HEAD) are retried here: a write that failed this way
 * is surfaced to its caller, which owns the decision to resubmit.
 */
export const RESOURCE_LOCK_CONTENTION = 'RESOURCE_LOCK_CONTENTION';

/** Retries after the first attempt (4 attempts in all). */
export const LOCK_CONTENTION_MAX_RETRIES = 3;
const BASE_DELAY_MS = 500;
const MAX_DELAY_MS = 4_000;

export function isLockContention(status: number, code: unknown): boolean {
  // Handlers spell the code in either case (`resource_lock_contention` from
  // the enterprise error mappers); the API contract compares it uppercased.
  return status === 503 && typeof code === 'string' && code.toUpperCase() === RESOURCE_LOCK_CONTENTION;
}

export function isRetryableMethod(method: string | undefined): boolean {
  const verb = (method ?? 'GET').toUpperCase();
  return verb === 'GET' || verb === 'HEAD';
}

/**
 * Delay before retry number `retry` (0-based): the server's `Retry-After`
 * hint plus full jitter over an exponential cap, so concurrent readers of one
 * session spread out instead of colliding again together.
 */
export function lockContentionDelayMs(
  retry: number,
  retryAfterHeader: string | null,
  random: () => number = Math.random,
): number {
  const cap = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** retry);
  const jittered = Math.round(random() * cap);
  const hintSecs = retryAfterHeader ? Number.parseInt(retryAfterHeader, 10) : Number.NaN;
  const floor = Number.isFinite(hintSecs) && hintSecs > 0 ? Math.min(hintSecs * 1_000, MAX_DELAY_MS) : 0;
  return floor + jittered;
}

/** Sleep that rejects with AbortError when `signal` aborts. */
export function abortableDelay(ms: number, signal?: AbortSignal | null): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException('Aborted', 'AbortError'));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException('Aborted', 'AbortError'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * Run `attempt` and retry it while it answers 503 RESOURCE_LOCK_CONTENTION,
 * at most {@link LOCK_CONTENTION_MAX_RETRIES} times. `attempt` returns the
 * raw response; the last one (successful or not) is returned to the caller.
 */
export async function withLockContentionRetry(
  method: string | undefined,
  attempt: () => Promise<Response>,
  signal?: AbortSignal | null,
  wait: (ms: number, signal?: AbortSignal | null) => Promise<void> = abortableDelay,
  random: () => number = Math.random,
): Promise<Response> {
  for (let retry = 0; ; retry++) {
    const response = await attempt();
    if (response.ok || !isRetryableMethod(method) || retry >= LOCK_CONTENTION_MAX_RETRIES || response.status !== 503) {
      return response;
    }
    const code = await response
      .clone()
      .json()
      .then((body: { error?: { code?: unknown } | unknown }) =>
        typeof body?.error === 'object' && body.error !== null ? (body.error as { code?: unknown }).code : body?.error,
      )
      .catch(() => undefined);
    if (!isLockContention(response.status, code)) return response;
    await wait(lockContentionDelayMs(retry, response.headers.get('Retry-After'), random), signal);
  }
}
