// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Run parser tests with bounded concurrency, retrying a 429 after the server's
 * `Retry-After` (security review 2026-11-08). The API admits a bounded number
 * of concurrent parser tests per user; a refusal is immediate, so the client
 * waits and retries rather than failing the event.
 */

export const PARSER_TEST_CONCURRENCY = 4;
const MAX_RETRIES = 5;
const DEFAULT_RETRY_AFTER_S = 1;
const MAX_RETRY_AFTER_S = 10;

/** Seconds to wait before retrying `error`, or undefined if it is not a 429. */
export function retryAfterSeconds(error: unknown): number | undefined {
  if (!error || typeof error !== 'object') return undefined;
  const { status, retryAfter } = error as { status?: unknown; retryAfter?: unknown };
  if (status !== 429) return undefined;
  const seconds =
    typeof retryAfter === 'number' && Number.isFinite(retryAfter) && retryAfter >= 0
      ? retryAfter
      : DEFAULT_RETRY_AFTER_S;
  return Math.min(seconds, MAX_RETRY_AFTER_S);
}

const realSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** Map `items` through `run`, at most `limit` in flight, in input order. */
export async function runParserTests<T, R>(
  items: readonly T[],
  run: (item: T) => Promise<R>,
  options: { limit?: number; sleep?: (ms: number) => Promise<void> } = {},
): Promise<R[]> {
  const limit = Math.max(1, options.limit ?? PARSER_TEST_CONCURRENCY);
  const sleep = options.sleep ?? realSleep;
  const results: R[] = new Array(items.length);
  let next = 0;
  const attempt = async (item: T): Promise<R> => {
    for (let tries = 0; ; tries++) {
      try {
        return await run(item);
      } catch (error) {
        const wait = retryAfterSeconds(error);
        if (wait === undefined || tries >= MAX_RETRIES) throw error;
        await sleep(wait * 1000);
      }
    }
  };
  const worker = async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await attempt(items[index]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
