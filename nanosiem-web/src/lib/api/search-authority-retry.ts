// SPDX-License-Identifier: AGPL-3.0-or-later
export const AUTHORITY_UNAVAILABLE = 'search_authority_unavailable';
export const AUTHORITY_NOTICE = 'Search authority is temporarily unavailable; retrying shortly';

export interface AuthorityRetryOptions {
  isCancelled?: () => boolean;
  onUnavailable?: () => void;
  onRecovered?: () => void;
}

export function isSearchAuthorityUnavailable(error: unknown): boolean {
  const value = error as { status?: number; code?: string } | null;
  return value?.status === 503 && value.code === AUTHORITY_UNAVAILABLE;
}

/** Retry only authoritative 503s, never revocations or ambiguous POST failures. */
export async function retrySearchAuthority<T>(
  operation: () => Promise<T>,
  options: AuthorityRetryOptions = {},
  wait: (ms: number) => Promise<void> = ms => new Promise(resolve => setTimeout(resolve, ms)),
): Promise<T> {
  let failures = 0;
  for (;;) {
    if (options.isCancelled?.()) throw new DOMException('Search cancelled', 'AbortError');
    try {
      const result = await operation();
      if (failures && !options.isCancelled?.()) options.onRecovered?.();
      return result;
    } catch (error) {
      if (options.isCancelled?.()) throw new DOMException('Search cancelled', 'AbortError');
      if (!isSearchAuthorityUnavailable(error)) throw error;
      options.onUnavailable?.();
      // Callers with a lifecycle predicate keep retrying until stopped. Other
      // consumers have a bounded retry window.
      if (!options.isCancelled && failures >= 5) throw error;
      await wait(Math.min(2_000 * 2 ** failures++, 30_000));
    }
  }
}
