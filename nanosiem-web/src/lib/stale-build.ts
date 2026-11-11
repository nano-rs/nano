// SPDX-License-Identifier: AGPL-3.0-or-later
import { isChunkLoadError } from './reload-route-chunk';

/**
 * NAN-5273: thrown by a context hook (e.g. `useAuth`) called with no provider
 * above it. Inside the app shell that only happens when a lazy page loaded a
 * second copy of the context module (a dev server restart under an open tab),
 * so the route boundary treats it as a stale build.
 */
export class ProviderMissingError extends Error {
  constructor(hook: string, provider: string) {
    super(`${hook} must be used within an ${provider}`);
    this.name = 'ProviderMissingError';
  }
}

/** Matches provider guards that still throw a plain Error with the usual wording. */
const PROVIDER_MISSING = /\bmust be used within (?:an? )?[A-Za-z]*Provider\b/;

/** Errors that a fresh document load is expected to fix. */
export function isStaleBuildError(error: unknown): boolean {
  if (error instanceof ProviderMissingError) return true;
  if (error instanceof Error && error.name === 'ProviderMissingError') return true;
  if (isChunkLoadError(error)) return true;
  const message = error instanceof Error ? error.message : String(error);
  return PROVIDER_MISSING.test(message);
}

export const STALE_BUILD_RELOAD_KEY = 'nano.stale-build-reload';
/** A second stale-build error inside this window shows the panel instead of reloading. */
export const STALE_BUILD_RELOAD_WINDOW_MS = 5 * 60_000;

interface ReloadDeps {
  storage?: Pick<Storage, 'getItem' | 'setItem'>;
  now?: () => number;
  reload?: () => void;
}

/**
 * Reload the document once per window. Returns true when a reload was started.
 * Without working sessionStorage there is no loop guard, so it never reloads.
 */
export function tryStaleBuildReload(deps: ReloadDeps = {}): boolean {
  const now = deps.now ?? Date.now;
  try {
    const storage = deps.storage ?? window.sessionStorage;
    const previous = Number(storage.getItem(STALE_BUILD_RELOAD_KEY));
    const at = now();
    if (previous && at - previous >= 0 && at - previous < STALE_BUILD_RELOAD_WINDOW_MS) return false;
    storage.setItem(STALE_BUILD_RELOAD_KEY, String(at));
    if (Number(storage.getItem(STALE_BUILD_RELOAD_KEY)) !== at) return false;
  } catch {
    return false;
  }
  (deps.reload ?? (() => window.location.reload()))();
  return true;
}
