// SPDX-License-Identifier: AGPL-3.0-or-later
import { readSearchFragment } from './search-fragment';

/** Only stale/network chunk failures warrant a document reload. */
export function reloadRouteChunk(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  if (!/ChunkLoadError|Loading (?:chunk|CSS chunk)|Failed to fetch dynamically imported module|Importing a module script failed|error loading dynamically imported module/i.test(message)) {
    throw error;
  }
  const { pathname, search, hash } = window.location;
  // A lazy Search chunk can fail before Search mounts and migrates old links.
  // Never replay a query-bearing document URL through Cloudflare on recovery.
  if (/\/search\/?$/.test(pathname) && search) {
    const params = readSearchFragment(search, hash).toString();
    window.history.replaceState(window.history.state, '', `${pathname}#${params}`);
  }
  // Stop persistent network failures from repeatedly reloading the document.
  const key = `nano.chunk-reload:${pathname}`;
  try {
    const previous = Number(window.sessionStorage.getItem(key));
    if (previous && Date.now() - previous < 60_000) throw error;
    window.sessionStorage.setItem(key, String(Date.now()));
  } catch (storageError) {
    // Storage denial cannot provide a safe retry guard.
    throw storageError;
  }
  window.location.reload();
}
