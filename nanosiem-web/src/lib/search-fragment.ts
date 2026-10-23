// SPDX-License-Identifier: AGPL-3.0-or-later
/** Search state is browser-only: fragments never reach the edge or origin. */
export function readSearchFragment(search: string, hash: string): URLSearchParams {
  const params = new URLSearchParams(search);
  const fragment = new URLSearchParams(hash.includes('=') ? hash.replace(/^#/, '') : '');
  for (const key of new Set(fragment.keys())) {
    params.delete(key);
    for (const value of fragment.getAll(key)) params.append(key, value);
  }
  return params;
}
