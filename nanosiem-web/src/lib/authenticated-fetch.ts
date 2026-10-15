// SPDX-License-Identifier: AGPL-3.0-or-later
import { getAccessToken } from './auth-token.ts';
import { allowsAnonymousRequest, requestCredentials } from './request-credentials.ts';
import { sessionCredentials } from './session-credentials.ts';

/** Wait for refresh before sending, and replay a rejected bearer once. The
 * caller's tenant authority check runs after every asynchronous boundary. */
export async function authenticatedFetch(
  endpoint: string,
  url: string,
  options: RequestInit = {},
  assertCurrent: () => void = () => {},
  sharedSession = false,
): Promise<Response> {
  const anonymous = allowsAnonymousRequest(endpoint);
  const token = anonymous ? getAccessToken() : await sessionCredentials.credential();
  const send = (credential: string | null) => {
    assertCurrent();
    options.signal?.throwIfAborted();
    const headers = new Headers(options.headers);
    if (credential) headers.set('Authorization', `Bearer ${credential}`);
    return fetch(url, {
      ...options,
      headers,
      credentials: requestCredentials(endpoint, headers, sharedSession),
    });
  };
  let response = await send(token);
  assertCurrent();
  if (response.status === 401 && !anonymous) {
    await response.body?.cancel();
    const fresh = await sessionCredentials.credential(token ?? undefined);
    response = await send(fresh);
    assertCurrent();
    if (response.status === 401) {
      await response.body?.cancel();
      throw sessionCredentials.expire();
    }
  }
  return response;
}
