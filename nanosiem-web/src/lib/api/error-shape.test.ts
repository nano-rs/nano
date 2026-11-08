// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4941: the client keeps the server's message whichever error shape a
 * handler answers with. The credentials 409 answers
 * `{"error":"credential_in_use","message":"…"}`; before this the toast read
 * "Request failed" and lost which source still holds the credential.
 */
import { afterEach, expect, it, vi } from 'vitest';
import { api, ApiClientError } from '@/lib/api';
import { setAccessToken } from '@/lib/auth-token';

afterEach(() => vi.restoreAllMocks());

async function failWith(body: unknown, status: number): Promise<ApiClientError> {
  setAccessToken('t', 900);
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }));
  try {
    await api.deleteCredential('cred_1');
  } catch (e) {
    return e as ApiClientError;
  }
  throw new Error('expected a failure');
}

it('reads the flat {error: code, message} shape', async () => {
  const err = await failWith({ error: 'credential_in_use', message: 'Credential is in use by source configuration "x"' }, 409);
  expect(err).toBeInstanceOf(ApiClientError);
  expect(err.message).toBe('Credential is in use by source configuration "x"');
  expect(err.code).toBe('credential_in_use');
  expect(err.status).toBe(409);
});

it('still reads the nested {error: {code, message}} shape', async () => {
  const err = await failWith({ error: { code: 'NOT_FOUND', message: 'Credential not found' } }, 404);
  expect(err.message).toBe('Credential not found');
  expect(err.code).toBe('NOT_FOUND');
  expect(err.status).toBe(404);
});
