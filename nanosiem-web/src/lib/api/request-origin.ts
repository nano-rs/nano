// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5571: mark REST calls a pivt action makes, so the audit log reads
// "<user> did X (via pivt)". The server records `X-Nano-Origin` (allowlisted)
// in the audit event's details; the actor is still the user and the header
// grants nothing.
//
// `withRequestOrigin('pivt', api)` returns a proxy of the client. While a
// proxied method runs synchronously, the origin is pending; `request()` takes
// it when it builds its headers, which happens before its first await. JS is
// single-threaded, so a concurrent page request can never pick it up. A
// method that awaits something before issuing its request is not marked
// (its call still succeeds and is audited as the user, just without "via").
// Only top-level ApiClient methods are proxied (`pivtApi.createDetection`),
// not sub-client getters, and a replay after a 401 refresh is not marked.
// The header is client-reported: audit readers treat it as "the web client
// says this came from pivt", never as authority.

export type RequestOrigin = 'pivt';

export const ORIGIN_HEADER = 'X-Nano-Origin';

let pending: RequestOrigin | null = null;

/** Called by the API client while building a request's headers. */
export function takeRequestOrigin(): RequestOrigin | null {
  const o = pending;
  pending = null;
  return o;
}

export function withRequestOrigin<T extends object>(origin: RequestOrigin, client: T): T {
  return new Proxy(client, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        const previous = pending;
        pending = origin;
        try {
          return (value as (...a: unknown[]) => unknown).apply(target, args);
        } finally {
          pending = previous;
        }
      };
    },
  });
}
