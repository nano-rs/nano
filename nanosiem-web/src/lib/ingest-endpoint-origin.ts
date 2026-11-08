// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-4945: an ingest origin that is a dev server cannot receive events.
 *
 * The Vite dev server (5173, `vite preview` 4173) proxies `/api` only: it answers
 * `<base>/ingest` and `<base>/otlp/v1/*` with an empty 404. When the API has no
 * NANO_INGEST_PUBLIC_BASE_URL it builds the endpoint from BASE_URL or the
 * browser's address, which on a local stack is exactly that dev server, so the
 * endpoint card warns instead of offering URLs that silently fail.
 */
export const INGEST_BASE_URL_ENV = 'NANO_INGEST_PUBLIC_BASE_URL';

const DEV_SERVER_PORTS = new Set(['5173', '4173']);

export function isDevServerOrigin(baseUrl: string): boolean {
  try {
    return DEV_SERVER_PORTS.has(new URL(baseUrl).port);
  } catch {
    return false;
  }
}
