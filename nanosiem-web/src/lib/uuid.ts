/**
 * Generate a v4 UUID that works in non-secure contexts.
 *
 * `crypto.randomUUID()` is only defined in a secure context (HTTPS or
 * localhost). Open-core installs are served over plain `http://<ip>` by default,
 * where it is `undefined` and throws "crypto.randomUUID is not a function"
 * (NAN-1235). `crypto.getRandomValues` IS available over plain HTTP, so we
 * build the UUID from it and only fall back to Math.random if crypto is absent
 * entirely.
 */
export function safeRandomUUID(): string {
  const c = typeof crypto !== 'undefined' ? crypto : undefined;

  if (c && typeof c.randomUUID === 'function') {
    return c.randomUUID();
  }

  if (c && typeof c.getRandomValues === 'function') {
    const b = c.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 10
    const hex = Array.from(b, (x) => x.toString(16).padStart(2, '0'));
    return (
      `${hex[0]}${hex[1]}${hex[2]}${hex[3]}-${hex[4]}${hex[5]}-` +
      `${hex[6]}${hex[7]}-${hex[8]}${hex[9]}-` +
      `${hex[10]}${hex[11]}${hex[12]}${hex[13]}${hex[14]}${hex[15]}`
    );
  }

  // Last-resort fallback (no Web Crypto at all) — not cryptographically strong,
  // but these IDs are only used for request tracking/cancellation.
  return `${Date.now().toString(16)}-${Math.random().toString(16).slice(2, 10)}-${Math.random()
    .toString(16)
    .slice(2, 10)}`;
}
