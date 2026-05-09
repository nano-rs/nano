// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Secure password generation for admin-issued credentials (invite + edit
 * flows). Cryptographically random via `crypto.getRandomValues`; falls back
 * to `Math.random` only when the Web Crypto API is unavailable (test
 * harnesses, SSR — should never hit in a real browser).
 *
 * Charset excludes ambiguous glyphs (`0/O`, `1/l/I`) so admins can read the
 * password aloud or paste-and-confirm without confusion.
 */

const PASSWORD_CHARSET = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%';

export function generateSecurePassword(length = 16): string {
  const out: string[] = [];

  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    for (let i = 0; i < length; i++) {
      out.push(PASSWORD_CHARSET[bytes[i] % PASSWORD_CHARSET.length]);
    }
  } else {
    for (let i = 0; i < length; i++) {
      out.push(PASSWORD_CHARSET[Math.floor(Math.random() * PASSWORD_CHARSET.length)]);
    }
  }

  return out.join('');
}
