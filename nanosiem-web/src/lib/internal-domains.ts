// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3226: internal DNS suffixes.
 *
 * A name equal to or under an internal suffix is an internal host, never an
 * internet domain: `prod` matches `prod` and `db1.prod`, but NOT `myprod.com`
 * or `db1.myprod` (label boundary). The list from
 * `/api/settings/internal-domains` is unioned with the built-in suffixes.
 *
 * Pure helpers only — the React Query hook lives in
 * `@/hooks/use-internal-domains`.
 */

/** Suffixes that are always internal. Mirrors the backend built-in list. */
export const BUILTIN_INTERNAL_SUFFIXES: readonly string[] = [
  'local',
  'corp',
  'internal',
  'lan',
  'home',
  'localdomain',
  'intranet',
  'private',
  'arpa',
];

/** Max total length of a DNS name. */
const MAX_NAME_LENGTH = 253;
const LABEL_RE = /^[a-z0-9_-]{1,63}$/;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Normalize a suffix the same way the server does: trim, lowercase, strip a
 * leading `*.` or `.` and a trailing dot. Returns null when the result is not
 * a valid DNS suffix (empty label, bad characters, label over 63 chars,
 * leading/trailing hyphen, an IP address, or over 253 chars).
 */
export function normalizeSuffix(raw: string): string | null {
  let s = raw.trim().toLowerCase();
  if ([...s].some((c) => c.charCodeAt(0) > 127)) s = normalizeName(s.replace(/^\*\./, '').replace(/^\./, ''));
  if (s.startsWith('*.')) s = s.slice(2);
  else if (s.startsWith('.')) s = s.slice(1);
  if (s.endsWith('.')) s = s.slice(0, -1);
  if (!s || s.length > MAX_NAME_LENGTH) return null;
  if (IPV4_RE.test(s)) return null;
  const labels = s.split('.');
  for (const label of labels) {
    if (!LABEL_RE.test(label)) return null;
    if (label.startsWith('-') || label.endsWith('-')) return null;
  }
  return s;
}

/**
 * Canonical form for matching: trim, drop a trailing dot, lowercase and map
 * to IDNA A-labels (`DB.Bücher.CORP.` → `db.xn--bcher-kva.corp`), the same
 * form the server matches on. Falls back to the lowercased input when the
 * browser cannot parse it as a host.
 */
function normalizeName(name: string): string {
  let n = name.trim();
  if (n.endsWith('.')) n = n.slice(0, -1);
  if (!n) return '';
  try {
    return new URL(`http://${n}/`).hostname.replace(/\.$/, '');
  } catch {
    return n.toLowerCase();
  }
}

/**
 * Whether `name` is equal to or under any internal suffix (built-ins plus
 * `suffixes`). Case-insensitive, trailing dot ignored, label boundary.
 */
export function isInternalName(name: string, suffixes: readonly string[] = []): boolean {
  const n = normalizeName(name);
  if (!n) return false;
  const check = (suffix: string) => n === suffix || n.endsWith(`.${suffix}`);
  for (const s of BUILTIN_INTERNAL_SUFFIXES) if (check(s)) return true;
  for (const raw of suffixes) {
    const s = normalizeName(raw);
    if (s && check(s)) return true;
  }
  return false;
}

/** Built-ins unioned with the saved suffixes, de-duplicated, built-ins first. */
export function effectiveInternalSuffixes(tenant: readonly string[] = []): string[] {
  const out = new Set<string>(BUILTIN_INTERNAL_SUFFIXES);
  for (const raw of tenant) {
    const s = normalizeSuffix(raw);
    if (s) out.add(s);
  }
  return [...out];
}
