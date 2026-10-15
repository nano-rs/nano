// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3226: internal DNS suffixes.
 *
 * A name equal to or under an internal suffix is an internal host, never an
 * internet domain: `prod` matches `prod` and `db1.prod`, but NOT `myprod.com`
 * or `db1.myprod` (label boundary). The tenant list from
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

/** Lowercase, trim and drop a trailing dot (`DB1.PROD.` → `db1.prod`). */
function normalizeName(name: string): string {
  let n = name.trim().toLowerCase();
  if (n.endsWith('.')) n = n.slice(0, -1);
  return n;
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

/** Built-ins unioned with tenant suffixes, de-duplicated, built-ins first. */
export function effectiveInternalSuffixes(tenant: readonly string[] = []): string[] {
  const out = new Set<string>(BUILTIN_INTERNAL_SUFFIXES);
  for (const raw of tenant) {
    const s = normalizeSuffix(raw);
    if (s) out.add(s);
  }
  return [...out];
}

/**
 * NAN-3230: high-volume public TLDs the server refuses outright (mirror of
 * `REFUSED_PUBLIC_TLDS` in `nanosiem-core/src/internal_domains.rs`). Every
 * name under one of these would lose threat-intel enrichment and domain
 * rarity, attacker-registered ones included.
 */
export const REFUSED_PUBLIC_TLDS: ReadonlySet<string> = new Set([
  'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'info', 'biz', 'app', 'dev',
  'ai', 'me', 'tv', 'cc', 'ws', 'xyz', 'top', 'online', 'site', 'shop', 'store', 'live',
  'click', 'link', 'icu', 'vip', 'club', 'page', 'mobi', 'name', 'pro', 'tech',
]);

/** Registry second-level labels (`co.uk`, `com.au`, `ne.jp`). */
const REGISTRY_SECOND_LEVELS: ReadonlySet<string> = new Set([
  'ac', 'co', 'com', 'edu', 'gob', 'go', 'gouv', 'gov', 'int', 'ltd', 'mil', 'ne', 'net',
  'nic', 'nom', 'or', 'org', 'plc', 'sch', 'info', 'biz',
]);

const CC_TLD_RE = /^[a-z]{2}$/;

/**
 * Client-side mirror of the server refusal, for immediate inline feedback.
 * The server is authoritative (it also refuses PSL entries such as
 * `github.io`, reported back per entry in the 422). Returns the inline
 * message, or null when the suffix is allowed.
 */
export function refusedSuffixMessage(suffix: string): string | null {
  const s = normalizeSuffix(suffix);
  if (s == null) return null;
  const labels = s.split('.');
  const tld = labels[labels.length - 1];
  let what: string | null = null;
  if (labels.length === 1) {
    if (REFUSED_PUBLIC_TLDS.has(tld)) what = 'is a high-volume public TLD';
    else if (CC_TLD_RE.test(tld)) what = 'is a country-code TLD';
  } else if (labels.length === 2 && CC_TLD_RE.test(tld) && REGISTRY_SECOND_LEVELS.has(labels[0])) {
    what = 'is a public registry suffix';
  }
  if (what == null) return null;
  return `${s} ${what}: listing it would switch off threat-intel enrichment and domain rarity for every domain under it, attacker-registered ones included. Use your own domain instead, such as corp.example.${s}.`;
}

/**
 * Low-volume public TLDs companies plausibly use internally. Allowed, with
 * the explicit blinding warning ([`publicSuffixWarningText`]). The server's
 * `public_suffix_warnings` (full Public Suffix List) is authoritative.
 */
export const PUBLIC_TLD_WARNINGS: ReadonlySet<string> = new Set([
  'cloud', 'prod', 'systems', 'network', 'group', 'services', 'zone', 'host', 'company',
  'global', 'office', 'email', 'run', 'studio', 'eu',
]);

/** True when `suffix` is a single label that is a known (allowed) public TLD. */
export function isPublicTldWarning(suffix: string): boolean {
  const s = normalizeSuffix(suffix);
  return s != null && !s.includes('.') && PUBLIC_TLD_WARNINGS.has(s);
}

/** Inline warning for an accepted public suffix (mirrors the server copy). */
export function publicSuffixWarningText(suffix: string): string {
  return `Domains under .${suffix} will no longer get threat-intel enrichment or domain rarity, including attacker-registered ones like evil.${suffix}. Prefer a narrower suffix such as corp.example.${suffix}.`;
}

/** Stats alias the preview query emits; the count is read from `results[0][PREVIEW_COUNT_FIELD]`. */
export const PREVIEW_COUNT_FIELD = 'names';

/**
 * nPL for the settings 24h preview: distinct destination hostnames equal to or
 * under any of `suffixes`. `dst_endpoint.hostname` on OCSF, `dest_host` on UDM.
 * Suffixes are re-normalized, so only `[a-z0-9_.-]` reaches the query. Returns
 * null when no valid suffix remains.
 */
export function buildInternalDomainsPreviewQuery(
  suffixes: readonly string[],
  schema: 'ocsf' | 'udm',
): string | null {
  const field = schema === 'ocsf' ? 'dst_endpoint.hostname' : 'dest_host';
  const valid = [...new Set(suffixes.map(normalizeSuffix).filter((s): s is string => s != null))];
  if (valid.length === 0) return null;
  const terms = valid.map((s) => `${field}="*.${s}" OR ${field}="${s}"`).join(' OR ');
  return `${terms} | stats dc(${field}) as ${PREVIEW_COUNT_FIELD}`;
}
