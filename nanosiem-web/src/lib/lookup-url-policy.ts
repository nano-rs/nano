// SPDX-License-Identifier: AGPL-3.0-or-later
// Mirrors nanosiem-core/src/inputlookup/storage_policy.rs. No DNS or requests.
import suffixData from './lookup-public-suffixes.txt?raw';

export const LOOKUP_PSL_VERSION = '2.1.199';
export const STORAGE_POLICY_ERROR =
  'Shared inputlookup requires a static public HTTPS URL on port 443';
export const ALLOWLIST_ERROR =
  "host not in this tenant's inputlookup allowlist; a tenant admin can add it in Settings";
const ENTRY_ERROR =
  'enter an ASCII or punycode public hostname, without a URL, port or path';
const LABEL_ERROR = 'only exact hosts or *.domain suffixes are supported';
const INTERNAL_SUFFIXES = [
  'localhost',
  'local',
  'localdomain',
  'internal',
  'intranet',
  'lan',
  'home.arpa',
  'svc',
  'cluster.local',
  'nano.rs',
];
type SuffixNode = {
  children: Map<string, SuffixNode>;
  exact?: boolean;
  wildcard?: boolean;
  exception?: boolean;
};
const suffixRoot: SuffixNode = { children: new Map() };
for (const rule of suffixData.split(/\r?\n/)) {
  if (!rule || rule.startsWith('//')) continue;
  const base = rule.replace(/^!|^\*\./, '');
  // The pinned Rust list contains Unicode and punycode rules. Hosts themselves
  // use the URL parser's ASCII representation in both implementations.
  let node = suffixRoot;
  for (const label of new URL('https://' + base + '/').hostname
    .split('.')
    .reverse()) {
    if (!node.children.has(label))
      node.children.set(label, { children: new Map() });
    node = node.children.get(label)!;
  }
  if (rule.startsWith('!')) node.exception = true;
  else if (rule.startsWith('*.')) node.wildcard = true;
  else node.exact = true;
}

export type PolicyResult<T> =
  | { value: T; error?: never }
  | { error: string; value?: never };
export const utf8Bytes = (value: string) =>
  new TextEncoder().encode(value).length;
const label = (value: string) =>
  value.length > 0 &&
  value.length <= 63 &&
  /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(value);
const whitespaceOrControl = /[\p{White_Space}\p{Cc}]/u;
const ipLiteral = (host: string) =>
  host.startsWith('[') || /^[0-9.]+$/.test(host);

/** Match the pinned psl crate's generated trie, including private suffixes.
 * Explicit child branches take precedence over wildcard fallback, even when
 * that child only has a deeper wildcard rule (unlike longest-match PSL tools).
 */
export function hasRegistrableLookupDomain(host: string): boolean {
  const parts = host.split('.').reverse();
  let node = suffixRoot;
  let suffixLabels = 0;
  for (let index = 0; index < parts.length; index++) {
    const child = node.children.get(parts[index]);
    if (!child) {
      if (node.wildcard) suffixLabels = index + 1;
      break;
    }
    node = child;
    if (node.exception) return true;
    if (node.exact) suffixLabels = index + 1;
  }
  return suffixLabels > 0 && parts.length > suffixLabels;
}

/** Shared by the add form and URL tester. Preserve server normalization/errors. */
export function normalizeLookupHost(raw: string): PolicyResult<string> {
  if (
    /[^\x00-\x7f]/.test(raw) ||
    /[/:@?#%\\]/.test(raw) ||
    whitespaceOrControl.test(raw)
  )
    return { error: ENTRY_ERROR };
  const entry = raw.replace(/\.$/, '').toLowerCase();
  const host = entry.startsWith('*.') ? entry.slice(2) : entry;
  if (host.includes('*') || host.length > 253 || !host.split('.').every(label))
    return { error: LABEL_ERROR };
  let parsed: URL;
  try {
    parsed = new URL('https://' + host + '/');
  } catch {
    return { error: STORAGE_POLICY_ERROR };
  }
  if (ipLiteral(parsed.hostname) || parsed.hostname !== host)
    return { error: 'IP literals are forbidden' };
  if (
    INTERNAL_SUFFIXES.some(
      (suffix) => host === suffix || host.endsWith('.' + suffix),
    )
  )
    return { error: 'internal hostnames are forbidden' };
  if (host === 'amazonaws.com' || !hasRegistrableLookupDomain(host))
    return {
      error: 'a registrable domain is required; public suffixes are forbidden',
    };
  return { value: entry };
}

export function lookupHostAllowed(
  host: string,
  entries: readonly string[],
): string | undefined {
  return entries.find((entry) =>
    entry.startsWith('*.')
      ? host.endsWith('.' + entry.slice(2)) && host.length > entry.length - 1
      : host === entry,
  );
}

/** Reject ambiguities before WHATWG normalization can erase them, as Rust does. */
export function parseLookupUrl(raw: string): PolicyResult<URL> {
  if (
    utf8Bytes(raw) > 16384 ||
    whitespaceOrControl.test(raw) ||
    /[\\{}]/.test(raw)
  )
    return { error: STORAGE_POLICY_ERROR };
  const separator = raw.indexOf('://');
  if (separator < 0) return { error: STORAGE_POLICY_ERROR };
  const tail = raw.slice(separator + 3);
  const authority = tail.split(/[/?#]/, 1)[0];
  if (!authority || /[@%]/.test(authority))
    return { error: STORAGE_POLICY_ERROR };
  const path = tail.slice(authority.length).split(/[?#]/, 1)[0];
  if (
    /%2f|%5c|%2e/i.test(path) ||
    path.split('/').some((part) => part === '.' || part === '..')
  )
    return { error: STORAGE_POLICY_ERROR };
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { error: STORAGE_POLICY_ERROR };
  }
  if (
    url.protocol !== 'https:' ||
    (url.port && url.port !== '443') ||
    url.username ||
    url.password ||
    url.hash ||
    raw.includes('#') ||
    ipLiteral(url.hostname)
  )
    return { error: STORAGE_POLICY_ERROR };
  const host = url.hostname.replace(/\.$/, '').toLowerCase();
  if (host.length > 253 || !host.includes('.') || !host.split('.').every(label))
    return { error: STORAGE_POLICY_ERROR };
  url.hostname = host;
  return { value: url };
}

export function checkLookupUrl(
  raw: string,
  entries: readonly string[],
): PolicyResult<{ host: string; entry: string }> {
  const parsed = parseLookupUrl(raw);
  if (parsed.error) return { error: parsed.error };
  const host = parsed.value!.hostname;
  // Settings responses are normalized by the server. Still refuse invalid
  // entries here so a stale/malformed client cache cannot claim authorization.
  const normalized = entries.flatMap((entry) => {
    const result = normalizeLookupHost(entry);
    return result.value ? [result.value] : [];
  });
  const match = lookupHostAllowed(host, normalized);
  return match ? { value: { host, entry: match } } : { error: ALLOWLIST_ERROR };
}
