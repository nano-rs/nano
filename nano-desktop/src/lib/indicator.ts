// Classify what the analyst typed into Quick Search: is it an indicator we can
// get a verdict on (IP / hash / domain), or a free-text nPL query? Runs on every
// keystroke, so it must be cheap and allocation-light.

export type IndicatorKind = 'ip' | 'hash' | 'domain';

export interface Indicator {
  kind: IndicatorKind;
  /** Normalized value (trimmed, hashes lowercased) — what we look up and query. */
  value: string;
}

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
// Full 8-group form, or any `::`-compressed form. Requiring `::` when there
// aren't 8 groups excludes MAC addresses (6 groups, no `::`), which the old
// loose pattern misread as IPv6.
const IPV6_FULL = /^(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$/i;
const IPV6_COMPRESSED = /^(?=.*::)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i;
// md5 / sha1 / sha256 by length.
const HASH = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
// A dotted hostname with a plausible TLD. No scheme, no path, no spaces.
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
// Common file extensions an analyst is likely to paste (a hash's filename, an
// artifact path). These look domain-shaped but aren't — and none is a real TLD,
// so excluding them is safe (unlike genuinely-ambiguous ones like .zip/.mov).
const FILE_EXT =
  /\.(?:exe|dll|sys|msi|dmg|pkg|app|bat|cmd|ps1|vbs|scr|jar|bin|dat|tmp|log|pdf|docx?|xlsx?|pptx?|rtf|csv|png|jpe?g|gif|bmp|svg|ico|txt|ini|conf|cfg|yaml|yml)$/i;

/** Return the indicator the input represents, or null if it's a free-text query. */
export function classifyIndicator(input: string): Indicator | null {
  const value = input.trim();
  if (!value || /\s/.test(value)) return null;

  if (IPV4.test(value) || IPV6_FULL.test(value) || IPV6_COMPRESSED.test(value)) {
    return { kind: 'ip', value };
  }
  if (HASH.test(value)) return { kind: 'hash', value: value.toLowerCase() };
  if (DOMAIN.test(value) && !FILE_EXT.test(value)) {
    return { kind: 'domain', value: value.toLowerCase() };
  }
  return null;
}

/**
 * The nPL query that finds an indicator's events, for the "Open in nano" handoff.
 * A quoted keyword search matches the value wherever it appears — the robust
 * "show me everything mentioning this" default; the analyst refines from there.
 */
export function indicatorQuery(indicator: Indicator): string {
  return `"${indicator.value}"`;
}

/**
 * Refang the conventions threat reports use so indicators can't be clicked or
 * auto-linked: `evil[.]com`, `hxxps://…`, `1.2.3[.]4`, `user[@]evil.com`.
 *
 * This is not a nicety — a pasted advisory is defanged FAR more often than not,
 * and an extractor that doesn't refang finds nothing in the exact documents
 * analysts actually paste.
 */
export function refang(text: string): string {
  return text
    .replace(/\bh(?:xx|XX)(ps?)\b/gi, 'htt$1')
    .replace(/\[\s*(?:\.|dot)\s*\]/gi, '.')
    .replace(/\(\s*(?:\.|dot)\s*\)/gi, '.')
    .replace(/\{\s*(?:\.|dot)\s*\}/gi, '.')
    .replace(/\[\s*(?::|colon)\s*\]/gi, ':')
    .replace(/\[\s*(?:@|at)\s*\]/gi, '@');
}

/** Punctuation a token picks up from prose — a trailing full stop, a quote. */
const EDGE_PUNCTUATION = /^[^\w[]+|[.,;:!?'")\]]+$/g;
const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Pull every indicator out of pasted freetext — a threat report, an advisory, a
 * chat message.
 *
 * Deduped, order-preserving. Classification reuses `classifyIndicator`, so the
 * careful parts (IPv6 vs MAC, filenames that look like domains) behave the same
 * here as in Quick Search rather than drifting into a second opinion.
 */
export function extractIndicators(text: string): Indicator[] {
  return extractWithStats(text).indicators;
}

export interface Extraction {
  indicators: Indicator[];
  /** How many times the paste repeated an indicator it already listed. */
  duplicates: number;
}

/**
 * The same extraction, plus the duplicate count. Counted HERE, where the tokens
 * are already refanged and classified — recovering it afterwards by re-scanning
 * the raw text does not work, because `evil[.]com` and `evil.com` are the same
 * indicator but not the same string.
 */
export function extractWithStats(text: string): Extraction {
  const seen = new Set<string>();
  const indicators: Indicator[] = [];
  let duplicates = 0;

  for (const rawToken of refang(text).split(/[\s,;"'<>()[\]{}|]+/)) {
    const candidate = hostOrValue(rawToken);
    if (!candidate) continue;

    const indicator = classifyIndicator(candidate);
    if (!indicator) continue;

    if (seen.has(indicator.value)) {
      duplicates += 1;
      continue;
    }
    seen.add(indicator.value);
    indicators.push(indicator);
  }

  return { indicators, duplicates };
}

/**
 * A URL is a domain wearing a scheme and a path. Reduce it to the host, which is
 * what the data actually holds — and strip the port, which it doesn't.
 */
function hostOrValue(token: string): string {
  const trimmed = token.replace(EDGE_PUNCTUATION, '');
  if (!trimmed) return '';

  const withoutScheme = trimmed.replace(SCHEME, '');
  const host = withoutScheme.split('/')[0];

  // `[2001:db8::1]:443` (bracketed IPv6 authority) — unwrap it before the port
  // strip below mistakes the address's own colons for one.
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(host);
  if (bracketed) return bracketed[1];

  // A single trailing `:443` is a port. An IPv6 address has several colons, so
  // this can't eat one of those.
  const colons = (host.match(/:/g) ?? []).length;
  return colons === 1 ? host.split(':')[0] : host;
}

export function indicatorLabel(kind: IndicatorKind): string {
  switch (kind) {
    case 'ip':
      return 'IP address';
    case 'hash':
      return 'File hash';
    case 'domain':
      return 'Domain';
  }
}
