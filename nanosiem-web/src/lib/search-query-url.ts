// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Query text persisted in browser history or copied into a shareable URL.
 * Execution keeps the original query; replaying a signed URL needs fresh credentials.
 *
 * Only credentials are removed, so an ordinary hunt replays byte for byte
 * (NAN-4927 review: a URL literal like `url.full="https://x/dl?id=42"` must
 * not become a different search after reload or share):
 *
 * - userinfo (`https://user:secret@host`) is always dropped;
 * - a URL inside an `inputlookup` stage (a signed storage/lookup URL, whose
 *   credential can sit in any parameter) loses its whole query and fragment;
 * - any other http(s) URL keeps its query and fragment, except the values of
 *   credential-bearing parameters (token, key, sig, password, secret, auth,
 *   cloud signing parameters, ...), which become `[REDACTED]`.
 */
const SENSITIVE_PARAM = /(token|key|sig|signature|password|passwd|pwd|secret|auth|credential|session|cookie|^x-amz-|^x-goog-|^code$)/iu;

function redactParams(part: string): string {
  // `part` is a query or fragment body without its leading `?`/`#`.
  return part
    .split('&')
    .map((pair) => {
      const eq = pair.indexOf('=');
      if (eq < 0) return pair;
      let name = pair.slice(0, eq);
      try { name = decodeURIComponent(name); } catch { /* keep raw */ }
      return SENSITIVE_PARAM.test(name) ? `${pair.slice(0, eq)}=[REDACTED]` : pair;
    })
    .join('&');
}

function redactQueryAndFragment(rest: string): string {
  // `rest` starts at the first `?` or `#` after the path.
  const hash = rest.indexOf('#');
  const search = hash < 0 ? rest : rest.slice(0, hash);
  const fragment = hash < 0 ? '' : rest.slice(hash + 1);
  const searchOut = search.startsWith('?') ? `?${redactParams(search.slice(1))}` : search;
  return hash < 0 ? searchOut : `${searchOut}#${redactParams(fragment)}`;
}

export function searchQueryForUrl(query: string): string {
  let safe = '';
  let cursor = 0;
  let quote: string | undefined;
  let stageStart = 0;
  while (cursor < query.length) {
    const scheme = /^https?:\/\//iu.exec(query.slice(cursor, cursor + 8));
    if (scheme) {
      let end = cursor + scheme[0].length;
      while (end < query.length) {
        const char = query[end];
        if (quote ? char === quote : /[\s|<>]/u.test(char)) break;
        end++;
      }
      const raw = query.slice(cursor, end);
      const cut = raw.search(/[?#]/u);
      const base = cut < 0 ? raw : raw.slice(0, cut);
      const tail = base.slice(scheme[0].length);
      const slash = tail.indexOf('/');
      const authority = slash < 0 ? tail : tail.slice(0, slash);
      safe += scheme[0] + authority.slice(authority.lastIndexOf('@') + 1);
      if (slash >= 0) safe += tail.slice(slash);
      if (cut >= 0) {
        const inLookup = /^\s*inputlookup\b/iu.test(query.slice(stageStart, cursor));
        safe += inLookup ? '?[REDACTED]' : redactQueryAndFragment(raw.slice(cut));
      }
      cursor = end;
      continue;
    }
    const char = query[cursor++];
    if (char === '"' || char === "'") {
      if (quote === char) quote = undefined;
      else if (!quote) quote = char;
    } else if (char === '|' && !quote) {
      stageStart = cursor;
    }
    safe += char;
  }
  return safe;
}
