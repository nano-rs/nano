// SPDX-License-Identifier: AGPL-3.0-or-later

/** Query text persisted in browser history or copied into a shareable URL.
 * Execution keeps the original query; replaying a signed URL needs fresh credentials.
 */
export function searchQueryForUrl(query: string): string {
  let safe = '';
  let cursor = 0;
  let quote: string | undefined;
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
      if (cut >= 0) safe += '?[REDACTED]';
      cursor = end;
      continue;
    }
    const char = query[cursor++];
    if (char === '"' || char === "'") {
      if (quote === char) quote = undefined;
      else if (!quote) quote = char;
    }
    safe += char;
  }
  return safe;
}
