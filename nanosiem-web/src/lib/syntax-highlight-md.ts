// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Syntax highlighting for code blocks in the Markdown component.
 * Extracted from the old render-markdown.ts — preserves VRL, SQL, nPL, and generic highlighting.
 */

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/** Highlight code for a given language, returning an HTML string */
export function highlightCode(code: string, lang: string): string {
  const escaped = escapeHtml(code);
  const l = lang.toLowerCase();

  if (l === 'vrl' || l === 'sql' || l === 'npl' || l === 'search') {
    return highlightStructured(escaped, l);
  }
  return highlightGeneric(escaped);
}

function highlightStructured(code: string, lang: string): string {
  return code.split('\n').map(line => {
    if (/^\s*(#|\/\/)/.test(line)) {
      return `<span class="text-muted-foreground italic">${line}</span>`;
    }

    let result = line;

    // Strings
    result = result.replace(/"([^"]*?)"/g, '<span class="text-green-600 dark:text-green-400">"$1"</span>');
    result = result.replace(/'([^']*?)'/g, '<span class="text-green-600 dark:text-green-400">\'$1\'</span>');

    // Numbers
    result = result.replace(/\b(\d+(?:\.\d+)?)\b/g, '<span class="text-amber-600 dark:text-amber-400">$1</span>');

    // Keywords per language
    if (lang === 'vrl') {
      result = highlightKeywords(result, [
        'if', 'else', 'for', 'abort', 'null', 'true', 'false', 'err', 'ok',
      ]);
      result = result.replace(/\b([a-z_]+!)\(/g, '<span class="text-blue-600 dark:text-blue-400">$1</span>(');
      result = result.replace(/(\.[A-Za-z_][A-Za-z0-9_.]*)/g, '<span class="text-cyan-600 dark:text-cyan-400">$1</span>');
      result = result.replace(/^(\s*)([a-z_][a-z0-9_.]*)\s*=/m, '$1<span class="text-purple-600 dark:text-purple-300">$2</span> =');
    } else if (lang === 'sql') {
      result = highlightKeywords(result, [
        'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 'LIKE', 'JOIN',
        'LEFT', 'RIGHT', 'INNER', 'OUTER', 'ON', 'AS', 'GROUP', 'BY', 'ORDER',
        'HAVING', 'LIMIT', 'OFFSET', 'INSERT', 'UPDATE', 'DELETE', 'CREATE',
        'TABLE', 'INDEX', 'INTO', 'VALUES', 'SET', 'NULL', 'IS', 'BETWEEN',
        'UNION', 'ALL', 'DISTINCT', 'COUNT', 'SUM', 'AVG', 'MIN', 'MAX',
        'CASE', 'WHEN', 'THEN', 'ELSE', 'END', 'WITH', 'PREWHERE',
        'select', 'from', 'where', 'and', 'or', 'not', 'in', 'like', 'join',
        'left', 'right', 'inner', 'outer', 'on', 'as', 'group', 'by', 'order',
        'having', 'limit', 'offset', 'null', 'is', 'between',
        'count', 'sum', 'avg', 'min', 'max',
        'case', 'when', 'then', 'else', 'end', 'with', 'prewhere',
      ]);
    } else if (lang === 'npl' || lang === 'search') {
      result = highlightKeywords(result, [
        'stats', 'where', 'sort', 'head', 'tail', 'table', 'timechart',
        'eval', 'rename', 'dedup', 'top', 'rare', 'count', 'by', 'as',
        'span', 'AND', 'OR', 'NOT',
      ]);
      result = result.replace(/\|/g, '<span class="text-purple-500 dark:text-purple-400 font-bold">|</span>');
    }

    // Inline comments at end of line
    result = result.replace(/(\/\/.*)$/, '<span class="text-muted-foreground italic">$1</span>');

    return result;
  }).join('\n');
}

function highlightKeywords(code: string, keywords: string[]): string {
  const kw = keywords.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  // Match HTML tags first (skip them), then keywords outside tags.
  // This prevents keywords like "span" from matching inside <span> tags
  // inserted by earlier highlighting passes (numbers, strings).
  const pattern = new RegExp(`<[^>]+>|\\b(${kw})\\b`, 'g');
  return code.replace(pattern, (match, captured) => {
    if (!captured) return match;
    return `<span class="text-blue-600 dark:text-blue-400 font-semibold">${captured}</span>`;
  });
}

function highlightGeneric(code: string): string {
  let result = code;
  result = result.replace(/(\/\/.*$)/gm, '<span class="text-muted-foreground italic">$1</span>');
  result = result.replace(/^(\s*#.*$)/gm, '<span class="text-muted-foreground italic">$1</span>');
  result = result.replace(/"([^"]*?)"/g, '<span class="text-green-600 dark:text-green-400">"$1"</span>');
  result = result.replace(/\b(\d+(?:\.\d+)?)\b/g, '<span class="text-amber-600 dark:text-amber-400">$1</span>');
  return result;
}

/** Check if a language tag represents a runnable query (nPL/search) */
export function isQueryLang(lang: string): boolean {
  const l = lang.toLowerCase();
  return l === 'npl' || l === 'search';
}

/** Format a language label for display */
export function langLabel(lang: string): string {
  const map: Record<string, string> = {
    vrl: 'VRL',
    sql: 'SQL',
    npl: 'nPL',
    search: 'nPL',
    json: 'JSON',
    yaml: 'YAML',
    bash: 'Bash',
    sh: 'Shell',
    rust: 'Rust',
    ts: 'TypeScript',
    typescript: 'TypeScript',
    js: 'JavaScript',
    javascript: 'JavaScript',
    python: 'Python',
    py: 'Python',
  };
  return map[lang.toLowerCase()] || lang.toUpperCase();
}
