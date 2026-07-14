// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Keyword highlighting for search results.
 *
 * Extracted from SearchResults.tsx so the desktop app renders the same yellow
 * marks over the same terms — a second copy would drift from this one.
 */

import type { ReactNode } from 'react';

/**
 * Extract keywords from a search query for highlighting.
 * Only extracts free-text keywords, not field=value patterns.
 *
 * Examples:
 * - "c2 beacon" → ["c2", "beacon"]
 * - "src_ip=192.168.1.1" → []
 * - "malware src_ip=10.0.0.1" → ["malware"]
 * - '"exact phrase"' → ["exact phrase"]
 */
export function extractKeywordsFromQuery(query: string | undefined): string[] {
  if (!query || !query.trim()) return [];

  // Only extract highlight terms from the search portion (before first pipe).
  // Everything after a pipe is a transformation command (stats, where, table, etc.)
  // and should not generate highlights — those tokens are commands, not search text.
  const searchPortion = query.split('|')[0];
  if (!searchPortion.trim()) return [];

  // Two tiers of highlight terms:
  //  • strong — explicit field=value, IN-list, and quoted values. Always
  //    highlighted, INCLUDING numeric values like status=500 / dest_port=443.
  //  • weak — bare free-text tokens. Short pure numbers are dropped from this
  //    tier because they produce noisy false-positive highlights everywhere.
  const strongKeywords: string[] = [];
  const weakKeywords: string[] = [];
  const fieldValueRegex = /(\w+)\s*(?:!=|=|<=|>=|<|>)\s*(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|\/((?:\\.|[^/\\])*)\/|(\S+))/g;
  const unescapeQuoted = (value: string): string =>
    value.replace(/\\(["'\\])/g, '$1');

  // Extract values from field=value patterns for highlighting
  // Matches: field="value", field='value', field=value, field=/regex/, field!="value", etc.
  // Skip sourcetype/source_type fields as they're common filters, not search terms
  let match;
  while ((match = fieldValueRegex.exec(searchPortion)) !== null) {
    const fieldName = match[1]?.toLowerCase();
    // Skip sourcetype/source_type - these are filter fields, not search keywords
    if (fieldName === 'sourcetype' || fieldName === 'source_type') {
      continue;
    }
    // match[2] = quoted with ", match[3] = quoted with ', match[4] = regex, match[5] = unquoted
    let value = match[2] || match[3] || match[4] || match[5];
    if (value && value.trim()) {
      value = unescapeQuoted(value);
      // Strip leading/trailing wildcards for highlighting (e.g., *powershell* -> powershell)
      value = value.trim().replace(/^\*+|\*+$/g, '');
      if (value) {
        strongKeywords.push(value);
      }
    }
  }

  // Also extract free-text keywords (not part of field=value)
  // Remove field=value patterns first
  fieldValueRegex.lastIndex = 0;
  const withoutFieldValues = searchPortion.replace(fieldValueRegex, ' ');

  // Remove field IN (...) patterns — extract quoted values as keywords first
  const inRegex = /\w+\s+IN\s*\(\s*((?:"[^"]*"|'[^']*'|[^)]*?))\s*\)/gi;
  let inMatch;
  const withoutIn = withoutFieldValues.replace(inRegex, (_fullMatch, valueList: string) => {
    // Extract quoted values from the IN list
    const quotedInRegex = /"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'/g;
    while ((inMatch = quotedInRegex.exec(valueList)) !== null) {
      const val = inMatch[1] || inMatch[2];
      if (val && val.trim()) strongKeywords.push(unescapeQuoted(val.trim()));
    }
    return ' ';
  });

  // Remove operators
  const withoutOperators = withoutIn.replace(/\b(AND|OR|NOT|IN)\b/gi, ' ');

  // Extract quoted phrases
  const quotedRegex = /"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'/g;
  while ((match = quotedRegex.exec(withoutOperators)) !== null) {
    const phrase = match[1] || match[2];
    if (phrase && phrase.trim()) {
      strongKeywords.push(unescapeQuoted(phrase.trim()));
    }
  }

  // Extract remaining words — strip parentheses and commas from tokens
  const withoutQuotes = withoutOperators.replace(/"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'/g, ' ');
  const words = withoutQuotes
    .replace(/[(),]/g, ' ')
    .split(/\s+/)
    .filter(w => w.trim().length > 0);
  weakKeywords.push(...words);

  // Shared noise filter: wildcards, empties, pure punctuation.
  const isNoise = (k: string): boolean =>
    k.length === 0 ||
    k === '*' ||
    /^[\\'"`]+$/.test(k) ||
    /^[=<>!,()]+$/.test(k);

  // Strong terms highlight as-is (numbers included). Weak (bare) terms also
  // drop short pure numbers (1–4 digits) to avoid excessive false positives.
  const strong = strongKeywords.filter(k => !isNoise(k));
  const weak = weakKeywords.filter(k => !isNoise(k) && !/^\d{1,4}$/.test(k));

  return [...new Set([...strong, ...weak])];
}

/**
 * Highlight keywords in text by wrapping them in <mark> elements.
 * Case-insensitive matching.
 */
export function highlightText(text: string, keywords: string[]): ReactNode {
  if (!keywords.length || !text) return text;

  // Escape special regex characters in keywords
  const escapedKeywords = keywords.map(k =>
    k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  );

  // Build regex that matches any keyword (case-insensitive)
  const regex = new RegExp(`(${escapedKeywords.join('|')})`, 'gi');
  const parts = text.split(regex);

  if (parts.length === 1) return text; // No matches

  return parts.map((part, i) => {
    const isMatch = keywords.some(k => k.toLowerCase() === part.toLowerCase());
    return isMatch ? (
      <mark key={i} className="bg-amber-200/80 text-amber-950 ring-1 ring-amber-500/40 dark:bg-amber-400/25 dark:text-amber-200 dark:ring-amber-400/30 rounded-[2px] px-0.5 py-px -my-px">
        {part}
      </mark>
    ) : (
      part
    );
  });
}
