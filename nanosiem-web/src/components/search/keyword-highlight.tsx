// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Keyword highlighting for search results.
 *
 * Extracted from SearchResults.tsx so the desktop app renders the same yellow
 * marks over the same terms — a second copy would drift from this one.
 */

import { Fragment, type ReactNode } from 'react';
import { eventRowLineObject } from './event-row-line';

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
/**
 * Highlight terms split by scope (NAN-5328).
 *  • `free` — bare and quoted free-text terms; they match anywhere.
 *  • `scoped` — `field=value` / `field IN (...)` values; they highlight only in
 *    the field they were scoped to (an OCSF dotted path such as
 *    `actor.user.name` is one field name, not a free-text `actor.user.`).
 */
export interface ScopedHighlightTerm {
  field: string;
  value: string;
}
export interface HighlightTerms {
  free: string[];
  scoped: ScopedHighlightTerm[];
}

export const EMPTY_HIGHLIGHT_TERMS: HighlightTerms = { free: [], scoped: [] };

/**
 * Extract keywords from a search query for highlighting.
 * Flat union of free-text and field-scoped terms (see `extractHighlightTerms`
 * for the scoped form the result views use).
 *
 * Examples:
 * - "c2 beacon" → ["c2", "beacon"]
 * - "src_ip=192.168.1.1" → ["192.168.1.1"]
 * - "malware src_ip=10.0.0.1" → ["10.0.0.1", "malware"]
 * - '"exact phrase"' → ["exact phrase"]
 */
export function extractKeywordsFromQuery(query: string | undefined): string[] {
  const { free, scoped } = extractHighlightTerms(query);
  return [...new Set([...scoped.map((t) => t.value), ...free])];
}

export function extractHighlightTerms(query: string | undefined): HighlightTerms {
  if (!query || !query.trim()) return { free: [], scoped: [] };

  // Only extract highlight terms from the search portion (before first pipe).
  // Everything after a pipe is a transformation command (stats, where, table, etc.)
  // and should not generate highlights — those tokens are commands, not search text.
  const searchPortion = query.split('|')[0];
  if (!searchPortion.trim()) return { free: [], scoped: [] };

  // Tiers of highlight terms:
  //  • scoped — explicit field=value and IN-list values. Always highlighted
  //    (numeric values like status=500 included), but only in their field.
  //  • strong free — quoted phrases. Always highlighted, anywhere.
  //  • weak free — bare free-text tokens. Short pure numbers are dropped from
  //    this tier because they produce noisy false-positive highlights.
  const scoped: ScopedHighlightTerm[] = [];
  const strongKeywords: string[] = [];
  const weakKeywords: string[] = [];
  // Field names are OCSF dotted paths (`actor.user.name`) or UDM names.
  const fieldValueRegex = /([\w.]+)\s*(?:!=|=|<=|>=|<|>)\s*(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|\/((?:\\.|[^/\\])*)\/|(\S+))/g;
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
        scoped.push({ field: match[1], value });
      }
    }
  }

  // Also extract free-text keywords (not part of field=value)
  // Remove field=value patterns first
  fieldValueRegex.lastIndex = 0;
  const withoutFieldValues = searchPortion.replace(fieldValueRegex, ' ');

  // Remove field IN (...) patterns — extract quoted values as scoped terms first
  const inRegex = /([\w.]+)\s+IN\s*\(\s*((?:"[^"]*"|'[^']*'|[^)]*?))\s*\)/gi;
  let inMatch;
  const withoutIn = withoutFieldValues.replace(inRegex, (_fullMatch, field: string, valueList: string) => {
    // Extract quoted values from the IN list
    const quotedInRegex = /"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'/g;
    while ((inMatch = quotedInRegex.exec(valueList)) !== null) {
      const val = inMatch[1] || inMatch[2];
      if (val && val.trim()) scoped.push({ field, value: unescapeQuoted(val.trim()) });
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

  const seen = new Set<string>();
  const scopedUnique = scoped.filter((t) => {
    if (isNoise(t.value)) return false;
    const key = `${t.field.toLowerCase()}\u0000${t.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return { free: [...new Set([...strong, ...weak])], scoped: scopedUnique };
}

/**
 * NAN-5328: the terms to highlight inside one field's value — free-text terms
 * plus the terms scoped to THIS field. A scoped term whose field is not a key
 * of the event (`presentKeys`) — e.g. a UDM alias the server resolved to an
 * OCSF column — cannot be placed, so it highlights in every value instead of
 * disappearing.
 */
export function keywordsForField(
  terms: HighlightTerms,
  field: string,
  presentKeys: ReadonlySet<string>,
): string[] {
  const f = field.toLowerCase();
  const out = [...terms.free];
  for (const t of terms.scoped) {
    const tf = t.field.toLowerCase();
    if (tf === f || !hasKeyCaseInsensitive(presentKeys, tf)) out.push(t.value);
  }
  return [...new Set(out)];
}

// Lower-cased key sets, computed once per event key set (callers pass the
// same Set for every field of an event).
const loweredKeyCache = new WeakMap<ReadonlySet<string>, Set<string>>();

function hasKeyCaseInsensitive(keys: ReadonlySet<string>, lowered: string): boolean {
  if (keys.has(lowered)) return true;
  let low = loweredKeyCache.get(keys);
  if (!low) {
    low = new Set([...keys].map((k) => k.toLowerCase()));
    loweredKeyCache.set(keys, low);
  }
  return low.has(lowered);
}

/**
 * Highlight keywords in text by wrapping them in <mark> elements.
 * Case-insensitive matching.
 */
export function highlightText(text: string, keywords: string[]): ReactNode {
  if (!keywords.length || !text) return text;

  // Escape special regex characters in keywords. NAN-5328: a numeric term
  // (`class_uid=1007`) matches a whole number only — not the `1007` inside
  // `100701`.
  const escapedKeywords = keywords.map(k => {
    const escaped = k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return /^\d+$/.test(k) ? `(?<!\\d)${escaped}(?!\\d)` : escaped;
  });

  // Build regex that matches any keyword (case-insensitive)
  const regex = new RegExp(`(${escapedKeywords.join('|')})`, 'gi');
  const parts = text.split(regex);

  if (parts.length === 1) return text; // No matches

  return parts.map((part, i) => {
    const isMatch = keywords.some(k => k.toLowerCase() === part.toLowerCase());
    return isMatch ? (
      <mark key={i} className="bg-amber-200/80 text-amber-950 ring-1 ring-amber-500/40 dark:bg-amber-400/15 dark:text-inherit dark:ring-0 rounded-[2px] px-0.5 py-px -my-px">
        {part}
      </mark>
    ) : (
      part
    );
  });
}

/**
 * NAN-5328: highlight the compact JSON event line (`buildEventRowLine`) with
 * field scoping. Keys are never highlighted; each value gets the free-text
 * terms plus the terms scoped to its own key, so `actor.user.name="mallory"`
 * marks `mallory` in `actor.user.name`, not inside `process.cmd_line`.
 * The text is identical to `buildEventRowLine(fields, false, isOcsf)`, cut to `maxLen`.
 */
export function highlightEventRowLine(
  fields: Record<string, unknown> | undefined,
  terms: HighlightTerms,
  maxLen = Infinity,
  isOcsf = false,
): ReactNode {
  const obj = eventRowLineObject(fields, isOcsf);
  if (!obj) return null;
  const keys = new Set(Object.keys(obj));
  const segments: Array<{ text: string; keywords: string[] }> = [];
  const entries = Object.entries(obj);
  segments.push({ text: '{', keywords: [] });
  entries.forEach(([k, v], i) => {
    segments.push({ text: `${i > 0 ? ',' : ''}${JSON.stringify(k)}:`, keywords: [] });
    segments.push({ text: JSON.stringify(v), keywords: keywordsForField(terms, k, keys) });
  });
  segments.push({ text: '}', keywords: [] });

  let remaining = maxLen;
  const out: ReactNode[] = [];
  for (let i = 0; i < segments.length && remaining > 0; i++) {
    const seg = segments[i];
    const text = seg.text.length > remaining ? seg.text.substring(0, remaining) : seg.text;
    remaining -= text.length;
    out.push(
      <Fragment key={i}>{seg.keywords.length > 0 ? highlightText(text, seg.keywords) : text}</Fragment>,
    );
  }
  return out;
}
