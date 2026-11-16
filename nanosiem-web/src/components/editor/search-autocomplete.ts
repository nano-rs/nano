// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * CodeMirror 6 autocomplete extension for the search bar.
 * Uses the same shared getQueryAutocompleteSuggestions as the rule editor.
 */
import {
  autocompletion,
  type CompletionContext,
  type CompletionResult,
  type Completion,
  type CompletionSection,
} from '@codemirror/autocomplete';
import { type Extension } from '@codemirror/state';
import {
  getQueryAutocompleteSuggestions,
  type AutocompleteOption,
} from '@/lib/query-autocomplete';
import { nplQuotedBody } from '@/lib/npl-quote';
import {
  FIELD_SECTION_LABELS,
  FIELD_SECTION_RANK,
  type FieldSection,
} from '@/lib/field-suggestion-ranking';

/** One CodeMirror section per field group, in fixed order (NAN-3812). */
export const FIELD_COMPLETION_SECTIONS: Record<FieldSection, CompletionSection> = Object.fromEntries(
  (Object.keys(FIELD_SECTION_LABELS) as FieldSection[]).map((key) => [
    key,
    { name: FIELD_SECTION_LABELS[key], rank: FIELD_SECTION_RANK[key] },
  ]),
) as Record<FieldSection, CompletionSection>;

/**
 * A completable token: field names include dotted OCSF paths
 * (`dst_endpoint.ip`, `actor.process.name`), so '.' is part of the word.
 * Without it the replaced range starts after the last '.', and accepting a
 * full-path suggestion duplicates the prefix (NAN-3192).
 */
export const COMPLETION_TOKEN_BEFORE = /[\w.*]+$/;
export const COMPLETION_VALID_FOR = /^[\w.*]*$/;

/**
 * Characters of an unquoted nPL value. Mirrors `is_unquoted_value_char` in
 * nanosiem-core/src/query/parser/values.rs: alphanumerics plus
 * `_ - . * ? / : @ \ +`. A value completion (`metadata.log_source=web-app-json`)
 * must replace this whole token; stopping at `-` replaced only `json` and
 * produced `web-app-"web-app-json"` (NAN-5500).
 */
// `\p{Alphabetic}` (not `\p{L}`) matches Rust `char::is_alphanumeric`, which
// includes combining marks.
const VALUE_CHARS = String.raw`\p{Alphabetic}\p{N}_\-.*?/:@\\+`;
const VALUE_TOKEN_BEFORE = new RegExp(`[${VALUE_CHARS}]+$`, 'u');
const VALUE_TOKEN_AFTER = new RegExp(`^[${VALUE_CHARS}]*`, 'u');
/** A value that needs no quotes when inserted bare. */
export const UNQUOTED_VALUE = new RegExp(`^[${VALUE_CHARS}]+$`, 'u');
export const VALUE_VALID_FOR = new RegExp(`^[${VALUE_CHARS}]*$`, 'u');
/** Body of a `"…"` value as query-autocomplete matches it (`"?([^"\s]*)$`). */
const QUOTED_VALUE_BEFORE = /=\s*"([^"\s]*)$/;
const QUOTED_VALUE_AFTER = /^[^"\s]*/;
const QUOTED_VALUE_VALID_FOR = /^[^"\s]*$/;

/** Completion contexts whose options are field VALUES, not names. */
const VALUE_CONTEXTS = new Set(['source_type']);

export interface CompletionRange {
  /** Start of the token being replaced. */
  from: number;
  /** End of the token being replaced (past the cursor when editing mid-token). */
  to: number;
  /** Value context: the token sits inside an open `"…"` literal. */
  quoted: boolean;
  /** Value context: a closing `"` already follows the token. */
  closed: boolean;
}

/**
 * The span an accepted completion replaces. Field/command names use the
 * `[\w.*]` token; value contexts use the nPL unquoted-value token (or the
 * body of an open `"…"`), extended past the cursor so the whole value is
 * replaced on Enter, Tab or click.
 */
export function completionRange(doc: string, pos: number, context: string | null): CompletionRange {
  const before = doc.slice(0, pos);
  const after = doc.slice(pos);
  if (!context || !VALUE_CONTEXTS.has(context)) {
    const m = before.match(COMPLETION_TOKEN_BEFORE);
    return { from: m ? pos - m[0].length : pos, to: pos, quoted: false, closed: false };
  }
  const quotedMatch = before.match(QUOTED_VALUE_BEFORE);
  if (quotedMatch) {
    const quotedTo = pos + (after.match(QUOTED_VALUE_AFTER)?.[0].length ?? 0);
    const closed = doc[quotedTo] === '"';
    // Unclosed literal: only the value token is ours, not `|stats` after it.
    const to = closed ? quotedTo : pos + (after.match(VALUE_TOKEN_AFTER)?.[0].length ?? 0);
    return { from: pos - quotedMatch[1].length, to, quoted: true, closed };
  }
  const m = before.match(VALUE_TOKEN_BEFORE);
  const to = pos + (after.match(VALUE_TOKEN_AFTER)?.[0].length ?? 0);
  return { from: m ? pos - m[0].length : pos, to, quoted: false, closed: false };
}

/**
 * Text inserted for a value completion: bare when nPL takes it bare as a
 * literal, else quoted. `*` / `?` are wildcards when bare, so values carrying
 * them are always quoted.
 */
export function valueCompletionApply(value: string, range: CompletionRange): string {
  if (range.quoted) return range.closed ? nplQuotedBody(value) : `${nplQuotedBody(value)}"`;
  return UNQUOTED_VALUE.test(value) && !/[*?]/.test(value) ? value : `"${nplQuotedBody(value)}"`;
}

/**
 * Value completions once the user may have typed a value in full. When the
 * token already equals an option (case-insensitively, as query-autocomplete
 * filters), the popup must close, or Enter accepts a completion (possibly a
 * longer sibling like `web-app-json-v2`) instead of running the search
 * (NAN-5500). An explicit request (Ctrl-Space) still lists the siblings.
 * Non-value contexts are returned unchanged.
 */
export function valueOptionsAfterTyping<T extends { value: string }>(
  options: T[],
  doc: string,
  range: CompletionRange,
  context: string | null,
  explicit: boolean,
): T[] {
  if (!context || !VALUE_CONTEXTS.has(context)) return options;
  const typed = doc.slice(range.from, range.to).toLowerCase();
  if (!typed || !options.some((o) => o.value.toLowerCase() === typed)) return options;
  return explicit ? options.filter((o) => o.value.toLowerCase() !== typed) : [];
}

/** `validFor` for a result: value contexts re-query once the token is an exact option. */
export function completionValidFor(
  context: string | null,
  range: CompletionRange,
  labels: string[],
): RegExp | ((text: string) => boolean) {
  if (!context || !VALUE_CONTEXTS.has(context)) return COMPLETION_VALID_FOR;
  const pattern = range.quoted ? QUOTED_VALUE_VALID_FOR : VALUE_VALID_FOR;
  const exact = new Set(labels.map((l) => l.toLowerCase()));
  return (text: string) => pattern.test(text) && !exact.has(text.toLowerCase());
}

/**
 * Convert query autocomplete options to CodeMirror completions
 */
function toCompletions(
  options: AutocompleteOption[],
  range: CompletionRange,
  context: string | null,
): CompletionResult {
  const completions: Completion[] = options.map((opt, index) => {
    const completion: Completion = {
      label: opt.value,
      info: opt.description,
      boost: options.length - index,
    };

    switch (context) {
      case 'command':
        completion.type = 'function';
        break;
      case 'field':
        completion.type = 'property';
        if (opt.category) {
          completion.detail = opt.category;
        }
        if (opt.section) {
          completion.section = FIELD_COMPLETION_SECTIONS[opt.section];
        }
        break;
      case 'function':
        completion.type = 'function';
        break;
      case 'parameter':
        completion.type = 'property';
        break;
      case 'argument_value':
        // Plain value (span=1h, type=inner): never append `()` (NAN-3193).
        completion.type = 'constant';
        break;
      case 'source_type':
        completion.type = 'enum';
        completion.apply = valueCompletionApply(opt.value, range);
        break;
      case 'table_wildcard':
        completion.type = 'keyword';
        break;
      default:
        completion.type = 'text';
    }

    return completion;
  });

  return {
    from: range.from,
    to: range.to,
    options: completions,
    validFor: completionValidFor(context, range, options.map((o) => o.value)),
  };
}

/**
 * Autocomplete source for nPL queries in the search bar
 */
export async function searchQueryAutocomplete(context: CompletionContext): Promise<CompletionResult | null> {
  const doc = context.state.doc.toString();
  const pos = context.pos;

  const result = await getQueryAutocompleteSuggestions(doc, pos, [], { explicit: context.explicit });

  const range = completionRange(doc, pos, result.context);
  const options = valueOptionsAfterTyping(result.options, doc, range, result.context, context.explicit);
  if (options.length === 0) {
    return null;
  }

  return toCompletions(options, range, result.context);
}

/**
 * Create the search autocomplete extension
 * @param activateOnTyping - When true, shows suggestions as you type. When false, only on Ctrl+Space/Tab.
 */
export function searchAutocomplete(activateOnTyping = true): Extension {
  return autocompletion({
    override: [searchQueryAutocomplete],
    activateOnTyping,
    maxRenderedOptions: 20,
    defaultKeymap: true,
    icons: true,
  });
}

export default searchAutocomplete;
