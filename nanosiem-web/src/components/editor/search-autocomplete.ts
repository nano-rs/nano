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
 * Convert query autocomplete options to CodeMirror completions
 */
function toCompletions(
  options: AutocompleteOption[],
  from: number,
  context: string | null,
  doc: string,
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
        // Check if we're already inside quotes
        if (from > 0 && doc[from - 1] !== '"') {
          completion.apply = `"${opt.value}"`;
        }
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
    from,
    options: completions,
    validFor: COMPLETION_VALID_FOR,
  };
}

/**
 * Autocomplete source for nPL queries in the search bar
 */
export async function searchQueryAutocomplete(context: CompletionContext): Promise<CompletionResult | null> {
  const doc = context.state.doc.toString();
  const pos = context.pos;

  const result = await getQueryAutocompleteSuggestions(doc, pos, [], { explicit: context.explicit });

  if (result.options.length === 0) {
    return null;
  }

  // Find where the current word starts
  const textBefore = doc.substring(0, pos);
  let from = pos;
  const wordMatch = textBefore.match(COMPLETION_TOKEN_BEFORE);
  if (wordMatch) {
    from = pos - wordMatch[0].length;
  }

  return toCompletions(result.options, from, result.context, doc);
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
