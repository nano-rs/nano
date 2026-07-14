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
} from '@codemirror/autocomplete';
import { type Extension } from '@codemirror/state';
import {
  getQueryAutocompleteSuggestions,
  type AutocompleteOption,
} from '@/lib/query-autocomplete';

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
        break;
      case 'function':
        completion.type = 'function';
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
    validFor: /^[\w*]*$/,
  };
}

/**
 * Autocomplete source for nPL queries in the search bar
 */
async function searchQueryAutocomplete(context: CompletionContext): Promise<CompletionResult | null> {
  const doc = context.state.doc.toString();
  const pos = context.pos;

  const result = await getQueryAutocompleteSuggestions(doc, pos, []);

  if (result.options.length === 0) {
    return null;
  }

  // Find where the current word starts
  const textBefore = doc.substring(0, pos);
  let from = pos;
  const wordMatch = textBefore.match(/[\w*]+$/);
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
