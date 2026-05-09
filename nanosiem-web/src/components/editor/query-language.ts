// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * CodeMirror 6 language mode for query language (without YAML)
 * Used for dashboard panel editor and other query inputs
 */
import { StreamLanguage, StringStream } from '@codemirror/language';
import { tags, Tag } from '@lezer/highlight';
import { UDM_COLUMNS } from '@/lib/udm-fields';
import {
  PIPE_COMMANDS_SET,
  COMMAND_PARAMS_SET,
  EVAL_FUNCTIONS_SET,
  ENRICHED_FIELDS_SET,
  IOC_FIELDS_SET,
  COMPUTED_FIELDS_SET,
  FIELD_ALIASES_SET,
  TREE_STEP_PATTERN,
} from '@/lib/query-tokens';

// Combined UDM field names (includes enriched, IOC, computed, and aliases)
// Mutable — ext fields discovered from search results are added at runtime
const UDM_FIELD_NAMES = new Set([...UDM_COLUMNS, ...ENRICHED_FIELDS_SET, ...IOC_FIELDS_SET, ...COMPUTED_FIELDS_SET, ...FIELD_ALIASES_SET]);

/**
 * Register additional field names for syntax highlighting (e.g. ext fields
 * discovered from search results). The tokenizer reads from the same Set
 * reference, so additions take effect on the next keystroke.
 */
export function registerDynamicFields(fields: string[]) {
  for (const f of fields) {
    UDM_FIELD_NAMES.add(f);
  }
}

interface QueryState {
  afterRegexOp: boolean;
  inBlockComment: boolean;
}

function createInitialState(): QueryState {
  return {
    afterRegexOp: false,
    inBlockComment: false,
  };
}

/**
 * Stream-based tokenizer for query language
 */
const queryLanguageDefinition = {
  name: 'query',

  startState: createInitialState,

  copyState(state: QueryState): QueryState {
    return { ...state };
  },

  token(stream: StringStream, state: QueryState): string | null {
    // Handle block comments
    if (state.inBlockComment) {
      if (stream.match(/.*?\*\//)) {
        state.inBlockComment = false;
        return 'blockComment';
      }
      stream.skipToEnd();
      return 'blockComment';
    }

    // Start of block comment
    if (stream.match(/^\/\*/)) {
      if (stream.match(/.*?\*\//)) {
        return 'blockComment';
      }
      state.inBlockComment = true;
      return 'blockComment';
    }

    // Skip whitespace
    if (stream.eatSpace()) {
      return null;
    }

    // Line comments
    if (stream.match(/^\/\/.*/)) {
      return 'lineComment';
    }

    // Regex patterns after =~ or ~ operators
    if (state.afterRegexOp && stream.peek() === '/') {
      if (stream.match(/^\/(?:[^/\\\n]|\\.)+\/[igmsuy]*/)) {
        state.afterRegexOp = false;
        return 'regexp';
      }
    }

    // Check for regex operators (=~ and ~)
    if (stream.match(/^=~|^~/)) {
      state.afterRegexOp = true;
      return 'operator';
    }

    // Comparison operators
    if (stream.match(/^!=|^>=|^<=/)) {
      state.afterRegexOp = false;
      return 'operator';
    }

    // Plain = can be followed by regex
    if (stream.match(/^=/)) {
      state.afterRegexOp = true;
      return 'operator';
    }

    // Other comparison operators
    if (stream.match(/^>|^</)) {
      state.afterRegexOp = false;
      return 'operator';
    }

    // Pipe operator (special highlighting)
    if (stream.match(/^\|/)) {
      state.afterRegexOp = false;
      return 'separator';
    }

    // Wildcard patterns *keyword*
    if (stream.match(/^\*[^*\s]+\*/)) {
      return 'string';
    }

    // Strings
    if (stream.match(/^"[^"]*"/)) {
      return 'string';
    }

    // Keywords (AND, OR, NOT, IN, CONTAINS, LIKE, STARTSWITH, ENDSWITH)
    if (stream.match(/^(AND|OR|NOT|IN|CONTAINS|LIKE|STARTSWITH|ENDSWITH)\b/i)) {
      return 'keyword';
    }

    // Boolean and enum values
    if (stream.match(/^(true|false|asc|desc|inner|left|outer|zscore|mad|sliding|tumbling)\b/i)) {
      return 'bool';
    }

    // Time window values (24h, 7d, 30m, etc.)
    if (stream.match(/^\d+[hdms]\b/)) {
      return 'number';
    }

    // Numbers
    if (stream.match(/^\d+(\.\d+)?/)) {
      return 'number';
    }

    // Handle extension field patterns (ext_, enriched_, ioc_)
    if (stream.match(/^(ext|enriched|ioc)_[a-zA-Z_][a-zA-Z0-9_]*/)) {
      return 'special(propertyName)';
    }

    // Identifiers (check against known sets)
    const startPos = stream.pos;
    if (stream.match(/^[a-zA-Z_][a-zA-Z0-9_]*/)) {
      const word = stream.string.slice(startPos, stream.pos);
      const wordLower = word.toLowerCase();

      // Pipe commands
      if (PIPE_COMMANDS_SET.has(wordLower)) {
        return 'function(variableName)';
      }

      // Command parameters
      if (COMMAND_PARAMS_SET.has(wordLower) || TREE_STEP_PATTERN.test(word)) {
        return 'propertyName';
      }

      // Eval functions
      if (EVAL_FUNCTIONS_SET.has(word) || EVAL_FUNCTIONS_SET.has(wordLower)) {
        return 'function(variableName)';
      }

      // UDM field names
      if (UDM_FIELD_NAMES.has(word)) {
        return 'special(propertyName)';
      }

      // Default identifier
      return 'variableName';
    }

    // Arithmetic operators
    if (stream.match(/^[+\-*\/%\.]/)) {
      return 'arithmeticOperator';
    }

    // Parentheses and brackets
    if (stream.match(/^[()[\]{}]/)) {
      return 'punctuation';
    }

    // Commas and colons
    if (stream.match(/^[,:]/)) {
      return 'punctuation';
    }

    // Default: consume one character
    stream.next();
    return null;
  },

  languageData: {
    commentTokens: { line: '//', block: { open: '/*', close: '*/' } },
  },
};

/**
 * Tag mappings for highlighting
 */
const tokenTable: Record<string, Tag> = {
  comment: tags.comment,
  lineComment: tags.lineComment,
  blockComment: tags.blockComment,
  string: tags.string,
  regexp: tags.regexp,
  keyword: tags.keyword,
  bool: tags.bool,
  number: tags.number,
  'function(variableName)': tags.function(tags.variableName),
  propertyName: tags.propertyName,
  'special(propertyName)': tags.special(tags.propertyName),
  variableName: tags.variableName,
  operator: tags.operator,
  arithmeticOperator: tags.arithmeticOperator,
  separator: tags.separator,
  punctuation: tags.punctuation,
  meta: tags.meta,
  atom: tags.atom,
};

/**
 * Create the StreamLanguage with token table
 */
export const queryLanguage = StreamLanguage.define({
  ...queryLanguageDefinition,
  tokenTable,
});

export default queryLanguage;
