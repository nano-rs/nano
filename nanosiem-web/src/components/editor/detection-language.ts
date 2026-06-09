// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Custom CodeMirror 6 language mode for detection rules
 * Supports dual-section format: YAML frontmatter + query language
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
const UDM_FIELD_NAMES = new Set([...UDM_COLUMNS, ...ENRICHED_FIELDS_SET, ...IOC_FIELDS_SET, ...COMPUTED_FIELDS_SET, ...FIELD_ALIASES_SET]);

/**
 * Register additional field names for detection-editor syntax highlighting
 * (NAN-1241) — e.g. the active schema's OCSF promoted columns from
 * `getSchemaFields()`. The tokenizer reads the same Set reference, so additions
 * take effect on the next keystroke. Under UDM this is never called with new
 * names, so highlighting stays byte-identical.
 */
export function registerDetectionDynamicFields(fields: string[]) {
  for (const f of fields) {
    UDM_FIELD_NAMES.add(f);
  }
}

// YAML keywords for value highlighting (sorted by length descending so longer matches are tried first)
const YAML_KEYWORDS = [
  'auto-detect', 'per_event', 'scheduled', 'alerting', 'realtime', 'critical', 'staging',
  'grouped', 'paused', 'medium', 'live', 'high', 'auto', 'low',
];

// YAML field names that have autocomplete
const YAML_AUTOCOMPLETE_FIELDS = new Set([
  'severity', 'mode', 'detection_mode', 'alert_mode', 'risk_score', 'risk_entity', 'mitre_tactics', 'mitre_techniques',
]);

interface DetectionState {
  inYaml: boolean;
  yamlStarted: boolean;
  yamlEnded: boolean;
  afterRegexOp: boolean;
  inBlockComment: boolean;
}

function createInitialState(): DetectionState {
  return {
    inYaml: false,
    yamlStarted: false,
    yamlEnded: false,
    afterRegexOp: false,
    inBlockComment: false,
  };
}

/**
 * Stream-based tokenizer for detection rules
 */
const detectionLanguageDefinition = {
  name: 'detection',

  startState: createInitialState,

  copyState(state: DetectionState): DetectionState {
    return { ...state };
  },

  token(stream: StringStream, state: DetectionState): string | null {
    // Handle YAML frontmatter delimiters
    if (stream.sol() && stream.match(/^---$/)) {
      if (!state.yamlStarted) {
        state.yamlStarted = true;
        state.inYaml = true;
        return 'meta';
      } else if (state.inYaml) {
        state.inYaml = false;
        state.yamlEnded = true;
        return 'meta';
      }
    }

    // YAML section parsing
    if (state.inYaml && state.yamlStarted && !state.yamlEnded) {
      return tokenizeYaml(stream, state);
    }

    // Query section parsing
    return tokenizeQuery(stream, state);
  },

  languageData: {
    commentTokens: { line: '//', block: { open: '/*', close: '*/' } },
  },
};

/**
 * Tokenize YAML frontmatter
 */
function tokenizeYaml(stream: StringStream, _state: DetectionState): string | null {
  // Skip leading whitespace
  if (stream.eatSpace()) {
    return null;
  }

  // YAML comments
  if (stream.match(/^#.*/)) {
    return 'comment';
  }

  // YAML key: value pattern
  if (stream.sol()) {
    const match = stream.match(/^([a-z_]+):/);
    if (match) {
      return 'propertyName';
    }
  }

  // Quoted strings (check early)
  if (stream.match(/^"[^"]*"/)) {
    return 'string';
  }

  // YAML keywords (mode values, severity, etc.)
  // Check longest first to match 'auto-detect' before 'auto'
  for (const keyword of YAML_KEYWORDS) {
    // Escape special regex chars (like hyphen) and use word boundary or end-of-string
    const escaped = keyword.replace(/[-]/g, '\\-');
    if (stream.match(new RegExp(`^${escaped}(?=[\\s,]|$)`))) {
      return 'atom';
    }
  }

  // MITRE IDs (TA0001, T1059, etc.) - match as whole token
  if (stream.match(/^T[AS]?\d{4}(\.\d{3})?(?=[\s,]|$)/)) {
    return 'atom';
  }

  // Cron expressions (contains * or / with numbers)
  if (stream.match(/^\*[\d\/\s\*,]+/)) {
    return 'string';
  }

  // Time durations (15m, 1h, 6h, 24h, 7d, etc.) - standalone only
  if (stream.match(/^\d+[hdms](?=[\s,]|$)/)) {
    return 'number';
  }

  // Plain numbers - only match if standalone (not part of identifier)
  // Must be followed by whitespace, comma, or end of line
  if (stream.match(/^\d+(?=[\s,]|$)/)) {
    return 'number';
  }

  // Identifiers/values: match whole words including alphanumeric with underscores/hyphens
  // This prevents numbers in the middle of words from being matched separately
  if (stream.match(/^[a-zA-Z_][a-zA-Z0-9_-]*/)) {
    return null; // Plain text, no special highlighting
  }

  // Handle remaining digits that are part of identifiers starting with numbers (e.g., after underscore)
  if (stream.match(/^[0-9]+[a-zA-Z_][a-zA-Z0-9_-]*/)) {
    return null; // Part of identifier
  }

  // Everything else (punctuation, etc.)
  stream.next();
  return null;
}

/**
 * Tokenize query language
 */
function tokenizeQuery(stream: StringStream, state: DetectionState): string | null {
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

  // Comparison operators - = can also precede regex like: sourcetype = /sys/
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

  // Keywords (AND, OR, NOT, IN, CONTAINS, LIKE, STARTSWITH, ENDSWITH, INTERVAL)
  if (stream.match(/^(AND|OR|NOT|IN|CONTAINS|LIKE|STARTSWITH|ENDSWITH|INTERVAL)\b/i)) {
    return 'keyword';
  }

  // Boolean and enum values (true/false, sort order, join types, anomaly methods, window types, interval units)
  if (stream.match(/^(true|false|asc|desc|inner|left|outer|zscore|mad|sliding|tumbling|microseconds?|milliseconds?|seconds?|minutes?|hours?|days?|weeks?|months?|years?)\b/i)) {
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

  // Identifiers (check against known sets). Dots are included so OCSF promoted
  // columns (`src_endpoint.ip`, `actor.user.name`) tokenize as a single field
  // and match the registered schema set (NAN-1241); bare UDM names are unaffected.
  // Save current position to get the matched string
  const startPos = stream.pos;
  if (stream.match(/^[a-zA-Z_][a-zA-Z0-9_.]*/)) {
    // Get the matched word by extracting from the string
    const word = stream.string.slice(startPos, stream.pos);
    const wordLower = word.toLowerCase();

    // Pipe commands
    if (PIPE_COMMANDS_SET.has(wordLower)) {
      return 'function(variableName)';
    }

    // Command parameters (including step1, step2, etc. for tree command)
    if (COMMAND_PARAMS_SET.has(wordLower) || TREE_STEP_PATTERN.test(word)) {
      return 'propertyName';
    }

    // Eval functions (case-insensitive)
    if (EVAL_FUNCTIONS_SET.has(word) || EVAL_FUNCTIONS_SET.has(wordLower)) {
      return 'function(variableName)';
    }

    // UDM field names (direct columns or UDM schema fields accessible via ext.*)
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

  // Commas
  if (stream.match(/^,/)) {
    return 'punctuation';
  }

  // Colon
  if (stream.match(/^:/)) {
    return 'punctuation';
  }

  // Default: consume one character
  stream.next();
  return null;
}

/**
 * Tag mappings for the highlighting (match with codemirror-theme.ts)
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
 * StreamLanguage instance for detection rules
 */
export const detectionLanguage = StreamLanguage.define({
  ...detectionLanguageDefinition,
  tokenTable,
});

/**
 * Helper to determine if a position is in the YAML section
 */
export function isInYamlSection(doc: string, pos: number): boolean {
  const textBefore = doc.substring(0, pos);
  const firstDelim = textBefore.indexOf('---');
  if (firstDelim === -1) return false;

  const secondDelim = textBefore.indexOf('---', firstDelim + 3);
  return secondDelim === -1 || pos <= secondDelim + 3;
}

/**
 * Helper to get the YAML field name at cursor position
 */
export function getYamlFieldAtPosition(doc: string, pos: number): string | null {
  if (!isInYamlSection(doc, pos)) return null;

  const lines = doc.substring(0, pos).split('\n');
  const currentLine = lines[lines.length - 1];
  const match = currentLine.match(/^(\w+):/);

  return match ? match[1] : null;
}

/**
 * Check if a YAML field has autocomplete available
 */
export function hasYamlAutocomplete(fieldName: string): boolean {
  return YAML_AUTOCOMPLETE_FIELDS.has(fieldName);
}

export default detectionLanguage;
