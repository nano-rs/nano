// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Syntax highlighter for nanosiem query language
 * Tokenizes and highlights detection/search queries
 */

import * as React from 'react';
import { UDM_COLUMNS } from './udm-fields';
import {
  QUERY_KEYWORDS_PATTERN,
  PIPE_COMMANDS_PATTERN,
  COMMAND_PARAMS_PATTERN,
  EVAL_FUNCTIONS_PATTERN,
  BOOLEAN_VALUES_PATTERN,
  ENRICHED_FIELDS_SET,
  IOC_FIELDS_SET,
  COMPUTED_FIELDS_SET,
  FIELD_ALIASES_SET,
} from './query-tokens';

/** Token types produced by the query tokenizer */
export type TokenType =
  | 'text' | 'comment' | 'string' | 'regex' | 'regex-delim' | 'regex-content'
  | 'wildcard' | 'keyword' | 'function' | 'eval-function' | 'udm-field'
  | 'field' | 'operator' | 'arithmetic' | 'number' | 'param' | 'time-window' | 'boolean';

/** A single token from the query tokenizer */
export interface Token {
  type: TokenType;
  value: string;
}

// Combined set for syntax highlighting (UDM + enriched + IOC + computed + aliases)
const UDM_FIELD_NAMES = new Set([...UDM_COLUMNS, ...ENRICHED_FIELDS_SET, ...IOC_FIELDS_SET, ...COMPUTED_FIELDS_SET, ...FIELD_ALIASES_SET]);

// Required YAML fields - show indicator when empty
const REQUIRED_YAML_FIELDS = new Set(['title', 'description', 'author', 'severity', 'mitre_tactics', 'mitre_techniques']);

// Format hints for fields when empty
const FIELD_HINTS: Record<string, string> = {
  tags: 'e.g. tag1, tag2',
  mitre_tactics: 'e.g. TA0001, TA0002',
  mitre_techniques: 'e.g. T1059, T1078',
};

export function highlightYaml(yaml: string): string {
  const lines = yaml.split('\n');
  return lines.map(line => {
    // YAML key: value pairs
    const keyValueMatch = line.match(/^(\s*)([a-z_]+):\s*(.*)$/);
    if (keyValueMatch) {
      const [, indent, key, value] = keyValueMatch;
      const isRequired = REQUIRED_YAML_FIELDS.has(key);
      const isEmpty = !value.trim();
      const keyHtml = `<span style="color:var(--syntax-field);font-weight:500">${escapeHtml(key)}</span>`;
      const valueHtml = highlightYamlValue(value, key);

      // Show hint or "required" indicator for empty fields
      let hint = '';
      if (isEmpty) {
        if (isRequired) {
          const formatHint = FIELD_HINTS[key];
          hint = formatHint
            ? `<span style="color:var(--syntax-comment);font-style:italic;opacity:0.7"> required (${formatHint})</span>`
            : '<span style="color:var(--syntax-comment);font-style:italic;opacity:0.7"> required</span>';
        } else if (FIELD_HINTS[key]) {
          hint = `<span style="color:var(--syntax-comment);font-style:italic;opacity:0.5"> ${FIELD_HINTS[key]}</span>`;
        }
      }
      return `${indent}${keyHtml}: ${valueHtml}${hint}`;
    }
    return escapeHtml(line);
  }).join('\n');
}

function highlightYamlValue(value: string, key?: string): string {
  // Fields that have autocomplete dropdowns
  // NOTE: risk_score and risk_entity removed - now set in-query using | risk command
  const autocompleteFields = ['severity', 'mode', 'detection_mode', 'alert_mode', 'mitre_tactics', 'mitre_techniques'];
  const hasAutocomplete = key && autocompleteFields.includes(key);
  
  // Add dotted underline style for autocomplete fields
  const underlineStyle = hasAutocomplete ? 'border-bottom:1px dotted var(--syntax-field);cursor:pointer;' : '';
  
  // Numbers
  if (/^\d+$/.test(value)) {
    return `<span style="color:var(--syntax-number);${underlineStyle}">${escapeHtml(value)}</span>`;
  }
  // Keywords (auto, auto-detect, etc)
  if (/^(auto|auto-detect|staging|live|alerting|paused|realtime|scheduled|critical|high|medium|low|grouped|per_event)$/.test(value)) {
    return `<span style="color:var(--syntax-function);font-weight:500;${underlineStyle}">${escapeHtml(value)}</span>`;
  }
  // Cron expressions (contains * or / with numbers)
  if (/[\*\/]/.test(value) && /\d/.test(value)) {
    return `<span style="color:var(--syntax-pipe)">${escapeHtml(value)}</span>`;
  }
  // Regular text
  return `<span style="color:var(--foreground);${underlineStyle}">${escapeHtml(value)}</span>`;
}

/** Escape HTML special characters to prevent XSS */
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Tokenize a query string into an array of tokens.
 * This is the core tokenization logic used by both the HTML and React renderers.
 */
export function tokenizeQuery(code: string): Token[] {
  if (!code) return [];

  const tokens: Token[] = [];
  let remaining = code;

  // Use static UDM field names for syntax highlighting
  const udmFieldNames = UDM_FIELD_NAMES;

  // Create a regex pattern for all UDM fields
  const udmFieldPattern = new RegExp(`^(${Array.from(udmFieldNames).join('|')})\\b`);

  while (remaining.length > 0) {
    // Block comments /* */
    const blockCommentMatch = remaining.match(/^\/\*[\s\S]*?\*\//);
    if (blockCommentMatch) {
      tokens.push({ type: 'comment', value: blockCommentMatch[0] });
      remaining = remaining.slice(blockCommentMatch[0].length);
      continue;
    }

    // Line comments //
    const commentMatch = remaining.match(/^\/\/.*/);
    if (commentMatch) {
      tokens.push({ type: 'comment', value: commentMatch[0] });
      remaining = remaining.slice(commentMatch[0].length);
      continue;
    }

    // Regex patterns /pattern/ - match after = or != operators
    const lastNonWsToken = tokens.slice().reverse().find(t => t.type !== 'text' || !/^\s+$/.test(t.value));
    const canBeRegex = lastNonWsToken && (
      lastNonWsToken.value === '=' ||
      lastNonWsToken.value === '!=' ||
      lastNonWsToken.value === '~' ||
      lastNonWsToken.value === '=~'
    );

    if (remaining.startsWith('/') && !remaining.startsWith('//')) {
      if (canBeRegex) {
        const regexMatch = remaining.match(/^\/(?:[^/\\\n]|\\.)+\//);
        if (regexMatch) {
          const fullMatch = regexMatch[0];
          const content = fullMatch.slice(1, -1);
          tokens.push({ type: 'regex-delim', value: '/' });
          tokens.push({ type: 'regex-content', value: content });
          tokens.push({ type: 'regex-delim', value: '/' });
          remaining = remaining.slice(fullMatch.length);
          continue;
        }
      }
    }

    // Wildcard patterns *keyword*
    const wildcardMatch = remaining.match(/^\*[^*\s]+\*/);
    if (wildcardMatch) {
      tokens.push({ type: 'wildcard', value: wildcardMatch[0] });
      remaining = remaining.slice(wildcardMatch[0].length);
      continue;
    }

    // Strings
    const stringMatch = remaining.match(/^"[^"]*"/);
    if (stringMatch) {
      tokens.push({ type: 'string', value: stringMatch[0] });
      remaining = remaining.slice(stringMatch[0].length);
      continue;
    }

    // Keywords and operators (AND, OR, NOT, IN, CONTAINS, etc.)
    const keywordMatch = remaining.match(QUERY_KEYWORDS_PATTERN);
    if (keywordMatch) {
      tokens.push({ type: 'keyword', value: keywordMatch[0] });
      remaining = remaining.slice(keywordMatch[0].length);
      continue;
    }

    // Pipe commands (stats, eval, where, etc.)
    const funcMatch = remaining.match(PIPE_COMMANDS_PATTERN);
    if (funcMatch) {
      tokens.push({ type: 'function', value: funcMatch[0] });
      remaining = remaining.slice(funcMatch[0].length);
      continue;
    }

    // Command parameters (enrich, window, span, limit, step1, step2, etc.)
    const paramMatch = remaining.match(COMMAND_PARAMS_PATTERN);
    if (paramMatch) {
      tokens.push({ type: 'param', value: paramMatch[0] });
      remaining = remaining.slice(paramMatch[0].length);
      continue;
    }

    // Time window values (24h, 7d, 30d, 1h, etc)
    const timeWindowMatch = remaining.match(/^\d+[hdms]\b/);
    if (timeWindowMatch) {
      tokens.push({ type: 'time-window', value: timeWindowMatch[0] });
      remaining = remaining.slice(timeWindowMatch[0].length);
      continue;
    }

    // Boolean and enum values
    const boolMatch = remaining.match(BOOLEAN_VALUES_PATTERN);
    if (boolMatch) {
      tokens.push({ type: 'boolean', value: boolMatch[0] });
      remaining = remaining.slice(boolMatch[0].length);
      continue;
    }

    // Eval functions
    const evalFuncMatch = remaining.match(EVAL_FUNCTIONS_PATTERN);
    if (evalFuncMatch) {
      tokens.push({ type: 'eval-function', value: evalFuncMatch[0] });
      remaining = remaining.slice(evalFuncMatch[0].length);
      continue;
    }

    // Extension field patterns (ext_, enriched_, ioc_)
    const extFieldMatch = remaining.match(/^(ext|enriched|ioc)_[a-zA-Z_][a-zA-Z0-9_]*/);
    if (extFieldMatch) {
      tokens.push({ type: 'udm-field', value: extFieldMatch[0] });
      remaining = remaining.slice(extFieldMatch[0].length);
      continue;
    }

    // UDM field names
    const udmFieldMatch = remaining.match(udmFieldPattern);
    if (udmFieldMatch) {
      tokens.push({ type: 'udm-field', value: udmFieldMatch[0] });
      remaining = remaining.slice(udmFieldMatch[0].length);
      continue;
    }

    // Field prefixes
    const fieldMatch = remaining.match(/^(event|source|destination|network|host)\b/);
    if (fieldMatch) {
      tokens.push({ type: 'field', value: fieldMatch[0] });
      remaining = remaining.slice(fieldMatch[0].length);
      continue;
    }

    // Arithmetic operators
    const arithmeticMatch = remaining.match(/^(\+|-|\*|\/|%|\.)/);
    if (arithmeticMatch) {
      tokens.push({ type: 'arithmetic', value: arithmeticMatch[0] });
      remaining = remaining.slice(arithmeticMatch[0].length);
      continue;
    }

    // Comparison and logical operators
    const opMatch = remaining.match(/^(!=|>=|<=|=|~|>|<|\|)/);
    if (opMatch) {
      tokens.push({ type: 'operator', value: opMatch[0] });
      remaining = remaining.slice(opMatch[0].length);
      continue;
    }

    // Numbers
    const numMatch = remaining.match(/^\d+(\.\d+)?/);
    if (numMatch) {
      tokens.push({ type: 'number', value: numMatch[0] });
      remaining = remaining.slice(numMatch[0].length);
      continue;
    }

    // Whitespace
    const wsMatch = remaining.match(/^[ \t]+/);
    if (wsMatch) {
      tokens.push({ type: 'text', value: wsMatch[0] });
      remaining = remaining.slice(wsMatch[0].length);
      continue;
    }

    // Newlines
    if (remaining[0] === '\n') {
      tokens.push({ type: 'text', value: '\n' });
      remaining = remaining.slice(1);
      continue;
    }

    // Identifiers and other text
    const identMatch = remaining.match(/^[\w.:_-]+/);
    if (identMatch) {
      tokens.push({ type: 'text', value: identMatch[0] });
      remaining = remaining.slice(identMatch[0].length);
      continue;
    }

    // Single character fallback
    tokens.push({ type: 'text', value: remaining[0] });
    remaining = remaining.slice(1);
  }

  return tokens;
}

/** Get the inline style for a token type */
function getTokenStyle(token: Token): React.CSSProperties {
  const colors: Record<string, string> = {
    comment: 'var(--syntax-comment)',
    string: 'var(--syntax-string)',
    regex: 'var(--syntax-regex)',
    'regex-delim': 'var(--syntax-regex-delim, var(--syntax-operator))',
    'regex-content': 'var(--syntax-regex)',
    wildcard: 'var(--syntax-wildcard)',
    keyword: 'var(--syntax-keyword)',
    function: 'var(--syntax-function)',
    'eval-function': 'var(--syntax-eval-function)',
    'udm-field': 'var(--syntax-udm-field)',
    field: 'var(--syntax-field)',
    operator: 'var(--syntax-operator)',
    arithmetic: 'var(--syntax-arithmetic)',
    number: 'var(--syntax-number)',
    param: 'var(--syntax-param, var(--syntax-field))',
    'time-window': 'var(--syntax-time-window, var(--syntax-number))',
    boolean: 'var(--syntax-boolean, var(--syntax-keyword))',
  };

  if (token.type === 'text') return {};

  const color = colors[token.type];

  switch (token.type) {
    case 'keyword':
      return { color, fontWeight: 600 };
    case 'operator':
      if (token.value === '|') {
        return { color: 'var(--syntax-pipe)', fontWeight: 700 };
      }
      return { color };
    case 'comment':
      return { color, fontStyle: 'italic' };
    case 'regex':
      return { color, fontWeight: 500, background: 'var(--syntax-regex-bg)' };
    case 'regex-delim':
      return { color, fontWeight: 600 };
    case 'regex-content':
      return { color, fontWeight: 500, background: 'var(--syntax-regex-bg)' };
    case 'wildcard':
      return { color, fontWeight: 500, background: 'var(--syntax-wildcard-bg)' };
    case 'udm-field':
      return { color, fontWeight: 600 };
    case 'eval-function':
    case 'param':
    case 'time-window':
      return { color, fontWeight: 500 };
    case 'boolean':
      return { color, fontWeight: 600 };
    default:
      return { color };
  }
}

/**
 * React component for rendering syntax-highlighted query code.
 * This is the safe alternative to dangerouslySetInnerHTML.
 */
export function QueryHighlight({ code, className }: { code: string; className?: string }): React.ReactElement {
  if (!code) {
    return React.createElement('span', { className: 'text-muted-foreground' }, 'No query defined');
  }

  // Check if this is YAML frontmatter format
  const yamlMatch = code.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (yamlMatch) {
    const yamlSection = yamlMatch[1];
    const querySection = yamlMatch[2];

    return React.createElement('span', { className }, [
      React.createElement('span', { key: 'yaml-start', style: { color: '#6b7280' } }, '---'),
      '\n',
      React.createElement(YamlHighlight, { key: 'yaml', code: yamlSection }),
      '\n',
      React.createElement('span', { key: 'yaml-end', style: { color: '#6b7280' } }, '---'),
      '\n',
      React.createElement(QueryTokensHighlight, { key: 'query', tokens: tokenizeQuery(querySection) }),
    ]);
  }

  const tokens = tokenizeQuery(code);
  return React.createElement('span', { className },
    React.createElement(QueryTokensHighlight, { tokens })
  );
}

/** Render tokenized query as React elements */
function QueryTokensHighlight({ tokens }: { tokens: Token[] }): React.ReactElement {
  return React.createElement(React.Fragment, null,
    tokens.map((token, i) => {
      if (token.type === 'text') {
        return React.createElement(React.Fragment, { key: i }, token.value);
      }
      return React.createElement('span', { key: i, style: getTokenStyle(token) }, token.value);
    })
  );
}

/** Render YAML section as React elements */
function YamlHighlight({ code }: { code: string }): React.ReactElement {
  const REQUIRED_YAML_FIELDS = new Set(['title', 'description', 'author', 'severity', 'mitre_tactics', 'mitre_techniques']);
  const FIELD_HINTS: Record<string, string> = {
    tags: 'e.g. tag1, tag2',
    mitre_tactics: 'e.g. TA0001, TA0002',
    mitre_techniques: 'e.g. T1059, T1078',
  };

  const lines = code.split('\n');
  return React.createElement(React.Fragment, null,
    lines.map((line, lineIdx) => {
      const keyValueMatch = line.match(/^(\s*)([a-z_]+):\s*(.*)$/);
      if (keyValueMatch) {
        const [, indent, key, value] = keyValueMatch;
        const isRequired = REQUIRED_YAML_FIELDS.has(key);
        const isEmpty = !value.trim();

        const elements: React.ReactNode[] = [
          indent,
          React.createElement('span', { key: 'key', style: { color: 'var(--syntax-field)', fontWeight: 500 } }, key),
          ': ',
          React.createElement(YamlValueHighlight, { key: 'value', value, fieldKey: key }),
        ];

        if (isEmpty) {
          if (isRequired) {
            const formatHint = FIELD_HINTS[key];
            elements.push(
              React.createElement('span', {
                key: 'hint',
                style: { color: 'var(--syntax-comment)', fontStyle: 'italic', opacity: 0.7 }
              }, formatHint ? ` required (${formatHint})` : ' required')
            );
          } else if (FIELD_HINTS[key]) {
            elements.push(
              React.createElement('span', {
                key: 'hint',
                style: { color: 'var(--syntax-comment)', fontStyle: 'italic', opacity: 0.5 }
              }, ` ${FIELD_HINTS[key]}`)
            );
          }
        }

        return React.createElement(React.Fragment, { key: lineIdx }, [
          ...elements,
          lineIdx < lines.length - 1 ? '\n' : null
        ]);
      }
      return React.createElement(React.Fragment, { key: lineIdx }, [
        line,
        lineIdx < lines.length - 1 ? '\n' : null
      ]);
    })
  );
}

/** Render YAML value with appropriate styling */
function YamlValueHighlight({ value, fieldKey }: { value: string; fieldKey?: string }): React.ReactElement {
  const autocompleteFields = ['severity', 'mode', 'detection_mode', 'alert_mode', 'mitre_tactics', 'mitre_techniques'];
  const hasAutocomplete = fieldKey && autocompleteFields.includes(fieldKey);

  const baseStyle: React.CSSProperties = hasAutocomplete
    ? { borderBottom: '1px dotted var(--syntax-field)', cursor: 'pointer' }
    : {};

  // Numbers
  if (/^\d+$/.test(value)) {
    return React.createElement('span', { style: { ...baseStyle, color: 'var(--syntax-number)' } }, value);
  }
  // Keywords
  if (/^(auto|auto-detect|staging|live|alerting|paused|realtime|scheduled|critical|high|medium|low|grouped|per_event)$/.test(value)) {
    return React.createElement('span', { style: { ...baseStyle, color: 'var(--syntax-function)', fontWeight: 500 } }, value);
  }
  // Cron expressions
  if (/[\*\/]/.test(value) && /\d/.test(value)) {
    return React.createElement('span', { style: { color: 'var(--syntax-pipe)' } }, value);
  }
  // Regular text
  return React.createElement('span', { style: { ...baseStyle, color: 'var(--foreground)' } }, value);
}

/** Convert a token to an HTML style string */
function getTokenStyleString(token: Token): string {
  const colors: Record<string, string> = {
    comment: 'var(--syntax-comment)',
    string: 'var(--syntax-string)',
    regex: 'var(--syntax-regex)',
    'regex-delim': 'var(--syntax-regex-delim, var(--syntax-operator))',
    'regex-content': 'var(--syntax-regex)',
    wildcard: 'var(--syntax-wildcard)',
    keyword: 'var(--syntax-keyword)',
    function: 'var(--syntax-function)',
    'eval-function': 'var(--syntax-eval-function)',
    'udm-field': 'var(--syntax-udm-field)',
    field: 'var(--syntax-field)',
    operator: 'var(--syntax-operator)',
    arithmetic: 'var(--syntax-arithmetic)',
    number: 'var(--syntax-number)',
    param: 'var(--syntax-param, var(--syntax-field))',
    'time-window': 'var(--syntax-time-window, var(--syntax-number))',
    boolean: 'var(--syntax-boolean, var(--syntax-keyword))',
  };

  const color = colors[token.type];

  switch (token.type) {
    case 'keyword':
      return `color:${color};font-weight:600`;
    case 'operator':
      return token.value === '|' ? 'color:var(--syntax-pipe);font-weight:700' : `color:${color}`;
    case 'comment':
      return `color:${color};font-style:italic`;
    case 'regex':
      return `color:${color};font-weight:500;background:var(--syntax-regex-bg)`;
    case 'regex-delim':
      return `color:${color};font-weight:600`;
    case 'regex-content':
      return `color:${color};font-weight:500;background:var(--syntax-regex-bg)`;
    case 'wildcard':
      return `color:${color};font-weight:500;background:var(--syntax-wildcard-bg)`;
    case 'udm-field':
      return `color:${color};font-weight:600`;
    case 'eval-function':
    case 'param':
    case 'time-window':
      return `color:${color};font-weight:500`;
    case 'boolean':
      return `color:${color};font-weight:600`;
    default:
      return `color:${color}`;
  }
}

export function highlightQueryOnly(code: string): string {
  if (!code) return '';

  const tokens = tokenizeQuery(code);

  return tokens.map(t => {
    // Escape HTML but preserve spaces exactly
    const escaped = t.value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    if (t.type === 'text') return escaped;

    const style = getTokenStyleString(t);
    return `<span style="${style}">${escaped}</span>`;
  }).join('');
}

/**
 * Syntax highlighter for VRL (Vector Remap Language)
 * Used for parser configurations
 */
export function highlightVrl(code: string): string {
  if (!code) return '';
  
  const tokens: { type: string; value: string }[] = [];
  let remaining = code;
  
  while (remaining.length > 0) {
    // Line comments #
    const hashCommentMatch = remaining.match(/^#.*/);
    if (hashCommentMatch) {
      tokens.push({ type: 'comment', value: hashCommentMatch[0] });
      remaining = remaining.slice(hashCommentMatch[0].length);
      continue;
    }
    
    // Regex literals r'...' or r"..."
    const regexMatch = remaining.match(/^r(['"])((?:\\.|(?!\1)[^\\])*)\1/);
    if (regexMatch) {
      tokens.push({ type: 'regex', value: regexMatch[0] });
      remaining = remaining.slice(regexMatch[0].length);
      continue;
    }
    
    // Strings (double or single quoted)
    const stringMatch = remaining.match(/^"(?:[^"\\]|\\.)*"|^'(?:[^'\\]|\\.)*'/);
    if (stringMatch) {
      tokens.push({ type: 'string', value: stringMatch[0] });
      remaining = remaining.slice(stringMatch[0].length);
      continue;
    }
    
    // Keywords
    const keywordMatch = remaining.match(/^(if|else|for|while|break|continue|return|null|true|false|abort)\b/);
    if (keywordMatch) {
      tokens.push({ type: 'keyword', value: keywordMatch[0] });
      remaining = remaining.slice(keywordMatch[0].length);
      continue;
    }
    
    // VRL built-in functions
    const funcMatch = remaining.match(/^(parse_regex|parse_json|parse_syslog|parse_timestamp|parse_key_value|parse_csv|parse_grok|parse_xml|to_string|to_int|to_float|to_bool|to_timestamp|to_unix_timestamp|now|format_timestamp|contains|starts_with|ends_with|match|replace|upcase|downcase|strip_whitespace|split|join|push|append|del|exists|is_string|is_int|is_float|is_bool|is_null|is_array|is_object|encode_json|decode_base64|encode_base64|sha256|md5|uuid_v4|get_env_var|log|assert|err|ok|compact|flatten|keys|values|length|slice|merge|set|get|type_of|ip_cidr_contains|ip_to_ipv6|ipv6_to_ipv4|community_id|redact|strip_ansi_escape_codes|ceil|floor|round|abs|mod|random_bytes)\b/);
    if (funcMatch) {
      tokens.push({ type: 'function', value: funcMatch[0] });
      remaining = remaining.slice(funcMatch[0].length);
      continue;
    }
    
    // Field access starting with .
    const fieldMatch = remaining.match(/^\.[a-zA-Z_][a-zA-Z0-9_]*/);
    if (fieldMatch) {
      tokens.push({ type: 'field', value: fieldMatch[0] });
      remaining = remaining.slice(fieldMatch[0].length);
      continue;
    }
    
    // Operators
    const opMatch = remaining.match(/^(!=|==|>=|<=|&&|\|\||=>|=|>|<|\+|-|\*|\/|%|\?{1,2}|!)/);
    if (opMatch) {
      tokens.push({ type: 'operator', value: opMatch[0] });
      remaining = remaining.slice(opMatch[0].length);
      continue;
    }
    
    // Numbers
    const numMatch = remaining.match(/^\d+(\.\d+)?/);
    if (numMatch) {
      tokens.push({ type: 'number', value: numMatch[0] });
      remaining = remaining.slice(numMatch[0].length);
      continue;
    }
    
    // Brackets and braces
    const bracketMatch = remaining.match(/^[{}[\]()]/);
    if (bracketMatch) {
      tokens.push({ type: 'bracket', value: bracketMatch[0] });
      remaining = remaining.slice(bracketMatch[0].length);
      continue;
    }
    
    // Whitespace - preserve exactly
    const wsMatch = remaining.match(/^[ \t]+/);
    if (wsMatch) {
      tokens.push({ type: 'text', value: wsMatch[0] });
      remaining = remaining.slice(wsMatch[0].length);
      continue;
    }
    
    // Newlines
    if (remaining[0] === '\n') {
      tokens.push({ type: 'text', value: '\n' });
      remaining = remaining.slice(1);
      continue;
    }
    
    // Identifiers
    const identMatch = remaining.match(/^[a-zA-Z_][a-zA-Z0-9_]*/);
    if (identMatch) {
      tokens.push({ type: 'identifier', value: identMatch[0] });
      remaining = remaining.slice(identMatch[0].length);
      continue;
    }
    
    // Single character fallback
    tokens.push({ type: 'text', value: remaining[0] });
    remaining = remaining.slice(1);
  }
  
  // VRL color scheme - using CSS variables for theme support
  const colors: Record<string, string> = {
    comment: 'var(--syntax-comment)',
    string: 'var(--syntax-string)',
    regex: 'var(--syntax-regex)',
    keyword: 'var(--syntax-keyword)',
    function: 'var(--syntax-function)',
    field: 'var(--syntax-field)',
    operator: 'var(--syntax-operator)',
    number: 'var(--syntax-number)',
    bracket: 'var(--syntax-pipe)',
    identifier: 'var(--foreground)',
  };
  
  return tokens.map(t => {
    const escaped = t.value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    if (t.type === 'text') return escaped;

    const style = t.type === 'keyword' ? `color:${colors[t.type]};font-weight:600`
                : t.type === 'comment' ? `color:${colors[t.type]};font-style:italic`
                : t.type === 'field' ? `color:${colors[t.type]};font-weight:500`
                : `color:${colors[t.type]}`;
    return `<span style="${style}">${escaped}</span>`;
  }).join('');
}

/**
 * Syntax highlighter for VRL with line numbers
 * Used for parser configurations in the editor view
 */
export function highlightVrlWithLineNumbers(code: string): string {
  if (!code) return '<span style="color:#6b7280"># No VRL code</span>';

  const lines = code.split('\n');
  const lineCount = lines.length;
  const gutterWidth = String(lineCount).length;

  return lines.map((line, idx) => {
    const lineNum = idx + 1;
    const paddedNum = String(lineNum).padStart(gutterWidth, ' ');
    const highlightedLine = highlightVrl(line) || ' '; // Use space for empty lines to maintain height

    return `<div style="display:flex;"><span style="color:#4b5563;user-select:none;padding-right:1em;text-align:right;min-width:${gutterWidth + 1}ch;">${paddedNum}</span><span style="flex:1;">${highlightedLine}</span></div>`;
  }).join('');
}
