// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * CodeMirror theme for the search bar input
 * Matches the existing textarea styling for visual parity
 */
import { EditorView } from '@codemirror/view';
import { Extension, Compartment } from '@codemirror/state';
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { tags } from '@lezer/highlight';

/**
 * Base search bar theme - matches the textarea styling
 * Font: 14px monospace
 * Padding: 11px vertical, 12px horizontal
 * Line height: 22px
 * Min height: 44px, max height: 200px
 */
export const searchBarTheme = EditorView.theme({
  '&': {
    fontSize: '13px',
    fontFamily: '"Geist Mono", Menlo, Courier, monospace',
    backgroundColor: 'transparent',
    maxHeight: 'inherit',
  },
  '&.cm-focused': {
    outline: 'none',
  },
  '.cm-scroller': {
    backgroundColor: 'transparent',
    overflow: 'auto',
    maxHeight: 'inherit',
  },
  '.cm-content': {
    padding: '7px 12px',
    caretColor: 'var(--foreground)',
    minHeight: '19px',
  },
  '.cm-cursor': {
    borderLeftColor: 'var(--foreground)',
    borderLeftWidth: '2px',
  },
  '.cm-selectionBackground, &.cm-focused .cm-selectionBackground': {
    backgroundColor: 'oklch(from var(--primary) l c h / 0.3)',
  },
  '.cm-line': {
    padding: '0',
    lineHeight: '19px',
  },
  '.cm-placeholder': {
    color: 'var(--muted-foreground)',
  },
  // Hide gutters for search bar
  '.cm-gutters': {
    display: 'none',
  },
});

/**
 * Query syntax highlighting using CSS variables
 * Matches the existing syntax highlighting
 */
export const searchBarSyntaxTheme = HighlightStyle.define([
  // Comments
  { tag: tags.comment, color: 'var(--syntax-comment)', fontStyle: 'italic' },
  { tag: tags.lineComment, color: 'var(--syntax-comment)', fontStyle: 'italic' },
  { tag: tags.blockComment, color: 'var(--syntax-comment)', fontStyle: 'italic' },

  // Strings
  { tag: tags.string, color: 'var(--syntax-string)' },

  // Numbers
  { tag: tags.number, color: 'var(--syntax-number)' },

  // Keywords (AND, OR, NOT, SELECT, FROM, WHERE, etc.)
  { tag: tags.keyword, color: 'var(--syntax-keyword)', fontWeight: '600' },
  { tag: tags.operatorKeyword, color: 'var(--syntax-keyword)', fontWeight: '600' },

  // SQL-specific tags (used by @codemirror/lang-sql)
  { tag: tags.standard(tags.keyword), color: 'var(--syntax-keyword)', fontWeight: '600' },
  { tag: tags.typeName, color: 'var(--syntax-number)' },
  { tag: tags.null, color: 'var(--syntax-keyword)', fontStyle: 'italic' },

  // Functions (pipe commands)
  { tag: tags.function(tags.variableName), color: 'var(--syntax-function)', fontWeight: '500' },

  // Operators
  { tag: tags.operator, color: 'var(--syntax-operator)' },
  { tag: tags.compareOperator, color: 'var(--syntax-operator)' },
  { tag: tags.arithmeticOperator, color: 'var(--syntax-arithmetic)' },

  // Pipe character
  { tag: tags.separator, color: 'var(--syntax-pipe)', fontWeight: '700' },

  // Regex
  { tag: tags.regexp, color: 'var(--syntax-regex)', fontWeight: '500' },

  // Properties/fields
  { tag: tags.propertyName, color: 'var(--syntax-field)', fontWeight: '500' },
  { tag: tags.special(tags.propertyName), color: 'var(--syntax-udm-field)', fontWeight: '600' },

  // Variables
  { tag: tags.variableName, color: 'var(--foreground)' },

  // Boolean
  { tag: tags.bool, color: 'var(--syntax-keyword)', fontWeight: '600' },
]);

/**
 * Compartment for dynamically switching AI mode styling
 */
export const aiModeCompartment = new Compartment();

/**
 * Combined theme extension for normal mode
 */
export const searchBarExtensions: Extension = [
  searchBarTheme,
  syntaxHighlighting(searchBarSyntaxTheme),
];

export default searchBarExtensions;
