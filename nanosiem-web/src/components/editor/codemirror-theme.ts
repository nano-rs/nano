// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * CodeMirror 6 theme for detection rule editor
 * Maps existing CSS variables to CodeMirror styling
 */
import { EditorView } from '@codemirror/view';
import { Extension } from '@codemirror/state';
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { tags } from '@lezer/highlight';

/**
 * Base editor theme using CSS variables
 */
export const editorTheme = EditorView.theme({
  '&': {
    height: '100%',
    // Mock: `font-mono text-[12.5px] leading-[1.7]` — denser than the 14px
    // default and matches the design-ref/shadcn/editor-code.jsx reference.
    fontSize: '12.5px',
    lineHeight: '1.7',
    fontFamily: '"Geist Mono", Menlo, Courier, monospace',
    backgroundColor: 'var(--background)',
  },
  '.cm-scroller': {
    backgroundColor: 'var(--background)',
    // Override default leading that scroller inherits so long lines track
    // the tighter 1.7 rhythm.
    lineHeight: '1.7',
  },
  '.cm-content': {
    padding: '10px 0',
    caretColor: 'var(--foreground)',
  },
  '.cm-cursor': {
    borderLeftColor: 'var(--foreground)',
    borderLeftWidth: '2px',
  },
  '.cm-selectionBackground, &.cm-focused .cm-selectionBackground': {
    backgroundColor: 'var(--primary)',
    opacity: '0.3',
  },
  '.cm-activeLine': {
    backgroundColor: 'oklch(from var(--muted) l c h / 0.35)',
  },
  '.cm-gutters': {
    backgroundColor: 'var(--background)',
    // Mock uses `border-r border-border/40` — softer divider between the
    // gutter and the code column. Keep it 1px but alpha-blended.
    borderRight: '1px solid color-mix(in srgb, var(--border) 60%, transparent)',
    color: 'var(--muted-foreground)',
    // Nudge gutter numbers slightly smaller to match mock (11px vs 12.5px body).
    fontSize: '11px',
  },
  '.cm-lineNumbers .cm-gutterElement': {
    // Padded on the left so digits don't hug the panel edge; tight right
    // padding keeps the gap to the code small.
    boxSizing: 'border-box',
    padding: '0 4px 0 10px',
    minWidth: '28px',
    textAlign: 'right',
    color: 'color-mix(in srgb, var(--muted-foreground) 70%, transparent)',
  },
  '.cm-activeLineGutter': {
    backgroundColor: 'oklch(from var(--muted) l c h / 0.35)',
    color: 'var(--foreground)',
  },
  // Breathing room so code doesn't hug the gutter divider.
  '.cm-line': {
    padding: '0 6px 0 10px',
  },
  // Lint gutter hosts validation markers. 10px fits the info/warn icons
  // with a hairline of breathing room on each side.
  '.cm-gutter-lint': {
    width: '10px',
    minWidth: '10px',
  },
  '.cm-gutter-lint .cm-gutterElement': {
    padding: '0',
  },
  // Autocomplete popup styling
  '.cm-tooltip': {
    backgroundColor: 'var(--popover)',
    border: '1px solid var(--border)',
    borderRadius: '8px',
    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
  },
  '.cm-tooltip.cm-tooltip-autocomplete': {
    '& > ul': {
      fontFamily: '"Geist Mono", Menlo, Courier, monospace',
      fontSize: '13px',
      maxHeight: '300px',
    },
    '& > ul > li': {
      padding: '6px 12px',
      color: 'var(--foreground)',
    },
    '& > ul > li[aria-selected]': {
      backgroundColor: 'var(--primary)',
      color: 'var(--primary-foreground)',
      '& .cm-completionDetail': {
        color: 'rgba(255, 255, 255, 0.8)',
      },
      '& .cm-completionIcon': {
        color: 'rgba(255, 255, 255, 0.7)',
      },
    },
  },
  '.cm-completionLabel': {
    fontWeight: '500',
  },
  '.cm-completionIcon': {
    color: 'var(--muted-foreground)',
    opacity: '1',
  },
  '.cm-completionIcon-constant': {
    color: 'var(--syntax-keyword)',
  },
  '.cm-completionIcon-property': {
    color: 'var(--syntax-field)',
  },
  '.cm-completionIcon-function': {
    color: 'var(--syntax-function)',
  },
  '.cm-completionIcon-enum': {
    color: 'var(--syntax-string)',
  },
  '.cm-completionDetail': {
    marginLeft: '8px',
    color: 'var(--muted-foreground)',
    fontSize: '12px',
  },
  // Note: Lint range styling is in index.css for proper CSS specificity
  '.cm-diagnostic': {
    padding: '8px 12px',
    borderRadius: '6px',
    fontSize: '12px',
    maxWidth: '350px',
    lineHeight: '1.4',
  },
  '.cm-diagnostic-error': {
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderLeft: '3px solid var(--destructive)',
  },
  '.cm-diagnostic-warning': {
    backgroundColor: 'rgba(245, 158, 11, 0.1)',
    borderLeft: '3px solid var(--chart-3)',
  },
  '.cm-diagnostic-info': {
    backgroundColor: 'rgba(59, 130, 246, 0.08)',
    borderLeft: '3px solid var(--primary)',
    color: 'var(--muted-foreground)',
  },
  // Panel styling
  '.cm-panels': {
    backgroundColor: 'var(--card)',
    borderTop: '1px solid var(--border)',
  },
  // Search/replace panel
  '.cm-searchMatch': {
    backgroundColor: 'rgba(250, 204, 21, 0.5)',
  },
  '.cm-searchMatch.cm-searchMatch-selected': {
    backgroundColor: 'rgba(250, 204, 21, 0.75)',
  },
  // Search/replace panel
  '.cm-panel.cm-search': {
    backgroundColor: 'var(--card)',
    borderTop: '1px solid var(--border)',
    color: 'var(--foreground)',
  },
  '.cm-panel.cm-search label': {
    color: 'var(--muted-foreground)',
  },
  '.cm-panel.cm-search button': {
    backgroundImage: 'none',
    backgroundColor: 'var(--accent)',
    color: 'var(--accent-foreground)',
    border: '1px solid var(--border)',
    borderRadius: '4px',
    padding: '2px 8px',
  },
  '.cm-panel.cm-search input, .cm-panel.cm-search .cm-textfield': {
    backgroundColor: 'var(--input)',
    color: 'var(--foreground)',
    border: '1px solid var(--border)',
    borderRadius: '4px',
  },
  // Placeholder values (faded, click to clear)
  '.cm-placeholder-value': {
    opacity: '0.5',
    fontStyle: 'italic',
    cursor: 'pointer',
    '&:hover': {
      opacity: '0.7',
      textDecoration: 'line-through',
    },
  },
  // Empty field hints (ghost text showing available options)
  '.cm-empty-field-hint': {
    color: 'var(--muted-foreground)',
    opacity: '0.6',
    fontStyle: 'italic',
    marginLeft: '4px',
  },
  '.cm-hint-separator': {
    opacity: '0.4',
  },
  '.cm-hint-option': {
    cursor: 'pointer',
    padding: '1px 4px',
    borderRadius: '3px',
    transition: 'all 0.15s',
    '&:hover': {
      opacity: '1',
      backgroundColor: 'var(--primary)',
      color: 'var(--primary-foreground)',
      fontStyle: 'normal',
    },
  },
});

/**
 * Syntax highlighting using CSS variables
 */
export const syntaxTheme = HighlightStyle.define([
  // Comments
  { tag: tags.comment, color: 'var(--syntax-comment)', fontStyle: 'italic' },
  { tag: tags.lineComment, color: 'var(--syntax-comment)', fontStyle: 'italic' },
  { tag: tags.blockComment, color: 'var(--syntax-comment)', fontStyle: 'italic' },

  // Strings
  { tag: tags.string, color: 'var(--syntax-string)' },
  { tag: tags.character, color: 'var(--syntax-string)' },

  // Numbers
  { tag: tags.number, color: 'var(--syntax-number)' },
  { tag: tags.integer, color: 'var(--syntax-number)' },
  { tag: tags.float, color: 'var(--syntax-number)' },

  // Keywords (stats, where, by, as)
  { tag: tags.keyword, color: 'var(--syntax-keyword)', fontWeight: '600' },
  { tag: tags.modifier, color: 'var(--syntax-keyword)', fontWeight: '600' },
  // Operator-keywords are compound — CONTAINS / OR / AND / NOT / IN / LIKE /
  // REGEX. Per the mock these render in the warn/amber tone to separate them
  // from the cyan structural keywords.
  { tag: tags.operatorKeyword, color: 'var(--syntax-operator)', fontWeight: '600' },

  // Functions (pipe commands — count, values, min, max)
  { tag: tags.function(tags.variableName), color: 'var(--syntax-function)', fontWeight: '500' },
  { tag: tags.standard(tags.variableName), color: 'var(--syntax-function)', fontWeight: '500' },

  // Operators
  { tag: tags.operator, color: 'var(--syntax-operator)' },
  { tag: tags.compareOperator, color: 'var(--syntax-operator)' },
  { tag: tags.arithmeticOperator, color: 'var(--syntax-arithmetic)' },
  // AND / OR / NOT — same amber as operatorKeyword so all logic reads as one
  // visual family (matches mock).
  { tag: tags.logicOperator, color: 'var(--syntax-operator)', fontWeight: '600' },

  // Punctuation keeps the muted gutter tone; separator is the pipe — the
  // single loudest structural token in a pipe language, so bright cyan bold.
  { tag: tags.punctuation, color: 'var(--muted-foreground)' },
  { tag: tags.separator, color: 'var(--syntax-pipe)', fontWeight: '700' },

  // Special tokens
  { tag: tags.regexp, color: 'var(--syntax-regex)', fontWeight: '500' },
  { tag: tags.escape, color: 'var(--syntax-regex)' },
  { tag: tags.special(tags.string), color: 'var(--syntax-wildcard)', fontWeight: '500' },

  // Properties/fields
  { tag: tags.propertyName, color: 'var(--syntax-field)', fontWeight: '500' },
  { tag: tags.definition(tags.propertyName), color: 'var(--syntax-field)', fontWeight: '500' },
  { tag: tags.special(tags.propertyName), color: 'var(--syntax-udm-field)', fontWeight: '600' },

  // Variables
  { tag: tags.variableName, color: 'var(--foreground)' },
  { tag: tags.definition(tags.variableName), color: 'var(--foreground)' },

  // Boolean — amber per the mock (true/false ride the `warn` palette).
  { tag: tags.bool, color: 'var(--syntax-number)', fontWeight: '600' },

  // Labels — YAML keys. Light cyan to match the mock's TOK.key palette.
  { tag: tags.labelName, color: 'var(--syntax-field)', fontWeight: '500' },

  // Null
  { tag: tags.null, color: 'var(--syntax-keyword)' },

  // Types
  { tag: tags.typeName, color: 'var(--syntax-function)' },
  { tag: tags.className, color: 'var(--syntax-function)' },

  // Atoms (for special values like auto, realtime, etc.)
  { tag: tags.atom, color: 'var(--syntax-function)', fontWeight: '500' },

  // Invalid syntax
  { tag: tags.invalid, color: 'var(--destructive)', textDecoration: 'underline wavy' },
]);

/**
 * Combined theme extension
 */
export const detectionTheme: Extension = [
  editorTheme,
  syntaxHighlighting(syntaxTheme),
];

export default detectionTheme;
