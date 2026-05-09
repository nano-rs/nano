// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Minimal CodeMirror editor for query input
 * Designed to look like a styled textarea with syntax highlighting
 * Used in dashboard panel editor and other places needing query input
 */
import React, { useRef, useEffect, useImperativeHandle, useCallback } from 'react';
import { EditorState, Extension, Compartment } from '@codemirror/state';
import { EditorView, keymap, placeholder as placeholderExt } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { bracketMatching } from '@codemirror/language';
import { closeBrackets, closeBracketsKeymap } from '@codemirror/autocomplete';
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { tags } from '@lezer/highlight';

import { queryLanguage } from './query-language';

/**
 * Editor ref methods
 */
export interface QueryEditorRef {
  focus: () => void;
  getValue: () => string;
  setValue: (value: string) => void;
}

/**
 * Editor props
 */
export interface QueryEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  readOnly?: boolean;
  className?: string;
  minHeight?: number;
  maxHeight?: number;
  /** Override the default 14px font size (e.g. 12 for a denser readout). */
  fontSize?: number;
  /** Called when Cmd/Ctrl+Enter is pressed */
  onSubmit?: () => void;
}

/**
 * Minimal editor theme - looks like a textarea
 */
const minimalTheme = EditorView.theme({
  '&': {
    // Per-instance override via inline `--cm-font-size` on the wrapper.
    fontSize: 'var(--cm-font-size, 14px)',
    fontFamily: '"Geist Mono", Menlo, Courier, monospace',
    backgroundColor: 'transparent',
  },
  '&.cm-focused': {
    outline: 'none',
  },
  '.cm-scroller': {
    backgroundColor: 'transparent',
    overflow: 'auto',
  },
  '.cm-content': {
    padding: '12px 16px',
    caretColor: 'var(--foreground)',
    minHeight: 'inherit',
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
  },
  '.cm-placeholder': {
    color: 'var(--muted-foreground)',
    fontStyle: 'italic',
  },
});

/**
 * Query syntax highlighting using CSS variables
 */
const querySyntaxTheme = HighlightStyle.define([
  // Comments
  { tag: tags.comment, color: 'var(--syntax-comment)', fontStyle: 'italic' },
  { tag: tags.lineComment, color: 'var(--syntax-comment)', fontStyle: 'italic' },

  // Strings
  { tag: tags.string, color: 'var(--syntax-string)' },

  // Numbers
  { tag: tags.number, color: 'var(--syntax-number)' },

  // Keywords (AND, OR, NOT)
  { tag: tags.keyword, color: 'var(--syntax-keyword)', fontWeight: '600' },
  { tag: tags.operatorKeyword, color: 'var(--syntax-keyword)', fontWeight: '600' },

  // Functions (pipe commands)
  { tag: tags.function(tags.variableName), color: 'var(--syntax-function)', fontWeight: '500' },

  // Operators
  { tag: tags.operator, color: 'var(--syntax-operator)' },
  { tag: tags.compareOperator, color: 'var(--syntax-operator)' },

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
 * Auto-height extension - grows editor to fit content
 */
function autoHeight(minHeight: number, maxHeight: number) {
  return EditorView.theme({
    '&': {
      minHeight: `${minHeight}px`,
      maxHeight: `${maxHeight}px`,
    },
    '.cm-scroller': {
      minHeight: `${minHeight}px`,
      maxHeight: `${maxHeight}px`,
    },
    '.cm-content': {
      minHeight: `${minHeight - 24}px`, // Account for padding
    },
  });
}

/**
 * Minimal CodeMirror Query Editor
 */
export function QueryEditor({
  value,
  onChange,
  placeholder = '',
  readOnly = false,
  className = '',
  minHeight = 80,
  maxHeight = 300,
  fontSize,
  onSubmit,
  ref,
}: QueryEditorProps & { ref?: React.Ref<QueryEditorRef> }) {
    const containerRef = useRef<HTMLDivElement>(null);
    const viewRef = useRef<EditorView | null>(null);
    const onChangeRef = useRef(onChange);
    const onSubmitRef = useRef(onSubmit);
    const isInternalChange = useRef(false);
    const readOnlyCompartment = useRef(new Compartment());

    // Keep refs updated
    useEffect(() => {
      onChangeRef.current = onChange;
      onSubmitRef.current = onSubmit;
    }, [onChange, onSubmit]);

    // Create update listener
    const createUpdateListener = useCallback(() => {
      return EditorView.updateListener.of((update) => {
        if (update.docChanged && !isInternalChange.current) {
          onChangeRef.current(update.state.doc.toString());
        }
      });
    }, []);

    // Submit keymap (Cmd/Ctrl+Enter)
    const submitKeymap = keymap.of([
      {
        key: 'Mod-Enter',
        run: () => {
          onSubmitRef.current?.();
          return true;
        },
      },
    ]);

    // Build extensions
    const getExtensions = useCallback((): Extension[] => {
      return [
        // Minimal features
        history(),
        bracketMatching(),
        closeBrackets(),

        // Keymaps
        keymap.of([
          ...closeBracketsKeymap,
          ...defaultKeymap,
          ...historyKeymap,
        ]),
        submitKeymap,

        // Language & theme
        queryLanguage,
        minimalTheme,
        syntaxHighlighting(querySyntaxTheme),
        autoHeight(minHeight, maxHeight),

        // Placeholder
        placeholder ? placeholderExt(placeholder) : [],

        // Update listener
        createUpdateListener(),

        // Read-only
        readOnlyCompartment.current.of(EditorState.readOnly.of(readOnly)),
      ].flat();
    }, [readOnly, placeholder, minHeight, maxHeight, createUpdateListener, submitKeymap]);

    // Initialize editor
    useEffect(() => {
      if (!containerRef.current) return;

      const state = EditorState.create({
        doc: value,
        extensions: getExtensions(),
      });

      const view = new EditorView({
        state,
        parent: containerRef.current,
      });

      viewRef.current = view;

      return () => {
        view.destroy();
        viewRef.current = null;
      };
    }, []); // Only on mount

    // Handle external value changes
    useEffect(() => {
      const view = viewRef.current;
      if (!view) return;

      const currentValue = view.state.doc.toString();
      if (currentValue !== value) {
        isInternalChange.current = true;
        view.dispatch({
          changes: {
            from: 0,
            to: currentValue.length,
            insert: value,
          },
        });
        isInternalChange.current = false;
      }
    }, [value]);

    // Handle readOnly changes
    useEffect(() => {
      const view = viewRef.current;
      if (!view) return;

      view.dispatch({
        effects: readOnlyCompartment.current.reconfigure(EditorState.readOnly.of(readOnly)),
      });
    }, [readOnly]);


    // Expose ref methods
    useImperativeHandle(ref, () => ({
      focus: () => viewRef.current?.focus(),
      getValue: () => viewRef.current?.state.doc.toString() ?? '',
      setValue: (newValue: string) => {
        const view = viewRef.current;
        if (!view) return;
        isInternalChange.current = true;
        view.dispatch({
          changes: { from: 0, to: view.state.doc.length, insert: newValue },
        });
        isInternalChange.current = false;
      },
    }), []);

  return (
    <div
      ref={containerRef}
      className={`
        border border-border rounded-xl bg-background
        focus-within:border-ring
        transition-colors resize-y overflow-auto
        ${className}
      `}
      style={fontSize ? ({ '--cm-font-size': `${fontSize}px` } as React.CSSProperties) : undefined}
    />
  );
}

export default QueryEditor;
