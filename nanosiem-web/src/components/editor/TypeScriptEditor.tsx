// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * CodeMirror 6 TypeScript Editor
 * Simple code editor with TypeScript syntax highlighting
 */
import React, { useRef, useEffect, useImperativeHandle } from 'react';
import { EditorState, Extension, Compartment } from '@codemirror/state';
import { EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { bracketMatching, foldGutter, indentOnInput } from '@codemirror/language';
import { closeBrackets, closeBracketsKeymap } from '@codemirror/autocomplete';
import { highlightSelectionMatches, searchKeymap } from '@codemirror/search';
import { javascript } from '@codemirror/lang-javascript';

import { editorTheme, syntaxTheme } from './codemirror-theme';
import { syntaxHighlighting } from '@codemirror/language';

export interface TypeScriptEditorRef {
  focus: () => void;
  getValue: () => string;
}

export interface TypeScriptEditorProps {
  value: string;
  onChange: (value: string) => void;
  readOnly?: boolean;
  className?: string;
  minHeight?: string;
}

export function TypeScriptEditor({
  value,
  onChange,
  readOnly = false,
  className = '',
  minHeight = '400px',
  ref,
}: TypeScriptEditorProps & { ref?: React.Ref<TypeScriptEditorRef> }) {
    const containerRef = useRef<HTMLDivElement>(null);
    const viewRef = useRef<EditorView | null>(null);
    const onChangeRef = useRef(onChange);
    const isInternalChange = useRef(false);
    const readOnlyCompartment = useRef(new Compartment());

    // Keep onChange ref updated
    useEffect(() => {
      onChangeRef.current = onChange;
    }, [onChange]);

    // Build extensions array
    const getExtensions = (): Extension[] => {
      return [
        // Basic editor features
        lineNumbers(),
        highlightActiveLine(),
        highlightActiveLineGutter(),
        history(),
        bracketMatching(),
        closeBrackets(),
        indentOnInput(),
        foldGutter(),
        highlightSelectionMatches(),

        // Keymaps
        keymap.of([
          ...closeBracketsKeymap,
          ...defaultKeymap,
          ...historyKeymap,
          ...searchKeymap,
        ]),

        // TypeScript language support
        javascript({ typescript: true, jsx: false }),

        // Theme
        editorTheme,
        syntaxHighlighting(syntaxTheme),

        // Update listener
        EditorView.updateListener.of((update) => {
          if (update.docChanged && !isInternalChange.current) {
            onChangeRef.current(update.state.doc.toString());
          }
        }),

        // Placeholder
        EditorView.contentAttributes.of({
          'aria-label': 'TypeScript code editor',
        }),

        // Read-only mode
        readOnlyCompartment.current.of(EditorState.readOnly.of(readOnly)),
      ];
    };

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
    }, []); // Only run once on mount

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
      focus: () => {
        viewRef.current?.focus();
      },
      getValue: () => {
        return viewRef.current?.state.doc.toString() ?? '';
      },
    }), []);

  return (
    <div
      ref={containerRef}
      className={`cm-editor-container w-full overflow-hidden rounded-lg border border-border bg-background ${className}`}
      style={{ minHeight }}
    />
  );
}

export default TypeScriptEditor;
